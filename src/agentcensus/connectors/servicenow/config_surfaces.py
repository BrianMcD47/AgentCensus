"""Configuration-surface detection: system properties and connection
aliases.

WHY THIS EXISTS SEPARATELY FROM shadow.py

shadow.py's four tiers all assume the evidence lives in one of two
places: a REST message record, or a script body. That covers a lot,
but it has a specific and consequential blind spot — the better an
integration is engineered, the less visible it is to those tiers:

    var endpoint = gs.getProperty('x_acme.llm_gateway_url');
    var r = new sn_ws.RESTMessageV2();
    r.setEndpoint(endpoint);

That script contains no provider hostname, no provider keyword, and no
REST message reference. Tier 2 sees nothing (no REST message record),
tier 4 sees nothing (no keyword in the source), and the integration is
invisible — even though the endpoint is sitting in `sys_properties` in
plain text, one table away, as a literal hostname that `match_host`
would resolve instantly.

Same story for Connection & Credential Aliases, which is what
ServiceNow's own documentation tells you to use instead of hardcoding
an endpoint on a REST message. An instance whose integrations follow
that guidance is LESS detectable to tier 2 than one that hardcodes
everything, which is exactly backwards for a governance tool.

WHY THESE ARE CONFIRMED-GRADE, NOT HEURISTICS

Both signals are literal hostnames in dedicated URL/value fields,
matched against the same `llm_providers.yaml` host list tier 2 uses.
That is structurally identical to tier 2's evidence, so it earns tier
2's confidence level. This is a stronger signal than tier 1 (keyword
match against an opaque OAuth client_id) and a lower-privilege read
than tiers 3-4 (no script source), which is why it runs in the DEFAULT
scan rather than behind `--include-script-scan`.

SECRET HANDLING

`sys_properties` is the one table in this connector where a value
field can legitimately hold an API key — it is, after all, where a
well-built integration is supposed to put one. Two independent guards:

  1. Any property whose `type` is a password/encrypted variant is
     skipped entirely, before its value is read, matched, or stored.
     ServiceNow generally returns those masked; "generally masked" is
     not a control worth betting a customer's credentials on.
  2. Every value that does get stored goes through `core.redaction`,
     so a plaintext key sitting in a property typed `string` (which
     happens constantly, and is itself worth flagging) is redacted on
     the way into the report.

A property that looks like it holds a credential is still reported as
a finding — the customer needs to know it exists. The report just
doesn't repeat its contents.
"""

from __future__ import annotations

from agentcensus.connectors.servicenow import is_inactive, tables
from agentcensus.connectors.servicenow.http import ServiceNowClient
from agentcensus.connectors.servicenow.llm_providers import (
    Provider,
    match_host,
    match_keywords,
)
from agentcensus.core.models import Confidence, Provenance, Tool
from agentcensus.core.redaction import REDACTED, is_secret_key, scrub_values

# Property-name fragments suggesting the property configures an LLM
# integration even when its value isn't a resolvable URL (e.g. a model
# name, a deployment id, a feature toggle). Weaker than a host match,
# so these land at NEEDS_REVIEW.
_SUGGESTIVE_NAME_FRAGMENTS = (
    "llm", "genai", "gen_ai", "ai_endpoint", "ai_gateway",
    "completion", "embedding", "inference",
)


def _is_secret_property(entry: dict) -> bool:
    """Fail CLOSED. Two independent reasons to treat a property as
    credential material:

      1. Its `type` is not one this connector has positively confirmed
         is safe. The previous version tested membership of a
         hand-written five-element secret list and read the value for
         anything else — so any type string nobody anticipated (a
         numeric glide type id, a scoped variant, a differently-cased
         label) defeated the guard silently. A guard on credential
         material has to fail closed on the unrecognised case.
      2. Its NAME looks secret-bearing. sys_properties is an
         entity-attribute-value table: `x_acme.anthropic.api_key` is a
         field NAME that happens to live in a row's `name` value. The
         key-name redaction layer only ever inspects dict keys
         (sys_id/name/type/value/description), so it is structurally
         unable to protect this table without this check.
    """
    prop_type = str(entry.get("type", "")).strip().lower()
    return prop_type not in tables.NON_SECRET_PROPERTY_TYPES


def _name_implies_credential(entry: dict) -> bool:
    """sys_properties is an entity-attribute-value table: the semantic
    field name lives in a row's `name` VALUE, not in a dict key. The
    key-name redaction layer only ever inspects dict keys
    (sys_id/name/type/value/description), so it is structurally unable
    to protect this table. A property called `x_acme.anthropic.api_key`
    typed `string` — which is the misconfiguration most worth flagging —
    otherwise had its plaintext value written into the report.

    Such a property is still REPORTED (the customer needs to know it
    exists); its value is simply never matched against or stored.
    """
    return is_secret_key(str(entry.get("name", "")))


def _fetch_properties(client: ServiceNowClient, providers: list[Provider], notes: list[str]) -> list[Tool]:
    rows, err = client.safe_get_all(
        tables.SYS_PROPERTIES_TABLE,
        tables.SYS_PROPERTIES_FIELDS,
        tables.SYS_PROPERTIES_QUERY,
        # The one filter here with a CONFIDENTIALITY consequence, not just
        # an accuracy one. `type!=<encrypted>` is what keeps encrypted
        # property values off the wire; if an ACL on `type` drops it, this
        # read requests `value` for every property including the encrypted
        # ones, and tables.py's claim that "their values are never
        # transmitted" stops being true.
        #
        # The report is still correct in that case — config_surfaces'
        # client-side check fails closed on an unknown or missing type, so
        # nothing secret is published. But "we fetched it and then chose
        # not to print it" is a materially weaker promise than "we never
        # asked for it", and a customer who granted least privilege is
        # owed the distinction rather than a silent downgrade.
        filter_fields=["type"],
    )
    if err:
        notes.append(err)
    # A note is NOT always fatal — see the identical comment in shadow.py.
    # Truncation or a field-level ACL still yields usable rows.
    if not rows:
        return []

    tools: list[Tool] = []
    skipped_secret = 0
    skipped_unrecognised: set[str] = set()

    for entry in rows:
        if _is_secret_property(entry):
            # Never read, match, or store the value of a property the
            # platform itself considers secret — see module docstring.
            # Counted separately by reason: "it was encrypted, we left
            # it alone" is the guard working as designed, while "we
            # didn't recognise the type so we failed closed" is a
            # COVERAGE GAP — that property might hold an endpoint this
            # scan never looked at. Reporting both under one number
            # would hide the second behind the first.
            prop_type = str(entry.get("type", "")).strip().lower()
            if prop_type in tables.SECRET_PROPERTY_TYPES:
                skipped_secret += 1
            else:
                skipped_unrecognised.add(prop_type or '(empty)')
            continue

        name = entry.get("name", "") or ""
        value = entry.get("value", "") or ""

        # A property whose NAME says "credential" has its value treated
        # as credential material: never host-matched, never stored.
        # Detection falls through to the name-based paths below, so the
        # property is still surfaced.
        value_is_credential = _name_implies_credential(entry)
        if value_is_credential:
            value = ""

        provider = match_host(value, providers)
        confidence = Confidence.CONFIRMED
        why = f"value points at {provider.label} ({scrub_values(value)})" if provider else ""

        if not provider:
            # Fall back to the property NAME — a `x_acme.llm_gateway_url`
            # whose value is an internal hostname the bundled provider
            # list can't know about is still worth surfacing, it just
            # isn't structurally confirmable.
            name_hit = next(iter(match_keywords(name, providers)), None)
            suggestive = any(f in name.lower() for f in _SUGGESTIVE_NAME_FRAGMENTS)
            if name_hit:
                provider, confidence = name_hit, Confidence.NEEDS_REVIEW
                why = (
                    f"property name matches {name_hit.label} by keyword"
                    + (
                        " and the property name indicates it holds a credential — "
                        "its value was neither matched against nor stored, and a "
                        "credential in a non-encrypted property is itself worth "
                        "remediating"
                        if value_is_credential
                        else ""
                    )
                )
            elif suggestive and value.startswith(("http://", "https://")):
                confidence = Confidence.NEEDS_REVIEW
                why = (
                    "property name suggests an AI/LLM integration and its value is a URL "
                    "not matching any known provider — likely an internal or self-hosted "
                    "gateway. Add its hostname via --llm-providers-extra to confirm future scans"
                )
            else:
                continue

        tools.append(
            Tool(
                id=entry["sys_id"],
                name=name or entry["sys_id"],
                description=(
                    f"System property '{name}' configures an outbound LLM endpoint — {why}. "
                    "Whatever reads this property is the actual integration; this record is "
                    "the endpoint it points at."
                ),
                credential_id=None,
                provenance=Provenance.SYNTHESIZED,
                confidence=confidence,
                direction="outbound",
                # Deliberately NOT the whole row. A reviewer needs to
                # know which property, of what type, pointing where —
                # not to receive its value back in a shareable
                # document. `value` appears only as the already-scrubbed
                # host that produced the match.
                raw={
                    "sys_id": entry.get("sys_id"),
                    "name": name,
                    "type": entry.get("type"),
                    "matched_value": (
                        REDACTED if value_is_credential
                        else (scrub_values(value) if value else None)
                    ),
                    "value_withheld_as_credential": value_is_credential,
                    "sys_created_by": entry.get("sys_created_by"),
                    "sys_updated_by": entry.get("sys_updated_by"),
                    "sys_updated_on": entry.get("sys_updated_on"),
                },
            )
        )

    # Say the tier RAN. Connections report "no records matched"; this tier
    # reported nothing at all when it found nothing, so a reader could not
    # tell "examined 3,661 properties, none held an LLM endpoint" from
    # "this tier did not execute". That is the exact ambiguity this whole
    # project exists to remove, still present in one surface.
    notes.append(
        f"System properties: {len(rows)} examined, {len(tools)} holding a value that "
        "matches a known LLM provider host. A property is where an endpoint hides when a "
        "script reads it via gs.getProperty() and therefore contains no provider keyword "
        "of its own — this tier exists for that case."
    )

    # Stated unconditionally, not gated on a count.
    #
    # This note used to fire only when `skipped_secret` was non-zero — and
    # it is ALWAYS zero, because encrypted properties are excluded by the
    # server-side query and so never reach this loop to be counted. The
    # reassurance that credential material is deliberately untouched
    # therefore never appeared in any report, and its absence read as the
    # tier having nothing to say about secrets at all.
    #
    # No number is claimed, because the exclusion happens at the database
    # and this code genuinely does not know how many there were. Naming a
    # count we cannot observe would be the fabrication this project keeps
    # removing; saying what the tool does and does not read is the part
    # that is actually true.
    notes.append(
        "System properties typed password/encrypted are excluded by the query itself, so "
        "their values never cross the network and are not counted here. AgentCensus never "
        "reads credential material — an LLM API key stored correctly is deliberately "
        "invisible to this scan. That is the guard working as intended, not a gap."
    )
    if skipped_secret:
        notes.append(
            f"{skipped_secret} system propert(ies) reached the client-side check and were "
            "skipped there as secret-typed. Their values were transmitted before being "
            "discarded, which means the server-side exclusion did not cover them — worth "
            "reporting so the query can be widened."
        )
    if skipped_unrecognised:
        # The type strings themselves, not just a count. The note used to
        # say "report the types involved so they can be classified" while
        # discarding them — telling the reader to do something the
        # artifact gave them no way to do, which is the same shape as the
        # unreachable-flag defect fixed in an earlier round.
        named = ", ".join(sorted(skipped_unrecognised))
        notes.append(
            f"COVERAGE GAP: system propert(ies) were skipped because their `type` is not "
            f"one this connector recognises as safe to read. Types seen: {named}. The check "
            "fails closed on purpose (an unrecognised type could be an encrypted variant), "
            "but that means any LLM endpoint stored in such a property was NOT examined. "
            "Add any of these that are genuinely non-secret to "
            "tables.NON_SECRET_PROPERTY_TYPES."
        )
    return tools


def _fetch_connections(
    client: ServiceNowClient,
    providers: list[Provider],
    notes: list[str],
    include_inactive: bool = False,
) -> list[Tool]:
    tools: list[Tool] = []

    for table, fields in (
        (tables.HTTP_CONNECTION_TABLE, tables.HTTP_CONNECTION_FIELDS),
        (tables.CONNECTION_TABLE, tables.CONNECTION_FIELDS),
    ):
        exists, exists_err = client.table_exists(table)
        if exists_err:
            notes.append(exists_err)
            continue
        if not exists:
            continue

        rows, err = client.safe_get_all(table, fields)
        if err:
            notes.append(err)
        # A note is NOT always fatal. `safe_get_all` returns rows AND a
        # note for a PARTIAL read — safety-cap truncation, or a
        # field-level ACL hiding one column. Bailing on the note threw
        # away every row that did arrive, turning "incomplete" into
        # "nothing found" with only a note to hint at it. Measured live:
        # sys_script hit the 5,000-row cap and all 5,000 Business Rules
        # were discarded. Bail only when there is nothing to work with.
        if not rows:
            continue

        for entry in rows:
            # `active` was stored into raw and never filtered on.
            if not include_inactive and is_inactive(entry):
                continue
            # Two shapes, because the destination lives in a different
            # place on the parent and the child table — the discovery that
            # this tier had been requesting `connection_url` on
            # `sys_connection`, where no such column exists, while it does
            # exist on `http_connection`. The field name was real; it was
            # on the wrong table, which is why grepping for it looked fine.
            #
            # `host` is preferred where present: it is the hostname already
            # parsed by the platform, so there is no URL splitting, no
            # scheme handling and no query-string edge case to get wrong.
            # The parser this tier was going to need was sitting in its own
            # column the whole time.
            url = entry.get("connection_url") or ""
            host = entry.get("host") or ""
            target = host or url
            if not target:
                continue
            provider = match_host(target, providers)
            if not provider:
                continue
            # Rebuilt for display only when the platform gave us the parts.
            if host and not url:
                scheme = entry.get("protocol") or "https"
                port = entry.get("port")
                url = f"{scheme}://{host}" + (f":{port}" if port else "")
            tools.append(
                Tool(
                    id=entry["sys_id"],
                    name=entry.get("name", entry["sys_id"]),
                    description=(
                        f"Connection alias pointing at {provider.label} "
                        f"({scrub_values(url)}) — configured outbound connection, not a "
                        "hardcoded REST message endpoint."
                    ),
                    credential_id=None,
                    provenance=Provenance.SYNTHESIZED,
                    confidence=Confidence.CONFIRMED,
                    direction="outbound",
                    raw={
                        "sys_id": entry.get("sys_id"),
                        "name": entry.get("name"),
                        "connection_url": scrub_values(url),
                        "host": entry.get("host"),
                        "connection_alias": entry.get("connection_alias"),
                        "credential": entry.get("credential"),
                        "active": entry.get("active"),
                        "sys_created_by": entry.get("sys_created_by"),
                    },
                )
            )

    if not tools:
        notes.append(
            "No Connection & Credential Alias records matched a known LLM provider host "
            "(this is the ServiceNow-recommended alternative to hardcoding an endpoint on "
            "a REST message, so it's checked alongside sys_rest_message)."
        )
    return tools


def fetch_config_surfaces(
    client: ServiceNowClient,
    providers: list[Provider],
    include_inactive: bool = False,
):
    """Returns (tools, scan_notes).

    Emits Tools rather than Agents on purpose: a property or connection
    record is an *endpoint*, not an actor. Something else — a script, a
    flow, an app — is the agent that reads it. Inventing an Agent here
    would be claiming to know a caller this module cannot see. The tool
    shows up in the graph, and the ungoverned-integration rule flags it;
    if tier 4 separately finds the script that reads it, the graph will
    already have both.
    """
    notes: list[str] = []
    tools = _fetch_properties(client, providers, notes)
    tools.extend(_fetch_connections(client, providers, notes, include_inactive=include_inactive))
    return tools, notes
