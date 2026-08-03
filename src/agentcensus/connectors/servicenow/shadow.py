"""Shadow/custom agent detection.

Finds agentic integrations that were hand-built directly on the
platform and therefore have no row in any native "agent" table at
all — Script Include + Scripted REST API + Business Rule calling out
to an LLM is a completely ordinary way to build this, not an edge
case. See the provenance/confidence design note in core/models.py and
the module docstring in tables.py for why this matters as much as, or
more than, reading a native table.

Four tiers, ranked by how much the signal can be trusted on its own:

  Tier 1 (NEEDS_REVIEW) — OAuth entities whose name/client_id matches a
      known LLM provider by keyword. This is a text match, not a
      structural one — client_id is an opaque identifier, not a
      hostname, so it can't be matched against llm_providers.yaml's
      host list the way tier 2 is. ServiceNow's Connection & Credential
      Alias framework may expose real authorization/token URL fields
      that WOULD make this structural, but those field names haven't
      been verified against a live instance yet. Labeled NEEDS_REVIEW
      until they are — see CONTRIBUTING.md before "fixing" this to
      CONFIRMED without doing that verification first.

      RETRACTION (2026-08): this docstring previously claimed that
      `client_id`/`sys_created_by`/`sys_updated_by`/`sys_updated_on`
      came back silently absent on a live instance, and attributed it to
      a field-level ACL. Re-tested directly: `oauth_entity` returns 19
      rows with every requested field present and no note at all. The
      original observation was made before the field-name bugs were
      found, when any absent field was assumed to be an ACL; it is not
      clear the fields were ever missing. Tier 1 reads fine.

      Kept rather than deleted because the pattern is the point: a
      confident claim about the platform, written from one ambiguous
      observation, survived in a docstring for weeks and would have
      misled anyone deciding whether tier 1 was worth improving.

  Tier 2 (CONFIRMED, or NEEDS_REVIEW via the template fallback below) —
      sys_rest_message (and sys_rest_message_fn, for per-HTTP-method
      endpoint overrides) records whose endpoint matches a known LLM API
      host. Verified live against a real PDI: the table, its
      Name/Endpoint/Application columns, confirmed to exist and behave
      as expected.

      TEMPLATE VARIABLE FALLBACK: an endpoint containing an unresolved
      `${variable}` placeholder — observed live in this same PDI's own
      default REST message data — can't match a literal hostname no
      matter how complete the provider list is; the real destination is
      resolved by ServiceNow elsewhere (environment-scoped variable
      values), not visible in the field set this connector reads. Rather
      than silently dropping these (the original, real gap this docstring
      used to describe), `_tier2_rest_message_tools` falls back to a
      keyword match against the REST message's own `name` — a signal
      tier 2 previously never looked at, since a host match was assumed
      sufficient. A name match on a templated endpoint is a materially
      weaker signal than a literal host match (it's a label a human
      chose, not where the request actually goes), so it's surfaced at
      NEEDS_REVIEW, not CONFIRMED — a lower-confidence finding beats no
      finding at all for something this connector can otherwise see
      exists but not verify structurally.

  Tier 3 (NEEDS_REVIEW) — Scripted REST API resources (sys_ws_operation)
      whose name/path/script suggests it exposes a tool/MCP surface
      *outward*, to external callers. Emitted as an inbound Tool
      finding, not an Agent — ServiceNow is the thing being called
      here, not the caller. Requires read access to `operation_script`
      (script source), a more sensitive grant than tiers 1-2 need — see
      `include_script_scan` below.

  Tier 4 (mixed) — Script Include / Business Rule / Scheduled Job script
      bodies. A script that calls an already-confirmed tier-2 REST
      message by name gets an Agent built for it directly, correlated
      to that tool, at CONFIRMED confidence — that's a real integration
      with a real registered endpoint, just missing from any agent
      table. A script that only matches an LLM keyword with NO
      corresponding REST message record (an inline `RESTMessageV2` call
      with a hardcoded endpoint, or similar) gets a NEEDS_REVIEW Agent
      *plus* a synthesized placeholder Tool representing that inline
      call, specifically so the dependency graph still has something to
      connect it to — an earlier version of this file built the
      NEEDS_REVIEW agent with no tool_ids at all, which left it
      floating in the graph with no edges. That was a real bug, not a
      style choice; the graph is supposed to be the differentiating
      capability, so a detection path that produces disconnected nodes
      defeats the point. Also requires script-source read access.

`include_script_scan` gates tiers 3 and 4 (default False). Reading raw
script bodies is a materially more sensitive permission grant than
reading table metadata, and most ServiceNow security teams restrict it
beyond a standard read-only role — bundling it into the default scan
would work against this project's own least-privilege constraint
(project plan, section 7). Tiers 1-2 stay on by default; they only read
structured fields (name, endpoint, client_id), not source code.

SCRIPT SOURCE IS READ, NEVER PUBLISHED. Tiers 3 and 4 have to read
script bodies to detect anything at all, but no script body is stored
in the report. This is not a stylistic choice — the scripts this tier
flags are, by construction, the ungoverned ones nobody reviewed, which
makes them the most likely place on the entire instance to find a
hardcoded API key. Writing them verbatim into a report designed to be
handed to auditors would make this tool a credential-exfiltration path
targeting exactly the highest-risk scripts it just identified. (This
was a real hole, found by reading a real report from a real instance,
not a hypothetical.) `_safe_raw` replaces every script field with a
sha256 fingerprint and length; `--include-script-excerpts` opts into a
short, secret-scrubbed window around the match. See
core/redaction.py.

Per severity.py, every NEEDS_REVIEW finding is capped at MEDIUM
regardless of impact/exposure, so this layer can't cry "critical" on a
guess.
"""

from __future__ import annotations

import re

from agentcensus.connectors.servicenow import tables
from agentcensus.connectors.servicenow.http import ServiceNowClient, ref
from agentcensus.connectors.servicenow.llm_providers import (
    Provider,
    load_providers,
    match_host,
    match_keywords,
)
from agentcensus.connectors.servicenow.owners import fetch_owners
from agentcensus.core.models import (
    AccountType,
    Agent,
    Confidence,
    Credential,
    Provenance,
    Tool,
)
from agentcensus.core.redaction import script_metadata, scrub, scrub_values

_TEMPLATE_VAR_PATTERN = re.compile(r"\$\{[^}]+\}")

# Fields whose value is raw source code. These are read (detection
# needs them) but must never reach a `raw` blob, because `raw` is
# serialized verbatim into the report — see `_safe_raw` and
# core/redaction.py's module docstring for why this is a hard rule and
# not a preference.
_SCRIPT_FIELDS = ("script", "operation_script")


def _safe_raw(entry: dict, *, matched_keyword: str | None = None,
              include_script_excerpts: bool = False, **extra) -> dict:
    """Builds a `raw` blob with script source replaced by metadata.

    Everything in `raw` ends up verbatim in the JSON report, which is a
    document meant to be shared. Script bodies are the highest-risk
    thing this connector reads — the most likely place on the whole
    instance to find a hardcoded API key, since the scripts this tier
    flags are by definition the ones nobody governed. They're also
    proprietary logic and, on a real instance, system prompts.

    So the body is dropped and replaced with a sha256 fingerprint plus
    length (see `redaction.script_metadata`), which is enough to diff
    scans over time and correlate duplicates without holding the
    content. An opt-in excerpt is available for reviewers who need to
    see the matching line; it is scrubbed before being stored.
    Everything else in the row still goes through `scrub` for
    secret-shaped values in ordinary fields (e.g. an endpoint with an
    `?api_key=` query parameter).
    """
    cleaned = {k: v for k, v in entry.items() if k not in _SCRIPT_FIELDS}
    raw = {**scrub(cleaned), **extra}
    for field in _SCRIPT_FIELDS:
        if field in entry:
            raw.update(
                script_metadata(
                    entry.get(field) or "",
                    excerpt_around=matched_keyword,
                    include_excerpt=include_script_excerpts,
                )
            )
            break
    return raw


def _has_unresolved_template_var(endpoint: str) -> bool:
    """True if `endpoint` contains a `${...}` placeholder ServiceNow
    resolves elsewhere (environment-scoped variable values) rather than
    storing literally on the REST message record itself — see tier 2's
    docstring above for why match_host can never see through this."""
    return bool(_TEMPLATE_VAR_PATTERN.search(endpoint or ""))


def _tier1_oauth_credentials(client: ServiceNowClient, providers: list[Provider], notes: list[str]) -> list[Credential]:
    raw, err = client.safe_get_all(tables.OAUTH_ENTITY_TABLE, tables.OAUTH_ENTITY_FIELDS)
    if err:
        notes.append(err)
    # A note is NOT always fatal. `safe_get_all` returns rows AND a
    # note for a PARTIAL read — safety-cap truncation, or a
    # field-level ACL hiding one column. Bailing on the note threw
    # away every row that did arrive, turning "incomplete" into
    # "nothing found" with only a note to hint at it. Measured live:
    # sys_script hit the 5,000-row cap and all 5,000 Business Rules
    # were discarded. Bail only when there is nothing to work with.
    if not raw:
        return []

    credentials = []
    for entry in raw:
        haystack = f"{entry.get('name', '')} {entry.get('client_id', '')}"
        hit = next(iter(match_keywords(haystack, providers)), None)
        if not hit:
            continue
        credentials.append(
            Credential(
                id=entry["sys_id"],
                name=entry.get("name", entry["sys_id"]),
                account_type=AccountType.UNKNOWN,
                owner_id=None,  # resolved by fetch_shadow once every tier's creator
                                 # usernames are known — see its docstring; the field
                                 # was being fetched into `raw` and then never used to
                                 # actually resolve an owner, which was a real gap
                provenance=Provenance.SYNTHESIZED,
                confidence=Confidence.NEEDS_REVIEW,
                provider=hit.id,
                # "_creator" is the normalized key fetch_shadow's unified owner
                # resolution pass looks for on every tier's output (see tier 2
                # and tier 4) — spelled out explicitly here too rather than
                # relying on the raw entity's own "sys_created_by" key, so
                # that pass doesn't need to special-case this tier.
                raw=_safe_raw(entry, _creator=entry.get("sys_created_by")),
            )
        )
    return credentials


def _tier2_rest_message_tools(client: ServiceNowClient, providers: list[Provider], notes: list[str]):
    """Returns (tools, credentials, tools_by_name) — the third lets
    tier 4 correlate a calling script back to a specific confirmed tool
    instead of just knowing "something" matched."""
    raw, err = client.safe_get_all(tables.REST_MESSAGE_TABLE, tables.REST_MESSAGE_FIELDS)
    if err:
        notes.append(err)
    # A note is NOT always fatal. `safe_get_all` returns rows AND a
    # note for a PARTIAL read — safety-cap truncation, or a
    # field-level ACL hiding one column. Bailing on the note threw
    # away every row that did arrive, turning "incomplete" into
    # "nothing found" with only a note to hint at it. Measured live:
    # sys_script hit the 5,000-row cap and all 5,000 Business Rules
    # were discarded. Bail only when there is nothing to work with.
    if not raw:
        return [], [], {}

    fn_rows, fn_err = client.safe_get_all(tables.REST_MESSAGE_FN_TABLE, tables.REST_MESSAGE_FN_FIELDS)
    if fn_err:
        notes.append(fn_err + " (per-method endpoint overrides will be missed)")
        fn_rows = []
    # per-method endpoint overrides, keyed by parent rest_message sys_id —
    # a message's own `endpoint` field can be blank/generic with the real
    # URL only set here (observed as a real pattern, not hypothetical:
    # this instance's own ServiceNowMobileApp Push message stores its
    # endpoint as a `${pushHost}` template on the base record).
    fn_endpoints_by_message: dict[str, list[str]] = {}
    for fn in fn_rows:
        msg_ref = ref(fn.get("rest_message"))
        if msg_ref and fn.get(tables.REST_ENDPOINT_FIELD):
            fn_endpoints_by_message.setdefault(msg_ref, []).append(fn[tables.REST_ENDPOINT_FIELD])

    tools: list[Tool] = []
    credentials: dict[str, Credential] = {}
    tools_by_name: dict[str, Tool] = {}

    for entry in raw:
        candidate_endpoints = [entry.get(tables.REST_ENDPOINT_FIELD, "")] + fn_endpoints_by_message.get(entry["sys_id"], [])
        provider = None
        matched_endpoint = None
        for candidate in candidate_endpoints:
            provider = match_host(candidate, providers)
            if provider:
                matched_endpoint = candidate
                break

        confidence = Confidence.CONFIRMED
        if not provider:
            # No candidate endpoint structurally matched a known host —
            # but if one of them is an unresolved ${...} template
            # variable (confirmed live, see module docstring), match_host
            # can never see the real destination no matter how complete
            # the provider list is. Falling back to a keyword match on
            # the message's own *name* — a field tier 2 previously never
            # looked at — is a real signal, just a weaker one than a
            # literal host match, so it lands at NEEDS_REVIEW.
            templated_candidate = next(
                (c for c in candidate_endpoints if _has_unresolved_template_var(c)), None
            )
            if templated_candidate:
                name_hit = next(iter(match_keywords(entry.get("name", ""), providers)), None)
                if name_hit:
                    provider = name_hit
                    matched_endpoint = templated_candidate
                    confidence = Confidence.NEEDS_REVIEW

        if not provider:
            continue

        cred_id = ref(entry.get("basic_auth_profile"))
        if cred_id and cred_id not in credentials:
            credentials[cred_id] = Credential(
                id=cred_id,
                name=f"basic_auth_profile:{cred_id}",
                account_type=AccountType.UNKNOWN,
                owner_id=None,  # resolved by fetch_shadow, see below
                provenance=Provenance.SYNTHESIZED,
                confidence=confidence,
                provider=provider.id,
                # basic_auth_profile is a separate record this connector never
                # reads (only its reference id) — it has no sys_created_by of
                # its own available here. Best-effort proxy: attribute the
                # credential to whoever created the REST message that
                # actually references it, same "closest available signal"
                # reasoning integration_accounts.py uses for its own
                # best-effort owner attribution.
                raw={"_creator": entry.get("sys_created_by")},
            )

        # Descriptions embed the endpoint, and an endpoint routinely
        # carries `?api_key=` — so a human-readable field leaks just as
        # effectively as a raw blob. Caught by an adversarial end-to-end
        # test, not by inspection: `raw` had been scrubbed while the
        # description built from the same value had not.
        safe_endpoint = scrub_values(matched_endpoint or "")
        if confidence == Confidence.CONFIRMED:
            description = f"Outbound REST message to {provider.label} ({safe_endpoint})"
        else:
            description = (
                f"Outbound REST message named '{entry.get('name', '')}' matches {provider.label} "
                f"by keyword; its endpoint ('{safe_endpoint}') uses an unresolved template "
                "variable, so the real destination could not be structurally confirmed — verify "
                "manually."
            )

        tool = Tool(
            id=entry["sys_id"],
            name=entry.get("name", entry["sys_id"]),
            description=description,
            credential_id=cred_id,
            provenance=Provenance.SYNTHESIZED,
            confidence=confidence,
            direction="outbound",
            # An endpoint is not a secret field, but an endpoint like
            # `https://gw/v1?api_key=...` is a secret value — _safe_raw
            # runs value-level scrubbing that a field-name allowlist
            # can't do.
            raw=_safe_raw(entry),
        )
        tools.append(tool)
        if tool.name:
            tools_by_name[tool.name] = tool

    return tools, list(credentials.values()), tools_by_name


def _tier3_inbound_tools(
    client: ServiceNowClient,
    providers: list[Provider],
    notes: list[str],
    include_script_excerpts: bool = False,
) -> list[Tool]:
    raw, err = client.safe_get_all(tables.WS_OPERATION_TABLE, tables.WS_OPERATION_FIELDS)
    if err:
        notes.append(err)
    # A note is NOT always fatal. `safe_get_all` returns rows AND a
    # note for a PARTIAL read — safety-cap truncation, or a
    # field-level ACL hiding one column. Bailing on the note threw
    # away every row that did arrive, turning "incomplete" into
    # "nothing found" with only a note to hint at it. Measured live:
    # sys_script hit the 5,000-row cap and all 5,000 Business Rules
    # were discarded. Bail only when there is nothing to work with.
    if not raw:
        return []

    tools = []
    for entry in raw:
        haystack = " ".join(
            str(entry.get(f, "")) for f in ("name", "relative_path", "operation_script")
        )
        hit_providers = match_keywords(haystack, providers)
        if not hit_providers:
            continue
        tools.append(
            Tool(
                id=entry["sys_id"],
                name=entry.get("name", entry["sys_id"]),
                description=(
                    f"Scripted REST API resource at '{entry.get('relative_path', '')}' — "
                    f"keyword match suggests it may expose a tool/MCP surface to external "
                    f"callers ({', '.join(p.label for p in hit_providers)}). Needs human review."
                ),
                credential_id=None,
                provenance=Provenance.SYNTHESIZED,
                confidence=Confidence.NEEDS_REVIEW,
                direction="inbound",
                raw=_safe_raw(
                    entry,
                    matched_keyword=hit_providers[0].keywords[0] if hit_providers[0].keywords else None,
                    include_script_excerpts=include_script_excerpts,
                ),
            )
        )
    return tools


def _references_tool(script: str, tool_name: str) -> bool:
    """Word-boundary match, not raw substring — a REST message named
    'API' would otherwise match nearly every script in the instance and
    falsely suppress or misattribute tier-4 findings.

    Was a plain `re.search(re.escape(name), script)` call with only a
    length floor guarding it — that's still a substring match, so a REST
    message named e.g. 'Chat' would match inside 'ChatHistoryUtils' or
    any other identifier containing it as a substring. `\\b` boundaries
    on both ends fix that; the length floor stays as defense in depth
    for very short names where boundary matching alone isn't enough
    signal (e.g. a 2-3 char name matching inside unrelated short
    tokens)."""
    tool_name = tool_name.strip()
    if not tool_name or len(tool_name) < 4:
        return False
    pattern = r"\b" + re.escape(tool_name) + r"\b"
    return re.search(pattern, script) is not None


def _resolve_scopes(client: ServiceNowClient) -> dict[str, str]:
    """sys_id -> scope string for every application on the instance.

    Reads through safe_get_all: if sys_scope is unreadable the map is
    empty, every record is treated as unclassified, and nothing is
    excluded. Failing open here is correct — an unresolvable scope must
    never cause a finding to disappear.
    """
    rows, _err = client.safe_get_all(tables.APP_SCOPE_TABLE, tables.APP_SCOPE_FIELDS)
    return {r["sys_id"]: str(r.get("scope") or "") for r in rows if r.get("sys_id")}


def _authored_directly(entry: dict) -> bool:
    """True when the record belongs to NO application — hand-authored on
    the instance rather than delivered by a plugin, store app or scoped
    app. See tables.UNPACKAGED_SENTINEL for the live evidence.

    This is the single best available signal for "a person built this
    here", which is the entire population this tool exists to find. It
    is reported as evidence and used to RANK; it never removes a
    finding. Its inverse is not reliable (a customer's own scoped app
    carries a real package too), and every over-correction defect in
    this project came from excluding on a signal like this."""
    return (ref(entry.get("sys_package")) or "") == tables.UNPACKAGED_SENTINEL


def _is_vendor_scope(scope: str) -> bool:
    return scope.lower().startswith(tables.VENDOR_SCOPE_PREFIXES)


def _tier4_script_agents(
    client: ServiceNowClient,
    providers: list[Provider],
    tools_by_name: dict[str, Tool],
    notes: list[str],
    include_script_excerpts: bool = False,
    include_vendor_scope: bool = False,
    include_inactive: bool = False,
):
    """Returns (agents, synthesized_tools)."""
    scopes = _resolve_scopes(client)
    excluded_vendor = 0
    excluded_inactive = 0
    # Every table on this instance that can hold a script an agent
    # could live in — see tables.py's "Additional script-bearing
    # surfaces" note for why the original three weren't enough. The
    # script field name differs per table (`operation_script` on
    # Scripted REST API resources), so it's carried explicitly rather
    # than assumed.
    sources = [
        (tables.SCRIPT_INCLUDE_TABLE, tables.SCRIPT_INCLUDE_FIELDS, "script_include", "script"),
        (tables.BUSINESS_RULE_TABLE, tables.BUSINESS_RULE_FIELDS, "business_rule", "script"),
        (tables.SCHEDULED_JOB_TABLE, tables.SCHEDULED_JOB_FIELDS, "scheduled_job", "script"),
        (tables.WIDGET_TABLE, tables.WIDGET_FIELDS, "service_portal_widget", "script"),
        (tables.UI_ACTION_TABLE, tables.UI_ACTION_FIELDS, "ui_action", "script"),
        (tables.INBOUND_EMAIL_ACTION_TABLE, tables.INBOUND_EMAIL_ACTION_FIELDS,
         "inbound_email_action", "script"),
        (tables.FIX_SCRIPT_TABLE, tables.FIX_SCRIPT_FIELDS, "fix_script", "script"),
        (tables.PROCESSOR_TABLE, tables.PROCESSOR_FIELDS, "processor", "script"),
        # Same table tier 3 reads, different question. Tier 3 asks
        # "does this expose a surface outward?"; here we ask "does this
        # itself call an LLM outward?" A bridge endpoint (receive
        # request → call model → return answer) is both, and reporting
        # only the inbound half describes half the integration.
        (tables.WS_OPERATION_TABLE, tables.WS_OPERATION_FIELDS,
         "scripted_rest_api", "operation_script"),
    ]
    agents: list[Agent] = []
    synthesized_tools: list[Tool] = []

    for table, fields, kind, script_field in sources:
        # Exclude vendor scopes SERVER-SIDE where possible, so the
        # safety cap is spent on customer code rather than on records
        # about to be discarded.
        #
        # Measured live: `sys_script` hit the 5,000-row cap on a small
        # PDI while 3,046 records were separately excluded as vendor
        # scope. The cap applies when FETCHING; the filter ran AFTER. So
        # most of the budget was spent pulling ServiceNow's own code and
        # then throwing it away — and on a large instance the cap could
        # be exhausted entirely inside vendor scope, returning ZERO
        # customer findings with only a truncation note to hint at it.
        # That is the silent-under-report failure this project keeps
        # rediscovering, in its newest feature.
        #
        # Dot-walking a reference field in an encoded query is standard
        # ServiceNow, but it is not verified against every release, so a
        # failure falls back to the unfiltered read rather than losing
        # the table. The client-side filter below still runs either way
        # — this only changes WHAT gets paid for.
        query = ""
        if not include_vendor_scope:
            query = "^".join(
                f"sys_scope.scopeNOT LIKE{prefix}"
                for prefix in tables.VENDOR_SCOPE_PREFIXES
            )
        # `sys_scope`, not `sys_scope.scope` — the ACL applies to the base
        # reference field, and that is what the response can be checked
        # for. A dropped filter here is the mildest of the four guarded
        # sites (the client-side `_is_vendor_scope` check still runs, so
        # the report stays correct) but it silently spends the row cap on
        # thousands of vendor records, which is how ~700 customer-authored
        # scripts went unexamined for several releases.
        raw, err = client.safe_get_all(
            table, fields, query, filter_fields=["sys_scope"] if query else None
        )

        # Retry unfiltered ONLY when the filtered read genuinely failed —
        # i.e. it produced no rows at all. A truncation or field-ACL note
        # arrives WITH usable rows, and re-fetching on those would spend
        # the API budget twice to get the same data.
        if query and err and not raw:
            notes.append(
                f"Server-side vendor-scope filter rejected on '{table}' — retrying "
                "unfiltered. The safety cap may now be consumed by vendor records; "
                "if this table also reports truncation, raise max_records_per_table "
                "or pass --include-vendor-scope to see what was dropped."
            )
            raw, err = client.safe_get_all(table, fields)

        if err:
            notes.append(err)
        # A note is NOT always fatal — see the identical reasoning at the
        # other call sites. Truncation and field-level ACLs both return
        # rows worth scanning; discarding them turned "incomplete" into
        # "nothing found". Measured live: sys_script hit the 5,000-row
        # cap and every one of those Business Rules was thrown away.
        if not raw:
            continue

        for entry in raw:
            script = entry.get(script_field, "") or ""
            if not script:
                continue

            # `active` was fetched on six of these tables and never
            # consulted — a disabled business rule was reported exactly
            # like a live one.
            if not include_inactive and str(entry.get("active", "true")).lower() == "false":
                excluded_inactive += 1
                continue

            scope = scopes.get(ref(entry.get("sys_scope")) or "", "")
            if not include_vendor_scope and _is_vendor_scope(scope):
                excluded_vendor += 1
                continue

            referenced = [t for name, t in tools_by_name.items() if _references_tool(script, name)]
            hit_providers = match_keywords(script, providers)

            # Business Rules carry a `collection` field — the table the
            # rule fires against. That's a real, already-fetched signal
            # for which table this shadow agent touches, so it feeds
            # SeverityConfig.sensitive_tables impact scoring (see
            # rules/access.py's SensitiveTableAccessRule). Script
            # Includes and Scheduled Jobs have no equivalent field —
            # they're not bound to one table — so target_table stays
            # None for those, which the rule treats as "not determined"
            # rather than "not sensitive". `collection` is a reference
            # field to sys_db_object by long-standing ServiceNow
            # convention (not live-confirmed on this specific field —
            # sys_script access was denied on the one live account tested
            # — but department on sys_user proved this exact failure mode
            # is real on this project's Table API reads in general, and
            # a raw {"link","value"} dict compared against a set[str] in
            # SensitiveTableAccessRule would raise TypeError: unhashable
            # type, not just misbehave). ref() unwraps it if so, passes a
            # plain string through unchanged if not.
            # UI Actions and inbound email actions carry the same
            # signal under a different field name (`table` rather than
            # `collection`) — both mean "the table this thing acts on",
            # which is what SensitiveTableAccessRule scores. Script
            # Includes, widgets, fix scripts and processors have no
            # equivalent: they aren't bound to one table, so this stays
            # None and the rule treats it as "not determined" rather
            # than "not sensitive".
            if kind == "business_rule":
                target_table = ref(entry.get("collection")) or None
            elif kind in ("ui_action", "inbound_email_action"):
                target_table = ref(entry.get("table")) or None
            else:
                target_table = None

            if referenced:
                # Real integration, real registered endpoint — just
                # missing from any agent table. High confidence because
                # it's anchored to a tier-2 structural match.
                agents.append(
                    Agent(
                        id=entry["sys_id"],
                        name=entry.get("name", entry["sys_id"]),
                        description=None,
                        owner_id=None,
                        tool_ids=[t.id for t in referenced],
                        provenance=Provenance.SYNTHESIZED,
                        confidence=Confidence.CONFIRMED,
                        detection_signal=f"shadow:{kind}_calls_confirmed_tool:{referenced[0].name}",
                        target_table=target_table,
                        raw=_safe_raw(
                            entry,
                            matched_keyword=referenced[0].name,
                            include_script_excerpts=include_script_excerpts,
                            _kind=kind,
                            _creator=entry.get("sys_created_by"),
                            _authored_directly=_authored_directly(entry),
                        ),
                    )
                )
                continue

            if not hit_providers:
                continue

            # Ad hoc call — keyword hit with no formal REST message
            # record. Synthesize a placeholder tool so this agent isn't
            # left as a disconnected node in the dependency graph; it's
            # exactly as uncertain as the agent it belongs to.
            placeholder = Tool(
                id=f"{entry['sys_id']}:inline_call",
                name=f"{entry.get('name', entry['sys_id'])} (inline call)",
                description=(
                    f"Inferred from keyword match in {kind} '{entry.get('name', '')}' — "
                    f"no REST message record found for this call "
                    f"({', '.join(p.label for p in hit_providers)})."
                ),
                credential_id=None,
                provenance=Provenance.SYNTHESIZED,
                confidence=Confidence.NEEDS_REVIEW,
                direction="outbound",
                raw={},
            )
            synthesized_tools.append(placeholder)

            agents.append(
                Agent(
                    id=entry["sys_id"],
                    name=entry.get("name", entry["sys_id"]),
                    description=None,
                    owner_id=None,
                    tool_ids=[placeholder.id],
                    provenance=Provenance.SYNTHESIZED,
                    confidence=Confidence.NEEDS_REVIEW,
                    detection_signal=(
                        f"shadow:script_keyword:{kind}:{','.join(p.id for p in hit_providers)}"
                    ),
                    target_table=target_table,
                    raw=_safe_raw(
                        entry,
                        matched_keyword=(
                            hit_providers[0].keywords[0] if hit_providers[0].keywords else None
                        ),
                        include_script_excerpts=include_script_excerpts,
                        _kind=kind,
                        _creator=entry.get("sys_created_by"),
                        _authored_directly=_authored_directly(entry),
                    ),
                )
            )

    # NEITHER count is a count of keyword matches, and both notes used to
    # say it was.
    #
    # Both filters run BEFORE `match_keywords`, so these counters tally
    # every record that reached the filter — not the subset that would
    # have matched a provider. The note said "N script record(s) ...
    # matched a provider keyword and were excluded", and on the measured
    # PDI N was 3,046. Almost none of them matched anything.
    #
    # That overstates by three orders of magnitude what
    # `--include-vendor-scope` would reveal, which is exactly the decision
    # the number exists to inform. Same defect as "2 configurations found
    # — X, Y" while three existed: a count sourced differently from the
    # claim it sits inside.
    #
    # Reworded rather than recounted. Running the matcher over thousands
    # of vendor scripts purely to produce a more flattering number would
    # cost real time on every scan to answer a question the reader can
    # settle by passing the flag.
    if excluded_vendor:
        notes.append(
            f"{excluded_vendor} script record(s) in ServiceNow-shipped application scopes "
            f"(sn_*/com.snc/com.glide) were excluded BEFORE keyword matching, so this is a "
            "count of records skipped, not of records that would have been flagged — the "
            "number that would be flagged is smaller and unknown without rescanning. OOB "
            "Now Assist / AI Search / Virtual Agent code contains provider keywords "
            "legitimately. Pass include_vendor_scope=True to include them. Records in "
            "'global' scope are NOT excluded: global holds both vendor and customer code "
            "and nothing in the field set separates them."
        )
    if excluded_inactive:
        notes.append(
            f"{excluded_inactive} inactive script record(s) were excluded BEFORE keyword "
            "matching — again a count of records skipped, not of records that would have "
            "been flagged. Pass include_inactive=True to include them."
        )
    return agents, synthesized_tools


def fetch_shadow(
    client: ServiceNowClient,
    providers: list[Provider] | None = None,
    include_script_scan: bool = False,
    include_script_excerpts: bool = False,
    include_vendor_scope: bool = False,
    include_inactive: bool = False,
):
    """Returns (agents, tools, credentials, owners, scan_notes).

    include_vendor_scope / include_inactive turn OFF the tier-4 noise
    filters. They are threaded from the CLI (--include-vendor-scope /
    --include-inactive) rather than being tier-4-internal, because the
    scan notes those filters emit tell the reader how to re-include
    what was dropped — and an instruction the user cannot actually act
    on is worse than no instruction. Excluding findings silently and
    unrecoverably is the same class of failure as missing them.

    include_script_scan gates tiers 3-4 (see module docstring) — off by
    default because it requires a broader read grant than tiers 1-2.

    include_script_excerpts additionally allows a short, secret-scrubbed
    excerpt of the matching script into the report. Separate from
    include_script_scan on purpose: *reading* script source to detect
    something and *publishing* script source into a shareable report are
    two different risk decisions, and a customer may reasonably say yes
    to the first and no to the second. Default is no — see `_safe_raw`.
    """
    providers = providers or load_providers()
    notes: list[str] = []

    oauth_credentials = _tier1_oauth_credentials(client, providers, notes)
    rest_tools, rest_credentials, tools_by_name = _tier2_rest_message_tools(client, providers, notes)

    inbound_tools: list[Tool] = []
    script_agents: list[Agent] = []
    synthesized_tools: list[Tool] = []

    if include_script_scan:
        inbound_tools = _tier3_inbound_tools(
            client, providers, notes, include_script_excerpts=include_script_excerpts
        )
        script_agents, synthesized_tools = _tier4_script_agents(
            client, providers, tools_by_name, notes,
            include_script_excerpts=include_script_excerpts,
            include_vendor_scope=include_vendor_scope,
            include_inactive=include_inactive,
        )
        notes.append(
            "Script source was read for detection but is NOT stored in this report — "
            "each script-derived finding carries a sha256 fingerprint and length instead. "
            + (
                "Scrubbed excerpts were included (--include-script-excerpts)."
                if include_script_excerpts
                else "Pass --include-script-excerpts to include a short, secret-scrubbed "
                "excerpt around each match."
            )
        )
    else:
        notes.append(
            "Script-body scanning (tiers 3-4: Scripted REST API resources, Script Include/"
            "Business Rule/Scheduled Job keyword scan) was skipped — requires a read grant "
            "beyond the default scan. Pass include_script_scan=True (CLI: "
            "--include-script-scan) to enable it."
        )

    # Owner resolution across every tier in one pass, not just tier 4 —
    # tier-1 OAuth entities and tier-2 REST message credentials both had
    # `sys_created_by` (or a proxy for it) fetched into `raw` and then
    # never actually used to resolve an owner. That's a real accuracy
    # gap fixed here: every synthesized agent AND credential this module
    # produces now gets the same best-effort owner attribution, not just
    # the ones tier 4 happens to build.
    all_synthesized = [*oauth_credentials, *rest_credentials, *script_agents]
    creator_usernames = {
        obj.raw.get("_creator") for obj in all_synthesized if obj.raw.get("_creator")
    }
    owners_by_username, owner_notes = fetch_owners(client, creator_usernames)
    notes.extend(owner_notes)
    for obj in all_synthesized:
        creator = obj.raw.get("_creator")
        owner = owners_by_username.get(creator) if creator else None
        if owner:
            obj.owner_id = owner.id

    # If the instance refused to return the very field a tier matches on,
    # that tier did not find nothing — it could not look. Saying "0
    # matched" next to an unrelated ACL warning forces the reader to
    # correlate two notes to work out that the number is meaningless.
    # Confirmed live: `sys_rest_message.endpoint` was ACL-hidden, so tier
    # 2 — the CONFIRMED-grade tier the whole confidence model rests on —
    # reported "0 outbound REST message(s) matched a known LLM provider
    # host" on every run, which reads exactly like "there aren't any".
    # Derived from recorded gaps, NOT by grepping note prose.
    #
    # The old version matched the literal string "FIELD-LEVEL ACL". A
    # WRONG COLUMN NAME produces a note beginning "SCHEMA MISMATCH", so
    # the guard built to stop tier 2 reporting a confident zero checked
    # for the one cause that had already been fixed and not the one that
    # caused the bug. If `rest_endpoint` is ever wrong again — a different
    # release, a fork of the schema, or the `sys_rest_message_fn` variant
    # which is NOT independently verified — the note reverts verbatim to
    # "0 outbound REST message(s) matched a known LLM provider host
    # (confirmed)". That sentence IS the bug.
    #
    # `models.py` argues at length that gaps are structured data
    # precisely so nothing has to regex sentences. This was the one place
    # that regexed sentences. Reading `access_gaps` covers FIELD_ACL,
    # SCHEMA_MISMATCH and TABLE_DENIED at once and survives any rewording.
    tier2_blind = any(
        g.table == tables.REST_MESSAGE_TABLE
        and (tables.REST_ENDPOINT_FIELD in g.fields or not g.fields)
        for g in getattr(client, "access_gaps", [])
    ) or any(
        # Note text as a SECOND source, not the only one.
        #
        # Structured gaps are the primary signal and survive any
        # rewording. But a caller can produce a note without a recorded
        # gap — a wrapped client, a partial mock, a future code path that
        # forgets — and this particular guard is the one standing between
        # a blinded tier and the sentence "0 outbound REST message(s)
        # matched a known LLM provider host (confirmed)". That sentence
        # IS the worst bug this project has had.
        #
        # Two independent mechanisms for one claim is redundancy where
        # redundancy is cheap and the failure is expensive.
        tables.REST_MESSAGE_TABLE in n
        and ("FIELD-LEVEL ACL" in n or "SCHEMA MISMATCH" in n
             or "QUERY FILTER SILENTLY DROPPED" in n or "Access denied" in n)
        for n in notes
    )

    rest_tools_confirmed = sum(1 for t in rest_tools if t.confidence == Confidence.CONFIRMED)
    rest_tools_templated = len(rest_tools) - rest_tools_confirmed
    notes.append(
        "Shadow detection: "
        + (
            "outbound REST message matching COULD NOT RUN — the instance did not return "
            "`sys_rest_message.endpoint` (field-level ACL), so this tier is blind and the "
            "count below is not evidence of absence"
            if tier2_blind
            else f"{rest_tools_confirmed} outbound REST message(s) matched a known LLM "
            f"provider host (confirmed)"
        )
        + (
            f", {rest_tools_templated} more matched only via a name keyword on a templated "
            "endpoint whose real host isn't structurally visible (needs review)"
            if rest_tools_templated
            else ""
        )
        + f", {len(inbound_tools)} Scripted REST API resource(s) "
        f"flagged as possible inbound tool/MCP surfaces (needs review), {len(script_agents)} "
        f"script(s) synthesized into agents (confirmed where correlated to a tier-2 tool, "
        f"needs review otherwise)."
    )

    agents = script_agents
    tools = rest_tools + inbound_tools + synthesized_tools
    credentials = oauth_credentials + rest_credentials
    owners = list(owners_by_username.values())
    return agents, tools, credentials, owners, notes
