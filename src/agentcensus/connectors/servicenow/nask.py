"""Now Assist Skill Kit (NASK) detection — ServiceNow's distinct
custom-generative-AI-skill authoring surface.

Worth naming as its own module rather than folding into flow_designer.py
or native.py: "skill" is a specific ServiceNow product concept, distinct
from an AI Agent Studio "agent" (native.py) and a Flow Designer "flow"
(flow_designer.py) — NASK lets admins/developers wire a custom prompt to
an LLM provider/model and expose the result as a reusable skill inside
Now Assist. Missing it would leave exactly the kind of "custom skill"
gap the project was asked to cover explicitly.

VERIFICATION STATUS: table names below (sys_generative_ai_provider,
sys_generative_ai_provider_mapping, sys_generative_ai_model_config) come
from public ServiceNow documentation/community sources describing GenAI
Controller configuration, not from a live-instance read — same caveat
class as flow_designer.py's tables before this project's live
verification pass corrected native.py's. Treat as a first draft.

Deliberately does NOT read `sys_generative_ai_log` or
`sys_gen_ai_usage_log`. Those tables hold actual prompt/response payload
content and per-run usage detail — a materially more sensitive read than
"which providers/models are configured," on par with shadow.py's
script-source tiers. This module only reads provider/model
*configuration* (structured metadata, analogous to flow_designer.py's
sensitivity class), so it stays in the default scan. If per-skill usage
auditing is wanted later, it belongs behind `include_script_scan` (or a
new equivalently-named opt-in), not bundled in here by default.
"""

from __future__ import annotations

from agentcensus.connectors.servicenow import is_inactive, tables
from agentcensus.connectors.servicenow.http import ServiceNowClient
from agentcensus.core.models import Confidence, Provenance, Tool

# Table/field constants live in tables.py, same as every other detection
from agentcensus.core.redaction import scrub

# module in this connector — see mcp_server.py's equivalent comment for
# why (single source of truth, mechanically checked by
# tests/test_no_secret_fields.py).
PROVIDER_MAPPING_TABLE = tables.NASK_PROVIDER_MAPPING_TABLE
PROVIDER_MAPPING_FIELDS = tables.NASK_PROVIDER_MAPPING_FIELDS

MODEL_CONFIG_TABLE = tables.NASK_MODEL_CONFIG_TABLE
MODEL_CONFIG_FIELDS = tables.NASK_MODEL_CONFIG_FIELDS


# Which column actually identifies a record on each table, best first.
# Verified against sys_dictionary on a live instance (2026-08); neither
# table has `name`, which is what the previous code asked for.
_LABEL_FIELDS = {
    PROVIDER_MAPPING_TABLE: ("provider", "provider_api", "gen_ai_provider"),
    MODEL_CONFIG_TABLE: ("model_display_name", "model", "provider"),
}


def _label_for(table: str, row: dict) -> str:
    """First readable identifying value, or "" if none came back."""
    for field in _LABEL_FIELDS.get(table, ()):
        value = row.get(field)
        if isinstance(value, dict):
            value = value.get("display_value") or value.get("value")
        if value and str(value).strip():
            return str(value).strip()
    return ""


def fetch_genai_credentials(client: ServiceNowClient):
    """Generative-AI credential stores, enumerated as metadata only.

    Returns (credentials, notes). Kept separate from `fetch_nask` rather
    than folded into its return so the existing signature and its callers
    are untouched — a new surface should not require editing the tests of
    an old one.

    These tables hold API keys for generative-AI providers. This function
    never requests the secret column: the field lists in
    `tables.GENAI_SECRET_TABLES` name only sys_id and audit stamps, and
    tests/test_no_secret_fields.py scans those lists mechanically to keep
    it that way. The finding is "a generative-AI credential exists here,
    created by X, and nothing else in this scan explains it" — which is
    actionable without the value, and is the same shape as the
    unattributed-integration-account finding.

    Enumerated even though every neighbouring GenAI table was empty on
    the instance that motivated this, because `gen_ai_service_secret` was
    NOT empty there. A credential can outlive the integration that used
    it, or precede the one that will — which is exactly when nobody is
    watching it.
    """
    from agentcensus.core.models import AccountType, Credential

    credentials: list[Credential] = []
    notes: list[str] = []

    for table, fields, label in tables.GENAI_SECRET_TABLES:
        exists, err = client.table_exists(table)
        if err:
            notes.append(f"Could not check generative-AI credential table '{table}': {err}")
            continue
        if not exists:
            continue

        raw, err = client.safe_get_all(table, fields)
        if err:
            notes.append(err)
        if not raw:
            continue

        for r in raw:
            credentials.append(
                Credential(
                    id=r["sys_id"],
                    # No name column is read (it could carry a hint about
                    # the secret's purpose, but naming conventions are not
                    # worth another field-ACL surface here), so the record
                    # is labelled by what it is. The sys_id stays in the
                    # id field where an identifier belongs — same
                    # reasoning as the NASK naming fix above.
                    name=f"{label} ({table})",
                    account_type=AccountType.UNKNOWN,
                    owner_id=None,
                    source=table,
                )
            )

    if credentials:
        notes.append(
            f"{len(credentials)} generative-AI service credential(s) are stored on this "
            "instance. Only their existence and audit stamps were read — no secret value was "
            "requested at any point. Each one authorises a call to an external model provider, "
            "so any that no other finding in this report explains is worth attributing by hand."
        )
    return credentials, notes


def fetch_nask(client: ServiceNowClient, include_inactive: bool = False):
    """Returns (tools, notes). No owner resolution attempted — provider/
    model config records aren't reliably tied to a specific human the way
    an agent or flow's creator is; ownership here is a governance
    question for a human to answer, not one this shallow a read can
    infer."""
    notes: list[str] = []
    tools: list[Tool] = []
    excluded_inactive = 0

    for table, fields, label in [
        (PROVIDER_MAPPING_TABLE, PROVIDER_MAPPING_FIELDS, "provider mapping"),
        (MODEL_CONFIG_TABLE, MODEL_CONFIG_FIELDS, "model config"),
    ]:
        exists, err = client.table_exists(table)
        if err:
            notes.append(f"Could not check for Now Assist Skill Kit ({table}): {err}")
            continue
        if not exists:
            notes.append(
                f"Now Assist Skill Kit {label} table ('{table}') not found — either not "
                "configured on this instance, or the table name needs live-instance "
                "verification (see module docstring)."
            )
            continue

        raw, err = client.safe_get_all(table, fields)
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
            continue

        # Was the name column withheld, or is it genuinely blank? The
        # report has to say one of the two and they are not the same
        # fact. Measured live: `name` was withheld by a field-level ACL
        # on BOTH NASK tables, and every record rendered "(unnamed)" —
        # which tells the reader the record has no name. It has a name;
        # this account may not read it. Labelling a permissions boundary
        # as a property of the data is the cosmetic-fix-to-a-blindness
        # failure this project has now made twice.
        # There is no `name` column on either NASK table — verified live
        # (2026-08). Both were being asked for one, getting silence, and
        # rendering every record as "(unnamed)". The label comes from
        # whichever identifying column the table actually has.
        name_withheld = bool(client.unreadable_fields(raw, [_LABEL_FIELDS[table][0]]))

        for r in raw:
            # Same gap as mcp_server.py: `active` fetched, never read.
            if not include_inactive and is_inactive(r):
                excluded_inactive += 1
                continue
            tools.append(
                Tool(
                    id=r["sys_id"],
                    # Live instances return these rows with an EMPTY
                    # name, so the fallback produced findings titled
                    # "'cb1ba3ccff5312107f63ffffffffff00' calls out to
                    # an external LLM provider" — unreadable, and the
                    # reader has no way to know what it refers to. A
                    # sys_id is an identifier, not a name; label the
                    # record by what it IS and keep the id in the
                    # subject field where it belongs.
                    name=(
                        _label_for(table, r)
                        or (
                            f"Now Assist {label} <unreadable: field-level ACL>"
                            if name_withheld
                            else f"Now Assist {label} (unidentified)"
                        )
                    ),
                    description=(
                        f"Now Assist Skill Kit {label} — a configured LLM provider/model "
                        "wiring available to custom generative AI skills on this instance. "
                        "Which specific skill(s) use it isn't visible from this table alone."
                    ),
                    credential_id=None,
                    provenance=Provenance.SYNTHESIZED,
                    confidence=Confidence.NEEDS_REVIEW,
                    direction="outbound",
                    raw=scrub(r),
                )
            )

    if excluded_inactive:
        notes.append(
            f"{excluded_inactive} inactive Now Assist Skill Kit configuration(s) were "
            "excluded. Pass --include-inactive to include them."
        )

    if tools:
        # NAME them. Before the field-name fix these records rendered as
        # "(unnamed)" and this note said only how many there were, so the
        # count was the whole message. With the right columns the same
        # read yields "VA Azure OpenAI", "gpt-4o",
        # "AmazonBedrockResponseHandler" — i.e. WHICH model providers this
        # instance is configured to call, which is the actual governance
        # question. Reporting a count when you know the names is throwing
        # away the finding and keeping the statistic.
        # The count and the list are derived from the SAME sequence, so
        # they cannot disagree.
        #
        # They did: a live run printed "2 provider/model configuration(s)
        # found — VA Azure OpenAI, gpt-4o" while the inventory held three
        # NASK tools, the third being an Amazon Bedrock handler. Counting
        # `tools` and naming a filtered subset of `tools` is two sources
        # of truth for one sentence, and the filter (dropping
        # placeholder-named records) silently changed the meaning of the
        # number.
        #
        # A reader cannot audit a count against a list that was built
        # differently. Now every entry that is counted is also named, and
        # a record whose identifying column was unreadable says so in
        # place of being quietly dropped.
        names = [t.name for t in tools]
        shown = ", ".join(names[:8]) + (f" (+{len(names) - 8} more)" if len(names) > 8 else "")
        notes.append(
            f"Now Assist Skill Kit: {len(names)} provider/model configuration(s) found — "
            f"{shown}. These name the model providers this instance is configured to "
            "call. Custom generative AI skills can be built against them, and any traffic "
            "they carry leaves the platform. See module docstring for why per-skill usage "
            "detail isn't read here."
        )
    return tools, notes
