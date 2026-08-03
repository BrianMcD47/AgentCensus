"""Round 5 review — failing tests for defects found at v32.

Every test in this file FAILS against the current tree and describes one
defect. Run:  python -m pytest tests/test_round5_defects.py -q
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from agentcensus.connectors.servicenow import shadow, tables
from agentcensus.connectors.servicenow.http import ServiceNowClient
from agentcensus.core import report
from agentcensus.core.correlate import merge_inventories
from agentcensus.core.models import (
    AccessGap,
    AccessGapKind,
    Agent,
    Confidence,
    Inventory,
    Provenance,
)
from agentcensus.core.redaction import scrub_values

from tests.servicenow_fakes import FakeClient


def _client():
    return ServiceNowClient(instance_url="https://x.service-now.com", username="u", password="p")


def _resp(rows):
    r = MagicMock()
    r.status_code = 200
    r.headers = {}
    r.json.return_value = {"result": rows}
    r.raise_for_status.side_effect = None
    return r


# =====================================================================
# D1. columns_of() walks super_class with a DOT-WALK, which tables.py
#     itself documents the Table API silently does not honour.
# =====================================================================

def test_columns_of_resolves_inherited_columns_without_a_dotwalk():
    """`columns_of` asks sys_db_object for `super_class.name`.

    tables.py (HUB_ACTION_TYPE_TABLE) records, from a live measurement,
    that the Table API returns a dot-walked field as NOTHING AT ALL — the
    base field comes back, the dotted key never appears — and concludes
    "no dot-walks anywhere in this connector". `columns_of` is a dot-walk.

    Consequence: the super_class chain never advances past the first
    table, so INHERITED columns are absent from `columns_of`. Every
    inherited field (sys_created_by, sys_updated_on, sys_id, ...) that is
    genuinely withheld by a field-level ACL is then classified
    NOT-A-REAL-COLUMN and reported to the customer as "SCHEMA MISMATCH —
    a defect in AgentCensus". That is the original rest_endpoint bug with
    the sign flipped: a real permissions problem reported as our bug.
    """
    def handler(url, **kwargs):
        params = kwargs.get("params", {})
        query = params.get("sysparm_query", "")
        offset = int(params.get("sysparm_offset", 0) or 0)
        if "/sys_dictionary" in url:
            if offset:
                return _resp([])
            owner = query.split("name=")[1].split("^")[0]
            own_columns = {
                # sys_rest_message's OWN columns. sys_created_by is
                # inherited from sys_metadata, exactly as in reality.
                "sys_rest_message": ["sys_id", "name", "rest_endpoint"],
                "sys_metadata": ["sys_created_by", "sys_updated_on"],
            }
            return _resp([{"element": c} for c in own_columns.get(owner, [])])
        if "/sys_db_object" in url:
            # THE POINT: a real instance returns the base reference field
            # and no dot-walked key. tests/test_schema_mismatch.py's
            # fixture returns {"super_class.name": ...} instead, which is
            # the author's model of the platform, not the platform.
            # Second read of the two-read fix: resolve the parent's NAME
            # from its sys_id. Added to the reviewer's fixture, which
            # modelled only the first read and so could not pass under the
            # fix the same review recommended. The assertion is untouched.
            if "sys_id=" in query:
                return _resp([{"name": "sys_metadata"}])
            owner = query.split("name=")[1].split("^")[0] if "name=" in query else ""
            parent = {"sys_rest_message": "sys_metadata"}.get(owner)
            return _resp([{"super_class": "0" * 32}] if parent else [])
        return _resp([{"sys_id": "1", "name": "x", "rest_endpoint": "https://h"}] if not offset else [])

    client = _client()
    with patch("requests.get", side_effect=handler):
        columns = client.columns_of("sys_rest_message")

    assert "sys_created_by" in columns, (
        "inherited column missing: the super_class walk stopped at the first "
        "table because the dot-walk was not honoured"
    )


def test_a_denied_inherited_field_is_not_blamed_on_agentcensus():
    """The user-visible consequence of D1."""
    def handler(url, **kwargs):
        params = kwargs.get("params", {})
        query = params.get("sysparm_query", "")
        offset = int(params.get("sysparm_offset", 0) or 0)
        if "/sys_dictionary" in url:
            if offset:
                return _resp([])
            owner = query.split("name=")[1].split("^")[0]
            own = {
                "gen_ai_service_secret": ["sys_id", "name", "purpose", "state"],
                "sys_metadata": ["sys_created_by", "sys_created_on", "sys_updated_on"],
            }
            return _resp([{"element": c} for c in own.get(owner, [])])
        if "/sys_db_object" in url:
            if "sys_id=" in query:
                return _resp([{"name": "sys_metadata"}])
            owner = query.split("name=")[1].split("^")[0] if "name=" in query else ""
            parent = {"gen_ai_service_secret": "sys_metadata"}.get(owner)
            return _resp([{"super_class": "0" * 32}] if parent else [])
        # sys_created_by withheld by a REAL field-level ACL (README
        # documents exactly this on the reference instance).
        return _resp([{"sys_id": "1", "name": "k", "purpose": "p", "state": "active"}] if not offset else [])

    client = _client()
    with patch("requests.get", side_effect=handler):
        _rows, note = client.safe_get_all(
            "gen_ai_service_secret",
            ["sys_id", "name", "purpose", "state", "sys_created_by"],
        )

    assert "FIELD-LEVEL ACL" in note, f"expected an ACL note, got: {note}"
    assert "SCHEMA MISMATCH" not in note, (
        "a genuinely ACL-denied inherited column was reported to the customer "
        "as an AgentCensus bug — the rest_endpoint failure, inverted"
    )
    assert all(g.kind is not AccessGapKind.SCHEMA_MISMATCH for g in client.access_gaps)


# =====================================================================
# D2. sys_dictionary is not in the read manifest, so preflight never
#     tells anyone the schema-mismatch diagnostic is inoperative.
# =====================================================================

def test_sys_dictionary_is_declared_in_the_read_manifest():
    """`columns_of` reads sys_dictionary on every classify call, and
    fails OPEN (empty set -> everything reported as FIELD-LEVEL ACL).

    sys_dictionary is commonly restricted on a least-privileged account.
    When it is, the entire schema-mismatch machinery silently reverts to
    the pre-v17 behaviour that caused the worst bug in the project — and
    nothing says so. It is also absent from DEFAULT_READ_MANIFEST, whose
    own comment says deriving preflight from it makes manifest drift
    "impossible", and from README's list of what the tool reads.
    """
    manifest_tables = {t for t, _f, _w in tables.DEFAULT_READ_MANIFEST}
    assert "sys_dictionary" in manifest_tables


# =====================================================================
# D3. tier2_blind only recognises FIELD-LEVEL ACL, not SCHEMA MISMATCH.
# =====================================================================

def test_tier2_reports_blindness_for_a_schema_mismatch_too():
    """shadow.fetch_shadow decides tier 2 is blind by grepping notes for
    the literal 'FIELD-LEVEL ACL'. A wrong column name produces a
    'SCHEMA MISMATCH' note instead — so if `rest_endpoint` is ever wrong
    again, the scan note reverts to the exact sentence that hid the bug
    for the whole life of the project: '0 outbound REST message(s)
    matched a known LLM provider host (confirmed)'.

    The guard built to stop that failure does not cover the cause of it.
    """
    class SchemaMismatchClient(FakeClient):
        def safe_get_all(self, table, fields, query="", filter_fields=None):
            if table == tables.REST_MESSAGE_TABLE:
                return [{"sys_id": "1", "name": "Anthropic Chat"}], (
                    f"SCHEMA MISMATCH on '{tables.REST_MESSAGE_TABLE}': this tool "
                    f"requested field(s) {tables.REST_ENDPOINT_FIELD}, which DO NOT EXIST "
                    "on that table."
                )
            return super().safe_get_all(table, fields, query, filter_fields)

    client = SchemaMismatchClient({tables.REST_MESSAGE_TABLE: [{"sys_id": "1", "name": "x"}]})
    *_rest, notes = shadow.fetch_shadow(client)
    summary = next(n for n in notes if n.startswith("Shadow detection:"))

    assert "0 outbound REST message(s) matched" not in summary, (
        "tier 2 could not look, and reported a confirmed zero anyway"
    )
    assert "COULD NOT RUN" in summary


# =====================================================================
# D4. Multi-connector scans silently drop the entire access section.
# =====================================================================

def test_merge_inventories_preserves_access_gaps():
    """`merge_inventories` rebuilds an Inventory without `access_gaps`,
    so `--connector servicenow --connector splunk` loses every recorded
    gap. The HTML then renders the GREEN banner: 'Full coverage — every
    table and field this scan needs was readable.'

    The tool's headline promise, inverted, by adding a second --connector.
    """
    sn = Inventory(
        platform="servicenow",
        scanned_at=datetime.now(timezone.utc),
        access_gaps=[
            AccessGap(table="auth_server_connection", kind=AccessGapKind.TABLE_DENIED),
        ],
    )
    sp = Inventory(platform="splunk", scanned_at=datetime.now(timezone.utc))

    merged = merge_inventories([sn, sp])
    assert len(merged.access_gaps) == 1, "access gaps were dropped by the merge"

    html = report.render_html(merged, [])
    assert "Full coverage" not in html


def test_coverage_banner_does_not_claim_full_coverage_for_a_connector_that_cannot_record_gaps():
    """Only the ServiceNow connector populates `access_gaps`. Anthropic
    and Splunk never do — not because they had full access, but because
    neither has any access-gap recording at all. The banner reads the
    empty list as an affirmative statement of complete coverage.

    A Splunk scan in which every endpoint returned 403 renders green.
    """
    splunk_only = Inventory(
        platform="splunk",
        scanned_at=datetime.now(timezone.utc),
        scan_notes=["Access denied reading '/services/saved/searches'."],
    )
    html = report.render_html(splunk_only, [])
    assert "Full coverage" not in html


# =====================================================================
# D5. "Where to find it" is dead in the findings table.
# =====================================================================

def test_findings_table_renders_a_navigation_target():
    """`_where_to_find(finding.subject_id, finding.evidence.get("raw"))`
    — no rule anywhere puts a `raw` key into `evidence`. The lookup is
    always None, so the column is unconditionally empty in the table a
    reader actually works from.

    Separately, `_kind` is set by shadow.py tier 4 only, so the agent
    inventory's 'Where to find it' column renders '—' for every Flow
    Designer, AI Agent Studio and Build Agent agent.
    """
    from agentcensus.core.models import Finding, FindingClass, Severity

    agent = Agent(
        id="abc123", name="F", description=None, owner_id=None,
        provenance=Provenance.SYNTHESIZED, confidence=Confidence.NEEDS_REVIEW,
        detection_signal="flow_designer:name_match",
        raw={"sys_id": "abc123", "name": "F", "_creator": "admin"},
    )
    finding = Finding(
        rule_id="ungoverned.shadow_agent",
        finding_class=FindingClass.UNGOVERNED,
        severity=Severity.MEDIUM,
        subject_type="agent", subject_id="abc123",
        title="'F' appears to be an LLM integration with no native governance record",
        explanation="x", recommended_action="y",
        confidence=Confidence.NEEDS_REVIEW,
        evidence={"detection_signal": "flow_designer:name_match"},
    )
    inv = Inventory(platform="servicenow", scanned_at=datetime.now(timezone.utc), agents=[agent])
    html = report.render_html(inv, [finding])

    assert "sys_hub_flow.do?sys_id=abc123" in html


# =====================================================================
# D6. SCHEMA_MISMATCH is not handled everywhere kind is switched on.
# =====================================================================

def test_schema_mismatch_has_a_human_label_and_is_not_offered_as_a_grant():
    """`_GAP_LABEL` has entries for three of four AccessGapKind values.
    A schema mismatch renders the raw enum string 'schema_mismatch' in
    the Kind column — inside a section titled 'Access needed to complete
    this scan', under a paragraph reading 'Each row is one grant to give
    the scan account', above a 'How to grant these' walkthrough.

    Everything about that framing is wrong for the one kind that models.py
    explicitly says is NOT an access problem, and it is the framing the
    project has already had to retract once.
    """
    inv = Inventory(
        platform="servicenow",
        scanned_at=datetime.now(timezone.utc),
        access_gaps=[
            AccessGap(
                table="sys_rest_message",
                kind=AccessGapKind.SCHEMA_MISMATCH,
                fields=("endpoint",),
            )
        ],
    )
    html = report.render_html(inv, [])
    assert "schema_mismatch" not in html, "raw enum value leaked into the rendered Kind column"
    assert "AgentCensus bug" in html


# =====================================================================
# D7. Vendor/inactive exclusion notes claim a keyword match that was
#     never evaluated.
# =====================================================================

def test_vendor_exclusion_note_does_not_claim_records_matched_a_keyword():
    """In `_tier4_script_agents` the vendor-scope and inactive filters
    run BEFORE `match_keywords`. So `excluded_vendor` counts every
    vendor-scope record that merely HAS a script, and the note says:

        "N script record(s) ... matched a provider keyword and were excluded"

    On the PDI measured in tables.py that N was 3,046. Almost none of
    them matched anything. This is the "2 configurations found — X, Y
    while three existed" defect: a count sourced differently from the
    claim it is embedded in.
    """
    client = FakeClient({
        tables.APP_SCOPE_TABLE: [{"sys_id": "s1", "scope": "sn_vendor_thing"}],
        tables.SCRIPT_INCLUDE_TABLE: [
            {"sys_id": "a", "name": "Totally Unrelated", "script": "gs.info('hello');",
             "active": "true", "sys_scope": "s1"},
        ],
    })
    notes: list[str] = []
    shadow._tier4_script_agents(client, shadow.load_providers(), {}, notes)

    vendor_notes = [n for n in notes if "ServiceNow-shipped application scopes" in n]
    assert vendor_notes, "expected a vendor-exclusion note"
    assert "matched a provider keyword" not in vendor_notes[0], vendor_notes[0]


# =====================================================================
# D8. MCP registrations are named by sys_id; the inactive filter is dead.
# =====================================================================

def test_mcp_registrations_are_named_not_rendered_as_a_sys_id():
    """mcp_server.py builds `Tool(name=r.get("name", r["sys_id"]))`, but
    `MCP_REGISTRY_FIELDS` does not contain `name` — the table is
    `auth_server_connection`, whose identifying column is
    `connection_alias`. So every MCP registration renders as 32 hex
    characters.

    This is byte-for-byte the defect nask.py fixed with `_LABEL_FIELDS`
    ("a sys_id is an identifier, not a name"), left live in the sibling
    module written in the same session.
    """
    from agentcensus.connectors.servicenow import mcp_server

    client = FakeClient({
        tables.MCP_REGISTRY_TABLE: [
            {"sys_id": "cb1ba3ccff5312107f63ffffffffff00",
             "connection_alias": "Claude Desktop MCP",
             "authorization_type": "oauth2", "resource": "https://x"},
        ],
    })
    tools, _owners, _notes = mcp_server.fetch_mcp_server_console(client)
    assert tools
    assert tools[0].name != tools[0].id, "MCP registration rendered as a bare sys_id"
    assert "Claude Desktop MCP" in tools[0].name


def test_mcp_inactive_filter_is_not_dead_code():
    """`fetch_mcp_server_console` calls `is_inactive(r)` and reports
    "N inactive MCP Server Console registration(s) were excluded" — but
    `active` is not in MCP_REGISTRY_FIELDS, so it is never requested,
    `is_inactive` always returns False, and that counter is structurally
    always zero. The comment above the filter still says "`active` is
    requested by this field list", which stopped being true when the
    registry was renamed to auth_server_connection.

    Either request the column or delete the filter and its note.

    RESOLVED BY DELETING (the review offered both). The UI list view for
    `auth_server_connection`, transcribed by hand because the table is
    403 to the API, shows: Authorization Type, CI Resource record, CI
    Resource table, Connection Alias, Access control enabled, Resource,
    Restricted Mode Opt-In. There is NO Active column.

    So adding `active` to the field list would be inventing a column —
    the precise defect class that produced the eight wrong field names,
    committed while fixing a symptom of it. A filter that cannot run is
    better deleted than fed a guess.
    """
    import inspect

    from agentcensus.connectors.servicenow import mcp_server

    src = inspect.getsource(mcp_server.fetch_mcp_server_console)
    # The CALL, not the word: a comment explaining why the filter was
    # removed is exactly what should remain.
    assert "is_inactive(" not in src, "dead filter still present"
    assert "inactive MCP Server Console registration" not in src, (
        "the note guarded by a structurally-zero counter is still emitted"
    )
    assert "active" not in tables.MCP_REGISTRY_FIELDS, (
        "requesting a column the UI shows does not exist"
    )


# =====================================================================
# D9. Over-redaction: a `credential` reference is not a credential.
# =====================================================================

def test_a_credential_reference_field_is_not_redacted():
    """`_JSON_PAIR_SECRET_PATTERN` excludes `credential_id` via an
    explicit lookahead — added after a round found the tool redacting a
    foreign key. config_surfaces stores the same reference under the key
    `credential` (that is the real column name on sys_connection /
    http_connection), which the lookahead does not cover.

    So the join key between a connection and its credential record is
    destroyed in every report, for the same reason and with the same
    consequence as the defect already fixed once.
    """
    payload = '{"credential": "a1b2c3d4e5f60718293a4b5c6d7e8f90", "name": "gw"}'
    assert scrub_values(payload) == payload


# =====================================================================
# D10. get_all terminates on a fully ACL-filtered page.
# =====================================================================

def test_pagination_survives_a_page_emptied_entirely_by_row_level_acls():
    """get_all's own comment establishes that row-level ACLs silently
    drop rows from a pagination window without the server signalling
    anything. It then breaks the loop on `len(page) == 0`.

    A run of 100 consecutive ACL-denied rows therefore produces an empty
    page mid-table and truncates the rest of it — silently, with no note,
    which is the precise failure mode `_with_stable_order` and the
    short-page fix were both written to eliminate.
    """
    pages = {0: [{"sys_id": str(i)} for i in range(100)],
             100: [],  # every row in this window denied by a row-level ACL
             200: [{"sys_id": str(i)} for i in range(200, 300)]}

    def handler(url, **kwargs):
        offset = int(kwargs["params"].get("sysparm_offset", 0) or 0)
        return _resp(pages.get(offset, []))

    client = _client()
    with patch("requests.get", side_effect=handler):
        rows = client.get_all("sys_script", ["sys_id"])

    assert len(rows) == 200, f"truncated at {len(rows)} rows by one ACL-emptied page"


# =====================================================================
# D11. match_keywords is a bare substring match, in a codebase that has
#      twice reasoned its way to word boundaries and not applied them here.
# =====================================================================

def test_keyword_matching_respects_word_boundaries():
    """`_references_tool` uses `\\b...\\b` because "a REST message named
    'Chat' would otherwise match inside 'ChatHistoryUtils'".
    `_platform_ai_note` uses `\\b` "so `nowassist` doesn't match inside an
    unrelated identifier". `match_keywords` — the matcher that drives
    tiers 1, 3 and 4, flow names, spoke names and property names — uses a
    plain `in`.

    So the word "coherence" in a comment makes a Script Include a Cohere
    integration, and every tier-4 keyword hit inherits the same class of
    error the other two matchers were explicitly hardened against.
    """
    from agentcensus.connectors.servicenow.llm_providers import load_providers, match_keywords

    hits = match_keywords("// ensure data coherence across nodes", load_providers())
    assert hits == [], f"false positive: {[p.id for p in hits]}"


# =====================================================================
# D12. A CONFIRMED-grade host match on a generic localhost port.
# =====================================================================

def test_a_generic_localhost_port_is_not_a_confirmed_llm_gateway():
    """llm_providers.yaml ships `localhost:8000` and `localhost:4000` as
    HOSTS, and `match_host` is a substring test. Hosts are the CONFIRMED
    tier — models.py defines CONFIRMED as "the signal is structural (a
    REST message endpoint literally matches a known LLM API host)".

    `http://localhost:8000/` is the single most generic dev endpoint
    there is. Any REST message, connection alias or system property
    pointing at it is reported as a confirmed self-hosted LLM gateway,
    at full severity, with no cap. These belong under `keywords`
    (NEEDS_REVIEW), where the yaml's own comment says the value is.
    """
    from agentcensus.connectors.servicenow.llm_providers import load_providers, match_host

    hit = match_host("http://localhost:8000/api/v2/reports", load_providers())
    assert hit is None, f"confirmed-grade false positive on {hit.id}"
