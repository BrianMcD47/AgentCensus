"""The access section: every refused read, as one actionable list.

Motivated by a live run that produced NINE separate blindness notes —
each naming a table, each stating a consequence, each correct, ordered by
whenever that table happened to be read. All the information a customer
needs to fix their coverage, in a form nobody will act on.

The tests here mostly guard against the two ways this feature fails
quietly:

  - it under-reports (a module's refused read never reaches the section,
    so the list looks shorter than reality and a customer grants nine
    permissions believing they've fixed everything)
  - it over-reports (duplicate rows for the same grant, which is how a
    section becomes noise and gets skipped, putting us back where we
    started with better formatting)

Both are silent. Neither shows up as a failing scan.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from agentcensus.connectors.servicenow import tables
from agentcensus.connectors.servicenow.http import ServiceNowClient
from agentcensus.core.models import AccessGap, AccessGapKind, Inventory
from agentcensus.core.report import _render_access_gaps, render_html, to_json


def _client() -> ServiceNowClient:
    return ServiceNowClient(instance_url="https://x.service-now.com", username="u", password="p")


def _pages(rows: list[dict]) -> list[MagicMock]:
    out = []
    for payload in (rows, []):
        r = MagicMock()
        r.status_code = 200
        r.headers = {}
        r.json.return_value = {"result": payload}
        r.raise_for_status.side_effect = None
        out.append(r)
    return out


def _denied() -> MagicMock:
    import requests

    r = MagicMock()
    r.status_code = 403
    r.headers = {}
    r.raise_for_status.side_effect = requests.HTTPError(response=r)
    return r


# ---------------------------------------------------------------------
# capture
# ---------------------------------------------------------------------

def test_a_denied_table_is_recorded_as_a_gap():
    client = _client()
    with patch("requests.get", return_value=_denied()):
        client.safe_get_all("sys_store_app", ["sys_id", "name"])

    assert len(client.access_gaps) == 1
    gap = client.access_gaps[0]
    assert gap.kind is AccessGapKind.TABLE_DENIED
    assert gap.grant == "read on table sys_store_app"
    # Impact comes from the measured mapping, not from the note text.
    assert gap.impact and "spokes" in gap.impact


def test_a_withheld_field_is_recorded_with_the_field_named():
    """The grant a ServiceNow admin needs is field-level, so a section
    that said only "sys_rest_message" would send them to widen access on
    a whole table when one column is what's wanted. Least privilege is
    the thing this product asks customers for; the remediation it prints
    has to respect it too."""
    client = _client()
    with patch("requests.get", side_effect=_pages([{"sys_id": "1", "name": "x"}])):
        client.safe_get_all(tables.REST_MESSAGE_TABLE, ["sys_id", "name", tables.REST_ENDPOINT_FIELD])

    gap = client.access_gaps[0]
    assert gap.kind is AccessGapKind.FIELD_ACL
    assert gap.fields == ("rest_endpoint",)
    assert "rest_endpoint" in gap.grant
    assert gap.impact and "Tier 2" in gap.impact


def test_the_same_grant_is_not_listed_twice():
    """`sys_user` is read by owners.py AND integration_accounts.py in one
    scan; several tables are read by more. Without dedup the section
    repeats the same row and becomes the thing it was built to replace."""
    client = _client()
    for _ in range(4):
        with patch("requests.get", return_value=_denied()):
            client.safe_get_all("sys_user", ["sys_id", "user_name"])

    assert len(client.access_gaps) == 1


def test_different_fields_on_one_table_stay_distinct():
    """Control for the dedup above: `sys_hub_action_instance` withheld
    both `name` and `active` on a live run. Collapsing by table alone
    would report one and hide the other."""
    client = _client()
    with patch("requests.get", side_effect=_pages([{"sys_id": "1"}])):
        client.safe_get_all("t", ["sys_id", "alpha"])
    with patch("requests.get", side_effect=_pages([{"sys_id": "1"}])):
        client.safe_get_all("t", ["sys_id", "beta"])

    assert len(client.access_gaps) == 2


def test_an_unmapped_surface_still_appears_without_inventing_an_impact():
    """A gap with no measured consequence is still worth listing — the
    admin can grant it — but claiming an impact this project never
    observed would be the same fabrication the report spent two rounds
    removing. Silence beats a plausible sentence."""
    client = _client()
    with patch("requests.get", return_value=_denied()):
        client.safe_get_all("some_table_nobody_mapped", ["sys_id"])

    gap = client.access_gaps[0]
    assert gap.impact is None
    assert "some_table_nobody_mapped" in _render_access_gaps([gap])


def test_probe_records_gaps_too_not_just_safe_get_all():
    """Found by the first live run of this feature: the section reported
    8 grants where the same scan's notes described 12, silently omitting
    all four MCP governance tables. `mcp_server.py` discovers those by
    PROBING, and only `safe_get_all` recorded gaps — so the section named
    every grant except the most valuable one and looked complete.

    Worse than a missing feature: a customer grants 8 permissions,
    believes coverage is now total, and MCP stays dark with nothing left
    in the report to say otherwise."""
    client = _client()
    with patch("requests.get", return_value=_denied()):
        status, _ = client.probe("mcp_auth_scopes", ["sys_id"])

    assert status == "denied"
    assert [g.grant for g in client.access_gaps] == ["read on table mcp_auth_scopes"]
    assert client.access_gaps[0].impact and "MCP servers" in client.access_gaps[0].impact


def test_probe_records_withheld_fields():
    """`preflight` exists to tell a security team what the scan will and
    won't see. A field it finds withheld has to reach the access section,
    or preflight knows something the report doesn't."""
    client = _client()
    r = MagicMock()
    r.status_code = 200
    r.headers = {}
    r.json.return_value = {"result": [{"sys_id": "1", "name": "x"}]}
    r.raise_for_status.side_effect = None
    with patch("requests.get", return_value=r):
        client.probe(tables.REST_MESSAGE_TABLE, ["sys_id", "name", tables.REST_ENDPOINT_FIELD])

    assert client.access_gaps[0].fields == ("rest_endpoint",)


def test_every_denial_path_in_the_client_records_a_gap():
    """Mechanical guard for the bug above, which was a MISSING call site
    rather than a wrong one — the kind of defect no behavioural test
    catches, because the path nobody remembered is also the path nobody
    wrote a test for.

    Asserts that each place the client concludes 'denied' sits near a
    `_record_gap`. Crude, and deliberately so: it fails loudly when a
    fifth denial path is added, which is the moment the reminder is
    worth something."""
    import inspect
    import re

    src = inspect.getsource(ServiceNowClient)
    # Anchored on the literal string a denial path RETURNS, not on the
    # word "denied" anywhere — `classify_missing_fields` has a local
    # named `denied` and is not a denial path.
    for match in re.finditer(r'return "denied"|return \[\], f"Access denied', src):
        window = src[max(0, match.start() - 700):match.start()]
        assert "_record_gap" in window, (
            "a denial path with no _record_gap within 700 chars — the access "
            "section will under-report:\n" + src[match.start() - 200:match.start() + 120]
        )


# ---------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------

def test_a_dropped_filter_is_called_out_above_the_table():
    """The only gap kind that makes findings WRONG rather than missing.
    Buried in a list of nine it reads as one more permission to grant; it
    is qualitatively different and has to look different."""
    gap = AccessGap(
        table="sys_user",
        kind=AccessGapKind.FILTER_DROPPED,
        fields=("web_service_access_only",),
    )
    html = _render_access_gaps([gap])
    assert "silently discarded" in html
    assert "may be wrong" in html


def test_gaps_with_measured_impact_sort_above_bare_ones():
    """A reader scans the top of a table. The rows that can justify a
    change request belong there."""
    mapped = AccessGap(
        table=tables.REST_MESSAGE_TABLE, kind=AccessGapKind.FIELD_ACL,
        fields=("rest_endpoint",), impact="Tier 2 cannot run.",
    )
    bare = AccessGap(table="whatever", kind=AccessGapKind.TABLE_DENIED)
    html = _render_access_gaps([bare, mapped])
    assert html.index("Tier 2 cannot run.") < html.index("whatever")


def test_no_gaps_says_so_positively():
    """An empty section must not read as a missing section. "Nothing was
    refused" is a real, reassuring result and the scan should claim it."""
    html = _render_access_gaps([])
    assert "No access gaps" in html
    # And is honest about what it does NOT mean.
    assert "what this tool knows to look for" in html


def test_the_section_appears_in_the_html_report():
    inv = Inventory(
        platform="servicenow",
        scanned_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        access_gaps=[AccessGap(table="sys_store_app", kind=AccessGapKind.TABLE_DENIED)],
    )
    html = render_html(inv, [])
    assert "Access needed to complete this scan" in html
    assert "read on table sys_store_app" in html


def test_gaps_are_machine_readable_in_json():
    """So a pipeline can gate on coverage — "fail if any filter was
    dropped" is a check worth being able to write, and parsing it out of
    prose notes would be miserable."""
    inv = Inventory(
        platform="servicenow",
        scanned_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        access_gaps=[
            AccessGap(table="sys_user", kind=AccessGapKind.FILTER_DROPPED, fields=("flag",)),
        ],
    )
    payload = json.loads(to_json(inv, []))
    assert payload["access_gaps"][0]["kind"] == "filter_dropped"
    assert payload["access_gaps"][0]["fields"] == ["flag"]


def test_the_section_carries_no_record_data():
    """It reports permissions, never contents. A section about what could
    not be read must not become a place where something read leaks."""
    gap = AccessGap(
        table=tables.SYS_PROPERTIES_TABLE,
        kind=AccessGapKind.FIELD_ACL,
        fields=("type",),
        impact=tables.impact_for(tables.SYS_PROPERTIES_TABLE, ("type",)),
    )
    html = _render_access_gaps([gap])
    for leaked in ["sk-", "Bearer ", "password", "secret"]:
        assert leaked not in html


# ---------------------------------------------------------------------
# report readability — found by rendering the HTML for the first time
# ---------------------------------------------------------------------

def test_agent_owner_renders_as_a_name_not_a_sys_id():
    """The first rendered report showed every agent's owner as
    `6816f79cc0a8016401c5a33be04be441`. The owner WAS resolved — an Owner
    record with a real name sat in the same inventory — and the table
    printed the foreign key.

    Ownership is the most consequential column here: a governance team's
    first question about an ungoverned agent is who is accountable for
    it. Answering with 32 hex characters is technically present and
    humanly useless, the same defect as NASK's "(unnamed)"."""
    import datetime

    from agentcensus.core.models import Agent, Owner, Provenance

    from agentcensus.core.models import OwnerStatus
    owner = Owner(id="u1", display_name="Brian McDonald",
                  status=OwnerStatus.ACTIVE, email="brian@example.com")
    inv = Inventory(
        platform="servicenow",
        scanned_at=datetime.datetime.now(datetime.timezone.utc),
        agents=[Agent(id="a1", name="ClaudeAgentService", description=None,
                      owner_id="u1", provenance=Provenance.SYNTHESIZED, raw={})],
        owners=[owner],
    )
    html = render_html(inv, [])
    assert "Brian McDonald" in html
    assert "6816f79cc0a8016401c5a33be04be441" not in html
    assert ">u1<" not in html


def test_an_unresolvable_owner_ref_says_so_rather_than_printing_the_id():
    """A bare sys_id reads like an answer. If the reference can't be
    resolved the report has to say that, not hand over the key and let
    the reader assume it means something."""
    import datetime

    from agentcensus.core.models import Agent, Provenance

    inv = Inventory(
        platform="servicenow",
        scanned_at=datetime.datetime.now(datetime.timezone.utc),
        agents=[Agent(id="a1", name="Orphan", description=None,
                      owner_id="deadbeefdeadbeefdeadbeefdeadbeef",
                      provenance=Provenance.SYNTHESIZED, raw={})],
        owners=[],
    )
    html = render_html(inv, [])
    assert "unresolved owner ref" in html
    assert "deadbeefdeadbeefdeadbeefdeadbeef" not in html


def test_the_access_section_says_how_to_grant_not_just_what():
    """A governance report's reader is often not a ServiceNow admin. A
    list of table names they cannot act on is a list they will forward
    and forget. The section carries the actual steps, including the two
    non-obvious ones: field ACLs are separate records from table ACLs,
    and editing ACLs needs elevated security_admin."""
    gap = AccessGap(table="sys_store_app", kind=AccessGapKind.TABLE_DENIED)
    html = _render_access_gaps([gap])
    assert "sys_security_acl" in html
    assert "security_admin" in html
    assert "Elevate role" in html
    # Must not tell them to just use admin — the whole product argues
    # against that, and an admin scan measures the wrong thing.
    assert "Do not use <code>admin</code>" in html


def test_coverage_is_summarised_above_the_findings_and_detailed_below():
    """The reordering, asserted at the level that matters: a one-line
    warning early, the twelve-row table late. Losing either recreates a
    failure — a silent partial scan, or a wall of caveats before any
    result."""
    import datetime

    from agentcensus.core.report import _coverage_banner

    banner = _coverage_banner([
        AccessGap(table="a", kind=AccessGapKind.TABLE_DENIED),
        AccessGap(table="b", kind=AccessGapKind.FIELD_ACL, fields=("x",)),
    ])
    assert "Partial coverage" in banner
    assert "Findings below are real" in banner
    # Short enough to actually be read.
    assert len(banner) < 500

    clean = _coverage_banner([])
    assert "Full coverage" in clean


def test_a_dropped_filter_is_shouted_in_the_banner_not_just_the_table():
    """The one gap kind that makes findings WRONG rather than missing.
    If it only appeared in a section below the results, a reader would
    act on findings that may be garbage before reaching the warning."""
    from agentcensus.core.report import _coverage_banner

    banner = _coverage_banner([
        AccessGap(table="sys_user", kind=AccessGapKind.FILTER_DROPPED, fields=("flag",)),
    ])
    assert "SILENTLY DROPPED" in banner
    assert "may be wrong" in banner


def test_findings_and_agents_carry_a_navigation_path():
    """"ClaudeAgentService is ungoverned" without saying where it lives
    does the hard half of the job and skips the easy one."""
    import datetime

    from agentcensus.core.models import Agent, Provenance

    inv = Inventory(
        platform="servicenow",
        scanned_at=datetime.datetime.now(datetime.timezone.utc),
        agents=[Agent(id="abc123", name="ClaudeAgentService", description=None,
                      owner_id=None, provenance=Provenance.SYNTHESIZED,
                      raw={"_kind": "script_include"})],
    )
    html = render_html(inv, [])
    assert "sys_script_include.do?sys_id=abc123" in html


def test_an_unknown_kind_gets_no_navigation_path_rather_than_a_guessed_one():
    """A wrong path is worse than none: it sends someone to an empty
    record and makes them distrust the rest."""
    from agentcensus.core.report import _where_to_find

    assert _where_to_find("abc", {"_kind": "something_new_in_2029"}) == ""
    assert _where_to_find("abc", {}) == ""
    assert _where_to_find(None, {"_kind": "script_include"}) == ""


def test_a_grouped_row_is_never_labelled_with_just_a_count():
    """Rendered live: two of five finding groups showed as "11×" and "7×"
    with no title at all. The group label is the shared title prefix —
    everything before the first quote — and a title that OPENS with a
    quoted subject name has an empty prefix.

    A count with no subject is worse than a slightly generic label: the
    reader cannot tell what eleven of anything refers to."""
    import datetime

    from agentcensus.core.models import (
        Confidence, Finding, FindingClass, Provenance, Severity,
    )
    from agentcensus.core.report import _group_title

    quoted_first = Finding(
        rule_id="ungoverned.shadow_agent",
        finding_class=FindingClass.UNGOVERNED,
        severity=Severity.MEDIUM,
        subject_type="agent",
        subject_id="a1",
        title="'OneExtendGlideUtil' is an agentic integration",
        explanation="e",
        recommended_action="a",
        confidence=Confidence.NEEDS_REVIEW,
    )
    assert _group_title(quoted_first) == "ungoverned.shadow_agent"

    prefixed = Finding(
        rule_id="ungoverned.inbound_surface",
        finding_class=FindingClass.UNGOVERNED,
        severity=Severity.MEDIUM,
        subject_type="tool",
        subject_id="t1",
        title="Scripted REST API resource at '/start' — keyword match",
        explanation="e",
        recommended_action="a",
        confidence=Confidence.NEEDS_REVIEW,
    )
    assert _group_title(prefixed) == "Scripted REST API resource at"


def test_the_mcp_tool_scan_tables_carry_their_impact():
    """Three rows read "Not separately documented" in the live report —
    including the tool-scan results table, which is the highest-value
    grant on the whole list. Added after the tables were, which is how
    they ended up unmapped."""
    from agentcensus.connectors.servicenow import tables as t

    for table in ("auth_server_connection",
                  "auth_server_connection_tool_scan_result",
                  "auth_server_connection_tool_scan_job"):
        assert t.impact_for(table), table
    assert "highest-value" in t.impact_for("auth_server_connection_tool_scan_result")
