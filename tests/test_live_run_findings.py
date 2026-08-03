"""Regression tests for defects found by the FIRST REAL SCAN.

Four rounds of independent review preceded this, all of them reading
code. Then the tool was pointed at a live ServiceNow instance and found
seven more defects in one afternoon — none of which any reviewer could
have found, because every one is a fact about the world rather than a
fact about the code:

  - the test suite read the developer's own shell environment
  - eight ordinary property types were being refused as "unrecognised"
  - the two most common real outcomes (unlicensed feature, uninstalled
    app) were classified as ERROR
  - the read manifest had drifted again, missing `domain`
  - preflight proved tables exist and never checked the FIELDS that
    detection actually depends on
  - the safety cap was being spent on records the vendor filter then
    discarded
  - ten ServiceNow-shipped accounts dominated the report at HIGH

The generalizable lesson, recorded because it will apply to the next
platform too: a review can only check a program against its author's
model of reality. Only contact with the real thing checks the model.
"""

from __future__ import annotations

import datetime
import os
import subprocess
import sys
from unittest.mock import MagicMock, patch

from agentcensus.connectors.servicenow import tables
from agentcensus.connectors.servicenow.http import ServiceNowClient
from agentcensus.connectors.servicenow.integration_accounts import (
    fetch_integration_accounts,
    is_platform_shipped,
)
from agentcensus.core.models import Inventory, Severity
from agentcensus.core.scan import run_scan
from tests.servicenow_fakes import FakeClient


def _resp(status=200, rows=None):
    r = MagicMock()
    r.status_code = status
    r.headers = {}
    r.json.return_value = {"result": rows if rows is not None else []}
    if status >= 400:
        import requests

        r.raise_for_status.side_effect = requests.HTTPError(response=r)
    else:
        r.raise_for_status.side_effect = None
    return r


# ---------------------------------------------------------------------
# 1 — the suite read the developer's real credentials
# ---------------------------------------------------------------------

def test_suite_is_hermetic_against_a_configured_environment():
    """Nine tests failed on a second machine and passed on the first,
    because `ServiceNowClient()` falls back to `AGENTCENSUS_SN_*` env
    vars. On a machine configured to actually USE the tool, the client
    took the OAuth path with real credentials and tried to exchange a
    token against a live instance the tests had only mocked GET for.

    Worse than a flaky suite: a test run that reaches a customer's
    production ServiceNow because of ambient shell state. `conftest.py`
    clears the whole namespace; this proves it, from a subprocess,
    because the fixture would otherwise hide the very thing under test.
    """
    import pathlib

    root = str(pathlib.Path(__file__).resolve().parents[1])
    env = {
        "PATH": "/usr/bin:/bin",
        "AGENTCENSUS_SN_INSTANCE": "https://should-not-be-used.example.com",
        "AGENTCENSUS_SN_CLIENT_ID": "leaked",
        "AGENTCENSUS_SN_CLIENT_SECRET": "leaked",
    }
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "tests/test_servicenow_http.py"],
        cwd=root, env=env, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, (
        "the HTTP tests read ambient AGENTCENSUS_* environment variables:\n"
        + result.stdout[-2000:]
    )


def test_conftest_clears_the_whole_namespace_not_just_known_vars():
    """The three that broke were `SN_INSTANCE/CLIENT_ID/CLIENT_SECRET`.
    Clearing only those would leave the next connector's variables to
    rediscover this the same way."""
    assert not [k for k in os.environ if k.startswith("AGENTCENSUS_")]


# ---------------------------------------------------------------------
# 2 — eight ordinary property types were refused
# ---------------------------------------------------------------------

def test_property_types_seen_on_a_real_instance_are_readable():
    """Every type below was reported by the live COVERAGE GAP note as
    refused. `short_string` is the one that matters: a standard type
    that routinely holds a URL, which is exactly what this tier exists
    to find. Refusing it is silent under-detection dressed as caution."""
    from agentcensus.connectors.servicenow.config_surfaces import _is_secret_property

    for observed in [
        "color", "date_format", "image", "short_string",
        "time_format", "timezone", "true", "uploaded_image",
    ]:
        assert not _is_secret_property({"type": observed}), observed


def test_genuinely_encrypted_types_are_still_refused_and_unknowns_fail_closed():
    """Control. Widening the allowlist must not open the guard."""
    from agentcensus.connectors.servicenow.config_surfaces import _is_secret_property

    for secret in ["password", "password2", "password (2 way encrypted)", "glide_encrypted"]:
        assert _is_secret_property({"type": secret}), secret
    assert _is_secret_property({"type": "some_type_invented_in_2029"})


# ---------------------------------------------------------------------
# 3 — an unlicensed feature reported as ERROR
# ---------------------------------------------------------------------

def test_an_unknown_table_is_absent_not_an_error():
    """ServiceNow answers an unknown table with 400 + "Invalid table",
    which contains neither "not found" nor "denied", so substring
    classification called it ERROR. On the live run that made
    `sn_aia_agent` (no Now Assist licence) and `sn_mcp_server_registry`
    (app not installed) — the two most common real outcomes — read as
    *something is broken*, and counted them as failures in the summary.
    """
    client = ServiceNowClient(instance_url="https://x.service-now.com", username="u", password="p")
    bad = _resp(400)
    bad.raise_for_status.side_effect.args = ("400 Invalid table sn_aia_agent",)
    with patch("requests.get", return_value=bad):
        status, detail = client.probe("sn_aia_agent", ["sys_id"])
    assert status == "absent", f"got {status}: {detail}"


def test_denied_and_readable_are_still_distinguished():
    client = ServiceNowClient(instance_url="https://x.service-now.com", username="u", password="p")
    with patch("requests.get", return_value=_resp(403)):
        assert client.probe("sys_script", ["sys_id"])[0] == "denied"
    with patch("requests.get", return_value=_resp(200, [{"sys_id": "1"}])):
        assert client.probe("sys_user", ["sys_id"])[0] == "ok"


# ---------------------------------------------------------------------
# 4 — preflight verified tables, never fields
# ---------------------------------------------------------------------

def test_probe_reports_fields_that_did_not_come_back():
    """An `OK` used to mean "the table exists" and nothing more, because
    the probe asked for `sys_id` alone. Detection depends on FIELDS —
    `connection_url`, `sp_widget.script`, `sys_properties.type` — each
    read with `.get()`, so a wrong name yields None and the surface
    silently finds nothing. Preflight, the feature whose whole job is
    telling a security team what will happen, could not see that."""
    client = ServiceNowClient(instance_url="https://x.service-now.com", username="u", password="p")
    with patch("requests.get", return_value=_resp(200, [{"sys_id": "1", "name": "x"}])):
        status, detail = client.probe("http_connection", ["sys_id", "name", "connection_url"])
    assert status == "ok"
    assert "connection_url" in (detail or ""), detail


def test_every_manifest_entry_carries_the_field_list_it_reads():
    for table, fields, purpose in (
        tables.DEFAULT_READ_MANIFEST + tables.SCRIPT_READ_MANIFEST
    ):
        assert isinstance(fields, list) and fields, f"{table} has no field list"
        assert purpose


def test_the_manifest_covers_every_table_the_scan_reads():
    """`domain` was missing while `domain_scope.py` read it on every
    scan — the same manifest drift the manifest was introduced to stop,
    reintroduced one round later. Preflight promising a security team a
    complete picture must not omit a table."""
    probed = {t for t, _f, _p in tables.DEFAULT_READ_MANIFEST + tables.SCRIPT_READ_MANIFEST}
    for required in (tables.DOMAIN_TABLE, tables.APP_SCOPE_TABLE, "sys_db_object"):
        assert required in probed, required


# ---------------------------------------------------------------------
# 5 — the safety cap was spent on records the filter then discarded
# ---------------------------------------------------------------------

def test_vendor_scope_is_excluded_server_side_so_the_cap_buys_customer_code():
    """Measured live: `sys_script` hit the 5,000-row cap while 3,046
    records were separately excluded as vendor scope. The cap applies
    when FETCHING and the filter ran AFTER, so most of the budget went
    on ServiceNow's own code and was then thrown away. On a large
    instance the cap could be exhausted entirely inside vendor scope,
    returning ZERO customer findings behind a truncation note."""
    from agentcensus.connectors.servicenow.shadow import _tier4_script_agents

    seen: dict[str, str] = {}

    def _capture(table, fields, query="", filter_fields=None):
        seen[table] = query
        return [], None

    client = FakeClient({})
    client.safe_get_all = _capture
    _tier4_script_agents(client, [], {}, [])

    # sys_scope itself is read unfiltered — it IS the scope lookup, and
    # filtering it by scope would be circular.
    script_reads = {t: q for t, q in seen.items() if t != tables.APP_SCOPE_TABLE}
    assert script_reads, "no script tables were read"
    assert all("sys_scope.scope" in q for q in script_reads.values()), script_reads


def test_a_rejected_server_side_filter_falls_back_rather_than_losing_the_table():
    """Dot-walking in an encoded query is standard ServiceNow but is not
    verified against every release. A rejection must cost the filter,
    never the table."""
    from agentcensus.connectors.servicenow.shadow import _tier4_script_agents

    calls: list[str] = []

    def _flaky(table, fields, query="", filter_fields=None):
        calls.append(query)
        if query:
            return [], "Failed to read: bad query"
        return [{"sys_id": "s1", "name": "Bot", "script": "// anthropic",
                 "active": "true", "sys_created_by": "admin"}], None

    client = FakeClient({})
    client.safe_get_all = _flaky
    notes: list[str] = []
    agents, _tools = _tier4_script_agents(client, __import__(
        "agentcensus.connectors.servicenow.llm_providers", fromlist=["load_providers"]
    ).load_providers(), {}, notes)

    assert any("Bot" == a.name for a in agents), "fallback lost the table entirely"
    assert any("retrying unfiltered" in n for n in notes)


# ---------------------------------------------------------------------
# 6 — ten ServiceNow-shipped accounts dominated the report at HIGH
# ---------------------------------------------------------------------

def test_platform_shipped_accounts_rank_below_customer_accounts():
    """A stock PDI produced ten HIGH findings for accounts ServiceNow
    ships on every instance — `soap.guest`, `virtual.agent`,
    `securitycenter.user`, `mic.administrator`. Literally true, entirely
    useless: the customer neither created them nor can remove them, and
    they are a FIXED cost that dominates a small estate's report.

    Lowered, never suppressed — a shipped account can still be abused or
    repurposed, and dropping it silently is the over-correction failure
    this project keeps hitting."""
    rows = [
        {"sys_id": f"u{i}", "user_name": n, "name": n,
         "active": "true", "web_service_access_only": "true"}
        for i, n in enumerate(
            ["soap.guest", "virtual.agent", "acme-custom-bot", "team-llm-runner"]
        )
    ]
    creds, owners = fetch_integration_accounts(FakeClient({"sys_user": rows}), [])
    inv = Inventory("servicenow", datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc),
                    credentials=creds, owners=owners)
    findings, _ = run_scan(inv)

    by_subject = {
        f.subject_id: f for f in findings
        if f.rule_id.endswith("unattributed_integration_account")
    }
    order = [Severity.INFORMATIONAL, Severity.LOW, Severity.MEDIUM,
             Severity.HIGH, Severity.CRITICAL]
    shipped = order.index(by_subject["u0"].severity)
    custom = order.index(by_subject["u2"].severity)
    assert shipped < custom, "a shipped account outranked a customer-built one"

    # Still reported, and the reason is in the evidence.
    assert "u0" in by_subject
    assert by_subject["u0"].evidence["platform_shipped"] is True
    assert "ships this account" in by_subject["u0"].evidence["severity_basis"]


def test_platform_shipped_matching_is_conservative():
    """A false positive here LOWERS severity, so the list is exact-match
    and short rather than pattern-based."""
    assert is_platform_shipped("soap.guest")
    assert is_platform_shipped("SOAP.GUEST")
    assert not is_platform_shipped("soap.guest.custom")
    assert not is_platform_shipped("acme-service-account")


# ---------------------------------------------------------------------
# 7 — authorship as annotation, never exclusion
# ---------------------------------------------------------------------

def test_unpackaged_records_are_annotated_not_privileged_or_dropped():
    """Confirmed live: three ServiceNow-shipped Script Includes in
    `global` SCOPE all carried the same real `sys_package` sys_id, while
    a hand-built custom agent in that same scope carried the literal
    "global". `sys_scope` and `sys_created_by` were identical across all
    four, so both are useless discriminators.

    Recorded as evidence and used to rank — NOT to exclude. The inverse
    doesn't hold (a customer's own scoped app carries a real package
    too), and every over-correction defect in this project came from
    dropping records on a signal like this one."""
    from agentcensus.connectors.servicenow.shadow import fetch_shadow

    client = FakeClient({
        "sys_script_include": [
            {"sys_id": "vendor1", "name": "OneExtendGlideUtil", "script": "// openai",
             "active": "true", "sys_created_by": "admin",
             "sys_scope": "global", "sys_package": "04e0f2b38c5103100a22deb6dd2b4e26"},
            {"sys_id": "cust1", "name": "ClaudeAgentService", "script": "// anthropic",
             "active": "true", "sys_created_by": "admin",
             "sys_scope": "global", "sys_package": "global"},
        ]
    })
    agents, *_ = fetch_shadow(client, include_script_scan=True)
    by_name = {a.name: a for a in agents}

    # BOTH still reported — this is annotation, not a filter.
    assert set(by_name) == {"OneExtendGlideUtil", "ClaudeAgentService"}
    assert by_name["ClaudeAgentService"].raw["_authored_directly"] is True
    assert by_name["OneExtendGlideUtil"].raw["_authored_directly"] is False


# ---------------------------------------------------------------------
# 8 — the deepest one: a field-level ACL made tier 2 silently blind
# ---------------------------------------------------------------------

def test_a_field_the_instance_refuses_to_return_is_reported_not_swallowed():
    """THE most serious defect this project found, and only a live run
    could have found it.

    ServiceNow omits a field entirely when a field-level ACL denies read
    on it — the row arrives with every other field intact and no error
    anywhere. Combined with this connector's defensive `.get()` reads,
    that produces perfect silence.

    Confirmed live: the scan credential could FILTER on
    `sys_rest_message.endpoint` (a server-side `endpointISNOTEMPTY`
    query returned three rows, so the data exists and is queryable) but
    could not READ it — responses carried only `name`. Tier 2, the
    CONFIRMED-grade tier the entire confidence model rests on, had
    therefore never been able to fire on that instance, and every scan
    reported "0 outbound REST message(s) matched a known LLM provider
    host" — which reads exactly like "there aren't any".

    The defensive reads were built to tolerate missing fields
    *gracefully*. Live data showed "gracefully" meant "report nothing
    found, indistinguishably from nothing being there."
    """
    client = ServiceNowClient(instance_url="https://x.service-now.com", username="u", password="p")
    # Exactly the observed shape: `name` present, `endpoint` absent.
    acl_filtered = [{"name": "Yahoo Finance"}, {"name": "Firebase Send"}]
    with patch("requests.get", side_effect=[_resp(200, acl_filtered), _resp(200, [])]):
        rows, note = client.safe_get_all(
            "sys_rest_message", ["sys_id", "name", tables.REST_ENDPOINT_FIELD]
        )

    assert rows, "the readable part of each row must still be returned"
    assert note and "FIELD-LEVEL ACL" in note, note
    assert "rest_endpoint" in note
    assert "BLIND" in note, "the note must say detection is blind, not merely note a gap"


def test_a_merely_empty_field_is_not_mistaken_for_an_acl_block():
    """Control, and the reason this checks every row rather than the
    first: a field that is EMPTY on one record is still present as a
    key. Sampling one row would raise a false alarm on sparse data — and
    a false alarm here tells a customer to go change ACLs for no
    reason."""
    client = ServiceNowClient(instance_url="https://x.service-now.com", username="u", password="p")
    sparse = [{"sys_id": "1", "name": "A", "rest_endpoint": ""},
              {"sys_id": "2", "name": "B", "rest_endpoint": "https://api.anthropic.com/v1"}]
    with patch("requests.get", side_effect=[_resp(200, sparse), _resp(200, [])]):
        _rows, note = client.safe_get_all("sys_rest_message", ["sys_id", "name", tables.REST_ENDPOINT_FIELD])
    assert note is None, note


def test_an_empty_table_raises_no_field_alarm():
    """Nothing came back, so nothing can be concluded about fields."""
    assert ServiceNowClient.unreadable_fields([], ["sys_id", tables.REST_ENDPOINT_FIELD]) == []


# ---------------------------------------------------------------------
# 9 — a warning note must not discard the rows that DID arrive
# ---------------------------------------------------------------------

def test_a_truncation_note_does_not_throw_away_the_rows_it_describes():
    """Found while fixing #8, and older than it. `safe_get_all` returns
    (rows, note) where the note can describe a PARTIAL read — safety-cap
    truncation, or a field-level ACL — with perfectly usable rows
    alongside. Every one of twelve call sites treated any note as fatal
    and returned empty.

    Measured live: `sys_script` hit the 5,000-row cap, so all 5,000
    Business Rules were fetched, paid for in API quota and three minutes
    of wall time, and then discarded. "Incomplete" silently became
    "nothing found" — the exact failure this project keeps rediscovering,
    this time in the error handling built to prevent it.
    """
    from agentcensus.connectors.servicenow.llm_providers import load_providers
    from agentcensus.connectors.servicenow.shadow import _tier4_script_agents

    rows = [{"sys_id": "s1", "name": "LLMBot", "script": "// anthropic",
             "active": "true", "sys_created_by": "admin"}]

    client = FakeClient({})
    client.safe_get_all = lambda table, fields, query="", filter_fields=None: (
        (rows, "'sys_script' has at least 5000 matching records — stopped at the safety cap.")
        if table == tables.BUSINESS_RULE_TABLE
        else ([], None)
    )
    notes: list[str] = []
    agents, _tools = _tier4_script_agents(client, load_providers(), {}, notes)

    assert any(a.name == "LLMBot" for a in agents), (
        "a truncation note discarded the rows it was describing"
    )
    assert any("safety cap" in n for n in notes), "the caveat must still travel with them"


def test_a_blind_tier_says_so_instead_of_reporting_zero_matches():
    """"0 matched" and "I could not look" are different claims, and only
    one of them is evidence. Reporting the first when the second is true
    is the single most misleading thing this tool can do — it is a clean
    bill of health for a check that never ran."""
    from agentcensus.connectors.servicenow.shadow import fetch_shadow

    client = FakeClient({"sys_rest_message": [{"sys_id": "r1", "name": "LLM"}]})
    real = client.safe_get_all

    def acl_blind(table, fields, query="", filter_fields=None):
        rows, note = real(table, fields, query, filter_fields)
        if table == tables.REST_MESSAGE_TABLE:
            return rows, (
                "FIELD-LEVEL ACL on 'sys_rest_message': requested field(s) "
                + tables.REST_ENDPOINT_FIELD
                + " were not returned by the instance"
            )
        return rows, note

    client.safe_get_all = acl_blind
    *_rest, notes = fetch_shadow(client)
    summary = [n for n in notes if n.startswith("Shadow detection:")]

    assert summary, "no summary note produced"
    assert "COULD NOT RUN" in summary[0], summary[0]
    assert "not evidence of absence" in summary[0]
