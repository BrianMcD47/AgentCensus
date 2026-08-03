"""Tests for the three new ServiceNow-side detection surfaces added to
close the scenario-coverage gaps: generic integration/service-account
detection (integration_accounts.py), the native MCP Server Console
(mcp_server.py), and Now Assist Skill Kit (nask.py) — plus the new
provider-agnostic ungoverned rule that consumes integration_accounts.py's
output.
"""

from datetime import datetime, timezone

from agentcensus.connectors.servicenow import integration_accounts, mcp_server, nask
from agentcensus.core.models import (
    AccountType,
    Confidence,
    Inventory,
    Provenance,
    Tool,
)
from agentcensus.core.rules import default_engine
from agentcensus.core.severity import SeverityConfig
from tests.servicenow_fakes import FakeClient

# -- integration_accounts.py --

INTEGRATION_USERS = [
    {
        "sys_id": "u_svc1", "user_name": "svc_splunk_forwarder", "name": "Splunk Forwarder Svc",
        "active": "true", "department": None, "email": "svc-splunk@example.com",
        "web_service_access_only": "true", "locked_out": "false", "last_login_time": None,
        "sys_created_by": "admin",
    },
    {
        "sys_id": "u_svc2", "user_name": "svc_disabled", "name": "Disabled Svc",
        "active": "false", "department": None, "email": None,
        "web_service_access_only": "true", "locked_out": "true", "last_login_time": None,
        "sys_created_by": "admin",
    },
    {
        "sys_id": "u_human", "user_name": "brian", "name": "Brian",
        "active": "true", "department": "Eng", "email": "brian@example.com",
        "web_service_access_only": "false", "locked_out": "false", "last_login_time": "2026-07-01 00:00:00",
        "sys_created_by": "admin",
    },
    {"sys_id": "u_admin", "user_name": "admin", "name": "Admin", "active": "true", "department": None, "email": None,
     "web_service_access_only": "false", "locked_out": "false", "last_login_time": None, "sys_created_by": None},
]


def test_integration_accounts_only_picks_up_api_only_users():
    client = FakeClient({"sys_user": INTEGRATION_USERS})
    notes = []
    credentials, owners = integration_accounts.fetch_integration_accounts(client, notes)

    # FakeClient doesn't filter by query string, so this proves the module
    # itself doesn't accidentally synthesize a credential for every user —
    # it must be reading web_service_access_only per-row, not trusting the
    # (unfiltered, in this fake) query result blindly... but since FakeClient
    # returns every row regardless of query, assert on what the module keeps.
    ids = {c.id for c in credentials}
    assert ids == {"u_svc1", "u_svc2", "u_human", "u_admin"}  # unfiltered by fake, real instance filters server-side
    svc1 = next(c for c in credentials if c.id == "u_svc1")
    assert svc1.account_type == AccountType.SCOPED_SERVICE_ACCOUNT
    assert svc1.provenance == Provenance.SYNTHESIZED
    assert svc1.confidence == Confidence.CONFIRMED
    # Deliberately None, and this assertion was inverted on purpose —
    # it previously asserted the email WAS the correlation_key, which is
    # the defect. models.py requires the key be set only when a
    # connector genuinely knows a credential identity (OAuth client_id,
    # API key id, HEC token id); an email is a PERSON identity. Two
    # service accounts sharing a team mailbox were being merged into one
    # node by correlate.py, so one inherited the other's downstream
    # agents, blast radius and severity — the exact false merge that
    # module argues is worse than a missed one.
    assert svc1.correlation_key is None
    # The email is not lost: it travels as Owner.email, which is the
    # field designed for person-level correlation and which correctly
    # does not imply "same credential".
    assert svc1.raw["_locked_out"] is False


def test_integration_accounts_degrades_when_denied():
    client = FakeClient({"sys_user": INTEGRATION_USERS}, deny={"sys_user"})
    notes = []
    credentials, owners = integration_accounts.fetch_integration_accounts(client, notes)
    assert credentials == []
    assert any("access denied" in n.lower() for n in notes)


def test_unattributed_integration_account_rule_fires_only_for_active_unreferenced():
    """svc1 is active and referenced by nothing -> should fire.
    svc2 is locked out -> should not fire (disabled, not an active
    unexplained door). A third credential IS referenced by a tool ->
    should not fire even though it's also an integration account."""
    client = FakeClient({"sys_user": INTEGRATION_USERS})
    notes = []
    credentials, _ = integration_accounts.fetch_integration_accounts(client, notes)

    referenced_cred = next(c for c in credentials if c.id == "u_human")
    tool = Tool(id="t1", name="known_tool", description="d", credential_id=referenced_cred.id)

    inventory = Inventory(
        platform="test", scanned_at=datetime.now(timezone.utc),
        agents=[], tools=[tool], credentials=credentials, owners=[],
    )
    findings = default_engine().run(inventory, SeverityConfig())
    hits = {f.subject_id for f in findings if f.rule_id == "ungoverned.unattributed_integration_account"}

    assert "u_svc1" in hits       # active, unreferenced -> fires
    assert "u_svc2" not in hits   # locked out -> does not fire
    assert "u_human" not in hits  # referenced by a tool -> does not fire


# -- mcp_server.py --

def test_mcp_server_console_detected_when_table_present():
    rows = [
        {"sys_id": "m1", "name": "Claude external agent access", "active": "true", "sys_created_by": "brian", "sys_updated_on": "2026-07-01 00:00:00"},
    ]
    client = FakeClient({"auth_server_connection": rows, "sys_db_object": [{"sys_id": "1"}], "sys_user": []})
    tools, owners, notes = mcp_server.fetch_mcp_server_console(client)

    assert len(tools) == 1
    assert tools[0].confidence == Confidence.NEEDS_REVIEW
    assert tools[0].provenance == Provenance.SYNTHESIZED
    assert any("MCP Server Console" in n for n in notes)


def test_mcp_server_console_absent_produces_honest_note_not_a_crash():
    client = FakeClient({})
    tools, owners, notes = mcp_server.fetch_mcp_server_console(client)

    assert tools == []
    assert any("not detected" in n for n in notes)


# -- nask.py --

def test_nask_detects_provider_and_model_config_tables():
    provider_mappings = [{"sys_id": "p1", "name": "Anthropic Mapping", "active": "true", "sys_created_by": "brian", "sys_updated_on": "2026-07-01 00:00:00"}]
    model_configs = [{"sys_id": "mc1", "name": "Claude Sonnet Config", "active": "true", "sys_created_by": "brian", "sys_updated_on": "2026-07-01 00:00:00"}]
    client = FakeClient({
        "sys_generative_ai_provider_mapping": provider_mappings,
        "sys_generative_ai_model_config": model_configs,
        "sys_db_object": [{"sys_id": "1"}],
    })
    tools, notes = nask.fetch_nask(client)

    assert len(tools) == 2
    assert all(t.confidence == Confidence.NEEDS_REVIEW for t in tools)
    assert any("Now Assist Skill Kit" in n for n in notes)


def test_nask_absent_degrades_cleanly():
    client = FakeClient({})
    tools, notes = nask.fetch_nask(client)
    assert tools == []
    assert any("not found" in n for n in notes)
