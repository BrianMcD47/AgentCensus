from agentcensus.connectors.servicenow import native
from agentcensus.core.models import Provenance
from tests.servicenow_fakes import FakeClient

AIA_AGENTS = [
    {"sys_id": "a1", "name": "Ticket Triage", "description": "triages tickets", "run_as": "svc_ai_agent", "role": "", "active": "true", "sys_created_by": "alice", "sys_updated_by": "alice", "sys_updated_on": "2026-07-01 00:00:00", "sys_domain": "global"},
]
AIA_LINKS = [
    {"sys_id": "l1", "agent": "a1", "tool": "t1", "run_as": "svc_ai_agent", "execution_mode": "auto", "max_auto_executions": "5"},
]
USERS = [{"sys_id": "u_alice", "user_name": "alice", "name": "Alice", "active": "true", "department": None}]


def test_prefers_aia_schema_when_present():
    client = FakeClient(
        {"sys_db_object": [{"sys_id": "1"}], "sn_aia_agent": AIA_AGENTS, "sn_aia_agent_tool_m2m": AIA_LINKS, "sys_user": USERS,
         "sn_build_agent_conversation": [{"sys_id": "should_not_be_read"}]},
    )
    # both schemas "exist" per table contents, but AIA must win — it's
    # checked first and is the more authoritative schema when present
    agents, tools, creds, owners, notes = native.detect_and_fetch(client)

    assert len(agents) == 1
    assert agents[0].name == "Ticket Triage"
    assert agents[0].provenance == Provenance.NATIVE
    assert agents[0].detection_signal == "native:sn_aia_agent"
    assert any("AI Agent Studio" in n for n in notes)

    # The tool's run_as credential should get the agent's own resolved
    # owner as a best-effort proxy — was unconditionally None before the
    # second fresh-eyes audit pass caught it (same bug shape shadow.py's
    # tier 1/2 credentials had before the first pass fixed those).
    assert len(creds) == 1
    assert creds[0].id == "svc_ai_agent"
    assert creds[0].owner_id == "u_alice"


def test_falls_back_to_build_agent_schema():
    conversations = [
        {"sys_id": "c1", "title": "chat 1", "user": "u1", "application_id": "app_1", "application_name": "Support Bot", "state": "closed", "active": "true", "sys_created_by": "alice", "sys_created_on": "2026-07-01 00:00:00", "last_message_at": "2026-07-30 00:00:00"},
    ]
    client = FakeClient({"sn_build_agent_conversation": conversations, "sys_user": USERS})

    agents, tools, creds, owners, notes = native.detect_and_fetch(client)

    assert len(agents) == 1
    assert agents[0].name == "Support Bot"
    assert any("Build Agent" in n for n in notes)


def test_reports_no_native_schema_cleanly_instead_of_erroring():
    client = FakeClient({})
    agents, tools, creds, owners, notes = native.detect_and_fetch(client)

    assert agents == tools == creds == owners == []
    assert any("No native AI agent schema found" in n for n in notes)


def test_degrades_gracefully_when_aia_table_read_is_denied():
    client = FakeClient(
        {"sys_db_object": [{"sys_id": "1"}], "sn_aia_agent": AIA_AGENTS},
        deny={"sn_aia_agent"},
    )
    agents, tools, creds, owners, notes = native.detect_and_fetch(client)

    assert agents == []
    assert any("access denied" in n.lower() for n in notes)


def test_dict_shaped_reference_fields_are_unwrapped_not_stored_raw():
    """Confirmed live against a real ServiceNow instance: without
    sysparm_exclude_reference_link=true (which http.py now sends —
    this test proves the connector-side defense holds even if that
    ever regresses), reference fields come back as
    {"link": "...", "value": "..."} dicts, not plain strings.
    sys_user.department was directly observed in this exact shape;
    run_as on sn_aia_agent/its tool-link table couldn't be confirmed
    the same way (the table doesn't exist on a non-licensed instance)
    but is handled the same defensive way since a wrong guess here
    means a crash (dict.lower() / using a dict as a dict key), not
    just a wrong value."""
    agents_dict_run_as = [
        {**AIA_AGENTS[0], "run_as": {"link": "https://x.service-now.com/api/now/table/sys_user/svc_dict", "value": "svc_dict"}},
    ]
    links_dict_run_as = [
        {**AIA_LINKS[0], "run_as": {"link": "https://x.service-now.com/api/now/table/sys_user/svc_dict", "value": "svc_dict"}},
    ]
    users_dict_department = [
        {**USERS[0], "department": {"link": "https://x.service-now.com/api/now/table/cmn_department/d1", "value": "d1"}},
    ]
    client = FakeClient(
        {
            "sys_db_object": [{"sys_id": "1"}],
            "sn_aia_agent": agents_dict_run_as,
            "sn_aia_agent_tool_m2m": links_dict_run_as,
            "sys_user": users_dict_department,
        },
    )

    agents, tools, creds, owners, notes = native.detect_and_fetch(client)  # must not raise

    assert creds[0].id == "svc_dict"  # unwrapped to the bare sys_id, not the dict
    assert agents[0].account_type.value in ("scoped_service_account", "shared_human_account")

    assert owners[0].department == "d1"  # unwrapped, not the {"link","value"} dict
