from agentcensus.connectors.servicenow import flow_designer
from agentcensus.core.models import Confidence, Provenance
from tests.servicenow_fakes import FakeClient

STORE_APPS = [
    {"sys_id": "app1", "name": "Anthropic Claude Spoke", "scope": "x_anthropic_spoke", "short_description": "Call Claude from a flow", "version": "1.0.0"},
    {"sys_id": "app2", "name": "Unrelated Spoke", "scope": "x_unrelated", "short_description": "does nothing LLM-related", "version": "1.0.0"},
]

FLOWS = [
    {"sys_id": "f1", "name": "Auto-triage new incidents", "description": "Calls Claude to draft a triage note", "active": "true", "type": "flow", "sys_created_by": "brian"},
    {"sys_id": "f2", "name": "Weekly report email", "description": "Sends a scheduled email, nothing AI-related", "active": "true", "type": "flow", "sys_created_by": "brian"},
    {"sys_id": "f3", "name": "Generic sounding flow", "description": "no obvious signal here", "active": "true", "type": "flow", "sys_created_by": "brian"},
]

# Shaped like the real table: FIVE own columns, and neither `name` nor
# `active` among them. A step carries only a REFERENCE to its action type.
#
# These fixtures have now been wrong twice, in two different ways, and
# both times the suite passed while the tier was dead on real data:
#
#   1. they carried a `name` column the table does not have
#   2. they carried `action_type.name`, on the assumption the Table API
#      would dot-walk it — measured live, it does not; the response has
#      `action_type` (a bare sys_id) and no dotted key at all
#
# So the fixture now models what the API actually returns, and the name
# is resolved through ACTION_TYPES below, exactly as the code does it.
ACTIONS = [
    {"sys_id": "a1", "flow": "f1", "action_type": "at_rest", "order": "100", "sys_created_by": "brian"},
    {"sys_id": "a2", "flow": "f2", "action_type": "at_email", "order": "100", "sys_created_by": "brian"},
    # this action references flow f3, which has no name/description hit —
    # the agent should still be created, correlated via the action alone
    {"sys_id": "a3", "flow": "f3", "action_type": "at_openai", "order": "100", "sys_created_by": "brian"},
]

ACTION_TYPES = [
    {"sys_id": "at_rest", "name": "Call Anthropic API"},
    {"sys_id": "at_email", "name": "Send Email"},
    {"sys_id": "at_openai", "name": "Invoke OpenAI completion"},
]

USERS = [{"sys_id": "u_brian", "user_name": "brian", "name": "Brian", "active": "true", "department": None}]

TABLES = {
    "sys_store_app": STORE_APPS,
    "sys_hub_flow": FLOWS,
    "sys_hub_action_instance": ACTIONS,
    "sys_hub_action_type_base": ACTION_TYPES,
    "sys_user": USERS,
}


def test_installed_spoke_matches_only_the_relevant_app():
    client = FakeClient(TABLES)
    from agentcensus.connectors.servicenow.llm_providers import load_providers

    notes = []
    tools = flow_designer._installed_llm_spokes(client, load_providers(), notes)

    assert [t.name for t in tools] == ["Anthropic Claude Spoke"]
    assert tools[0].confidence == Confidence.NEEDS_REVIEW


def test_flow_agent_connected_to_its_action_step_tool():
    """Same class of bug as shadow.py's tier 4: an agent with no
    tool_ids is a disconnected graph node. This proves flow_designer.py
    doesn't repeat it."""
    client = FakeClient(TABLES)
    agents, tools, owners, notes = flow_designer.fetch_flow_designer(client)

    triage_flow = next(a for a in agents if a.id == "f1")
    assert triage_flow.provenance == Provenance.SYNTHESIZED
    assert triage_flow.confidence == Confidence.NEEDS_REVIEW
    assert len(triage_flow.tool_ids) == 1
    matching_tool = next(t for t in tools if t.id in triage_flow.tool_ids)
    assert matching_tool.name == "Call Anthropic API"

    # owner_id must actually resolve to a real Owner in the returned list
    assert triage_flow.owner_id is not None
    assert any(o.id == triage_flow.owner_id for o in owners)


def test_flow_with_no_name_hit_still_found_via_action_step():
    client = FakeClient(TABLES)
    agents, tools, owners, notes = flow_designer.fetch_flow_designer(client)

    generic_flow = next((a for a in agents if a.id == "f3"), None)
    assert generic_flow is not None, "flow f3 should be found via its OpenAI-calling action step"
    assert generic_flow.detection_signal == "flow_designer:action_step_match"
    assert len(generic_flow.tool_ids) == 1


def test_unrelated_flow_not_flagged():
    client = FakeClient(TABLES)
    agents, tools, owners, notes = flow_designer.fetch_flow_designer(client)

    assert not any(a.id == "f2" for a in agents)


def test_degrades_gracefully_when_flow_table_read_is_denied():
    """native.py and shadow.py both have a test proving a denied table
    degrades to a scan note instead of a crash (safe_get_all's
    fault-isolation contract — see README's 'Fault-isolated' guarantee
    and servicenow_fakes.FakeClient's docstring). flow_designer.py relies
    on the exact same safe_get_all calls but had no equivalent test —
    this closes that gap for the no-code detection path specifically."""
    client = FakeClient(TABLES, deny={"sys_hub_flow"})
    agents, tools, owners, notes = flow_designer.fetch_flow_designer(client)

    assert agents == []
    assert any("access denied" in n.lower() and "sys_hub_flow" in n for n in notes)


def test_degrades_gracefully_when_action_instance_table_read_is_denied():
    """Action-step correlation (flow_designer's version of shadow.py's
    tier-4 REST-message correlation) reads a second table independently
    — a denial there should degrade to flow-level name/description
    matches only, not take down the whole detection path.

    Note: none of the module-level FLOWS fixtures match at the flow
    level on their own — 'Claude' alone isn't a configured keyword
    (llm_providers.yaml uses 'claude-', with the hyphen, specifically
    to avoid matching plain English usage of the word), so f1 in the
    shared fixture is only found via its action step. This test uses
    its own flow with a real flow-level keyword hit ('anthropic', bare)
    so it's independent of action-instance correlation entirely."""
    flow_level_flow = {
        "sys_id": "f_flow_level", "name": "Anthropic summarizer flow",
        "description": "Uses anthropic for summarization", "active": "true",
        "type": "flow", "sys_created_by": "brian",
    }
    tables = {**TABLES, "sys_hub_flow": [*FLOWS, flow_level_flow]}
    client = FakeClient(tables, deny={"sys_hub_action_instance"})
    agents, tools, owners, notes = flow_designer.fetch_flow_designer(client)

    # found via its own name/description match, independent of actions
    flow_level_agent = next((a for a in agents if a.id == "f_flow_level"), None)
    assert flow_level_agent is not None
    assert flow_level_agent.detection_signal == "flow_designer:name_match"
    assert flow_level_agent.tool_ids == []  # no action correlation possible, but not crashed

    # f1/f3, which only had an action-step signal, are correctly absent
    # now that the action-instance table can't be read
    assert not any(a.id == "f1" for a in agents)
    assert not any(a.id == "f3" for a in agents)
    assert any(
        "access denied" in n.lower() and "sys_hub_action_instance" in n for n in notes
    )
