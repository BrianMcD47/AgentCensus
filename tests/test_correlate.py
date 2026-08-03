from datetime import datetime, timezone

from agentcensus.core.correlate import merge_and_correlate, merge_inventories
from agentcensus.core.models import (
    AccountType,
    Agent,
    Credential,
    Inventory,
    Owner,
    OwnerStatus,
    Tool,
)


def _inv(platform: str, agent_id: str, cred_correlation_key: str | None, owner_email: str | None) -> Inventory:
    owner = Owner(id="o1", display_name="Person", status=OwnerStatus.ACTIVE, email=owner_email)
    cred = Credential(
        id="c1", name="cred", account_type=AccountType.UNKNOWN, owner_id="o1",
        correlation_key=cred_correlation_key,
    )
    tool = Tool(id="t1", name="tool", description="d", credential_id="c1")
    agent = Agent(id=agent_id, name=agent_id, description="d", owner_id="o1", tool_ids=["t1"])
    return Inventory(
        platform=platform, scanned_at=datetime.now(timezone.utc),
        agents=[agent], tools=[tool], credentials=[cred], owners=[owner],
    )


def test_merge_namespaces_ids_and_prevents_collision():
    inv_a = _inv("platform-a", "agent1", cred_correlation_key=None, owner_email=None)
    inv_b = _inv("platform-b", "agent1", cred_correlation_key=None, owner_email=None)  # same literal id

    merged = merge_inventories([inv_a, inv_b])
    agent_ids = {a.id for a in merged.agents}
    assert agent_ids == {"platform-a::agent1", "platform-b::agent1"}
    cred_ids = {c.id for c in merged.credentials}
    assert cred_ids == {"platform-a::c1", "platform-b::c1"}
    # foreign keys rewritten to match
    for agent in merged.agents:
        assert agent.tool_ids[0].startswith(agent.id.split("::")[0] + "::")
    for cred in merged.credentials:
        assert cred.owner_id.startswith(cred.id.split("::")[0] + "::")


def test_merge_without_shared_signal_does_not_add_identity_edges():
    inv_a = _inv("platform-a", "agent1", cred_correlation_key=None, owner_email=None)
    inv_b = _inv("platform-b", "agent2", cred_correlation_key=None, owner_email=None)

    _, g = merge_and_correlate([inv_a, inv_b])
    identity_edges = [d for _, _, d in g.edges(data=True) if d.get("relation") == "same_identity_as"]
    assert identity_edges == []  # no shared signal -> correctly stays two separate identities


def test_merge_with_shared_correlation_key_adds_symmetric_identity_edges():
    inv_a = _inv("platform-a", "agent1", cred_correlation_key="shared-key", owner_email=None)
    inv_b = _inv("platform-b", "agent2", cred_correlation_key="shared-key", owner_email=None)

    merged, g = merge_and_correlate([inv_a, inv_b])
    a_node, b_node = "credential:platform-a::c1", "credential:platform-b::c1"
    assert g.has_edge(a_node, b_node)
    assert g.has_edge(b_node, a_node)  # symmetric, so blast-radius traversal works both ways

    from agentcensus.core.graph import downstream_agents

    downstream = downstream_agents(g, a_node)
    assert downstream == {"agent:platform-a::agent1", "agent:platform-b::agent2"}


def test_merge_with_shared_owner_email_adds_identity_edges_too():
    inv_a = _inv("platform-a", "agent1", cred_correlation_key=None, owner_email="same@example.com")
    inv_b = _inv("platform-b", "agent2", cred_correlation_key=None, owner_email="Same@Example.com")  # case-insensitive

    _, g = merge_and_correlate([inv_a, inv_b])
    a_node, b_node = "owner:platform-a::o1", "owner:platform-b::o1"
    assert g.has_edge(a_node, b_node)
    assert g.has_edge(b_node, a_node)
