"""Dependency graph.

Per the project plan, this is the differentiating capability: everyone
else produces a list, this produces a graph. Nodes are agents, tools,
credentials, and owners. Edges are "uses", "runs_as", and "owned_by".

The payoff is blast-radius queries: given one orphaned credential,
which agents break or become a risk if it's revoked? Given one
deprecated tool, which agents call it? That's what makes a finding
actionable instead of informational, and it's what `severity.
escalate_for_blast_radius` reads from.
"""

from __future__ import annotations

import networkx as nx

from agentcensus.core.models import Inventory


def build_graph(inventory: Inventory) -> nx.DiGraph:
    g = nx.DiGraph()

    for owner in inventory.owners:
        g.add_node(f"owner:{owner.id}", kind="owner", label=owner.display_name, data=owner)

    for cred in inventory.credentials:
        g.add_node(f"credential:{cred.id}", kind="credential", label=cred.name, data=cred)
        if cred.owner_id:
            g.add_edge(f"credential:{cred.id}", f"owner:{cred.owner_id}", relation="owned_by")

    for tool in inventory.tools:
        g.add_node(f"tool:{tool.id}", kind="tool", label=tool.name, data=tool)
        if tool.credential_id:
            g.add_edge(f"tool:{tool.id}", f"credential:{tool.credential_id}", relation="runs_as")

    for agent in inventory.agents:
        g.add_node(f"agent:{agent.id}", kind="agent", label=agent.name, data=agent)
        if agent.owner_id:
            g.add_edge(f"agent:{agent.id}", f"owner:{agent.owner_id}", relation="owned_by")
        for tool_id in agent.tool_ids:
            g.add_edge(f"agent:{agent.id}", f"tool:{tool_id}", relation="uses")

    return g


def downstream_agents(g: nx.DiGraph, node_id: str) -> set[str]:
    """Every agent that depends, directly or transitively, on `node_id`
    (a credential or tool node). Used to size blast radius for severity
    escalation and for the "what breaks if I remove this" report section.
    """
    if node_id not in g:
        return set()
    # edges point from dependent -> dependency, so we want ancestors
    ancestors = nx.ancestors(g, node_id)
    return {n for n in ancestors if n.startswith("agent:")}


def to_dict(g: nx.DiGraph) -> dict:
    """JSON-safe view of the graph for the report — node id/kind/label
    and edges only, deliberately dropping each node's `data` attribute
    (the full Owner/Agent/Tool/Credential object). That object is
    already serialized under the report's `inventory` section; repeating
    it here would just be redundant weight in every report file, and
    dataclasses nested inside a networkx node-attr dict aren't something
    `report._default` reaches on its own since `json.dumps` walks plain
    dicts/lists, not arbitrary node-attr values, without a custom
    encoder pass over this structure specifically.
    """
    return {
        "nodes": [
            {"id": n, "kind": d.get("kind"), "label": d.get("label")}
            for n, d in g.nodes(data=True)
        ],
        "edges": [
            {"source": u, "target": v, "relation": d.get("relation")}
            for u, v, d in g.edges(data=True)
        ],
    }
