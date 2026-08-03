"""Cross-connector correlation.

A single connector run only ever sees one platform. But "an agent
connected to both Splunk and ServiceNow simultaneously" — one of the
scenarios this project was explicitly asked to cover — can't be seen by
any single-platform Inventory on its own: two independently-run
connectors, each internally consistent, say nothing about whether a
credential in one is the same real-world identity as a credential in
the other. That correlation has to happen one layer up, after both
scans have already run.

`merge_and_correlate` does two things:

  1. Namespaces every object's id by platform before combining
     (`merge_inventories`) — two connectors that happen to reuse the
     same id scheme, or even the same literal id, must never collide
     into one accidental node. Every merge across platforms has to be
     an explicit, evidenced identity match, never a coincidence of two
     unrelated systems both calling something "1".
  2. Adds `same_identity_as` edges, both directions so blast-radius
     traversal (core/graph.py's `downstream_agents`, which walks
     `nx.ancestors`) works symmetrically across the merge point, between
     nodes whose *own connector* populated a shared identity signal:
     `Credential.correlation_key` or `Owner.email`. Never inferred by
     guessing at name similarity — a false merge (treating two
     different real identities as one) is worse than a missed one on a
     graph whose entire purpose is showing what's actually connected to
     what. If two connectors don't expose a shared signal for what is
     in fact the same underlying credential or person, this correctly
     leaves them as two separate nodes rather than guessing.

CURRENT REALITY, STATED PLAINLY: this feature is INERT end to end, and
a reader should know that before relying on it.

  * No shipped connector populates `Credential.correlation_key`. The
    only one that ever did was inventing it from an email address, which
    merged two service accounts sharing a team mailbox — see
    `integration_accounts.py`. Setting it to None was the correct fix,
    and it leaves credential-level correlation with no real signal.
  * `Owner.email` edges ARE built, but owner nodes are sinks in the
    dependency graph, so a `same_identity_as` edge between two owners
    can never widen a credential's blast radius. It de-duplicates people
    in the inventory; it does not connect infrastructure.

So the machinery here is correct and tested, and currently has nothing
to act on. That is a gap in the CONNECTORS (none of them expose a
genuine cross-platform credential identity yet — an OAuth client_id
registered in both ServiceNow and Splunk would be one), not in this
module. Named here rather than left for a reader to discover, because
README lists cross-platform correlation as a capability.

This only activates when the CLI is given more than one `--connector`.
A single-connector run never goes through this module at all — see
`cli.py` and `core/scan.py`'s `run_scan`, which stays exactly as it was
for that case, so single-platform reports and their id scheme are
unaffected by any of this.
"""

from __future__ import annotations

import dataclasses

import networkx as nx

from agentcensus.core.graph import build_graph
from agentcensus.core.models import Inventory


def _namespaced(platform: str, id_: str) -> str:
    return f"{platform}::{id_}"


def merge_inventories(inventories: list[Inventory]) -> Inventory:
    """Combines N Inventory objects into one, namespacing every id (and
    every foreign key that references one — owner_id, credential_id,
    tool_ids) by the originating platform. Always namespaces, even for a
    single-element list, so this function's output has one consistent id
    scheme regardless of input size — callers needing the original,
    unnamespaced single-connector behavior should use `core.scan.run_scan`
    directly instead of going through this module at all.
    """
    if not inventories:
        raise ValueError("merge_inventories requires at least one Inventory")

    merged_agents = []
    merged_tools = []
    merged_credentials = []
    merged_owners = []
    merged_notes: list[str] = []

    for inv in inventories:
        platform = inv.platform
        for owner in inv.owners:
            merged_owners.append(dataclasses.replace(owner, id=_namespaced(platform, owner.id)))
        for cred in inv.credentials:
            merged_credentials.append(
                dataclasses.replace(
                    cred,
                    id=_namespaced(platform, cred.id),
                    owner_id=_namespaced(platform, cred.owner_id) if cred.owner_id else None,
                )
            )
        for tool in inv.tools:
            merged_tools.append(
                dataclasses.replace(
                    tool,
                    id=_namespaced(platform, tool.id),
                    credential_id=_namespaced(platform, tool.credential_id) if tool.credential_id else None,
                )
            )
        for agent in inv.agents:
            merged_agents.append(
                dataclasses.replace(
                    agent,
                    id=_namespaced(platform, agent.id),
                    owner_id=_namespaced(platform, agent.owner_id) if agent.owner_id else None,
                    tool_ids=[_namespaced(platform, t) for t in agent.tool_ids],
                )
            )
        merged_notes.append(
            f"[{platform}] contributed {len(inv.agents)} agent(s), {len(inv.tools)} tool(s), "
            f"{len(inv.credentials)} credential(s) to this merged scan."
        )
        merged_notes.extend(f"[{platform}] {note}" for note in inv.scan_notes)

    # Access gaps MUST survive the merge, and the consequence of them not
    # doing so was the single worst defect an independent review found.
    #
    # This function rebuilt an Inventory field by field and simply never
    # mentioned `access_gaps`, so it defaulted to []. `_coverage_banner([])`
    # renders "Full coverage — every table and field this scan needs was
    # readable." So `--connector servicenow --connector splunk` — a command
    # in the CLI's own docstring — took a scan with twelve recorded gaps
    # and published it as complete. The JSON's `access_gaps` array, sold as
    # the thing a pipeline can gate on, was empty for the same reason: a CI
    # check for "fail if any filter was dropped" silently passed.
    #
    # The product's central promise, inverted by adding one flag.
    #
    # Deduped on (table, kind, fields) and prefixed with the platform,
    # because the same table name can exist on two platforms and a merged
    # section that says "read on table users" twice is unactionable.
    merged_gaps = []
    seen_gaps: set[tuple] = set()
    for inv in inventories:
        for gap in inv.access_gaps:
            key = (inv.platform, gap.table, gap.kind, gap.fields)
            if key in seen_gaps:
                continue
            seen_gaps.add(key)
            merged_gaps.append(dataclasses.replace(gap, table=f"[{inv.platform}] {gap.table}"))

    return Inventory(
        platform="+".join(sorted({inv.platform for inv in inventories})),
        scanned_at=max(inv.scanned_at for inv in inventories),
        agents=merged_agents,
        tools=merged_tools,
        credentials=merged_credentials,
        owners=merged_owners,
        scan_notes=merged_notes,
        access_gaps=merged_gaps,
    )


def add_cross_platform_identity_edges(g: nx.DiGraph, inventories: list[Inventory]) -> nx.DiGraph:
    """Mutates and returns `g` (expected to already be `build_graph`'d from
    `merge_inventories`'s output) by adding `same_identity_as` edges within
    every group of nodes that share a non-null `Credential.correlation_key`
    or `Owner.email`, computed from the ORIGINAL (pre-merge) inventories so
    each platform's own id can be namespaced identically to how
    `merge_inventories` namespaced it."""
    by_cred_key: dict[str, list[str]] = {}
    by_owner_email: dict[str, list[str]] = {}

    for inv in inventories:
        platform = inv.platform
        for cred in inv.credentials:
            if not cred.correlation_key:
                continue
            node_id = f"credential:{_namespaced(platform, cred.id)}"
            by_cred_key.setdefault(cred.correlation_key.strip().lower(), []).append(node_id)
        for owner in inv.owners:
            if not owner.email:
                continue
            node_id = f"owner:{_namespaced(platform, owner.id)}"
            by_owner_email.setdefault(owner.email.strip().lower(), []).append(node_id)

    for groups in (by_cred_key, by_owner_email):
        for node_ids in groups.values():
            unique = sorted({n for n in node_ids if n in g})
            if len(unique) < 2:
                continue
            for i, a in enumerate(unique):
                for b in unique[i + 1 :]:
                    g.add_edge(a, b, relation="same_identity_as")
                    g.add_edge(b, a, relation="same_identity_as")
    return g


def merge_and_correlate(inventories: list[Inventory]) -> tuple[Inventory, nx.DiGraph]:
    """The entry point multi-connector CLI runs use: merge, build the
    graph, then correlate. Returns (merged_inventory, graph) — findings
    still need to be run against the merged inventory separately (see
    cli.py), same division of responsibility as core.scan.run_scan."""
    merged = merge_inventories(inventories)
    g = build_graph(merged)
    add_cross_platform_identity_edges(g, inventories)
    return merged, g
