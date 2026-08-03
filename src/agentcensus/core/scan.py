"""Scan orchestration — the piece that actually wires the dependency
graph into the rule engine's output.

Before this module existed, the CLI called `RuleEngine.run` directly
and `core/graph.py` was fully implemented but never invoked by anything
except tests: nothing built a graph from a real scan, and
`severity.escalate_for_blast_radius` — the whole point of building a
graph, per its own docstring and the README's "Dependency mapping"
section — was dead code outside test_core.py. `run_scan` is the one
place that changes: build the graph once, run every rule, then walk
the findings and escalate any whose subject (a credential or tool) has
agents downstream of it in the graph.

Kept separate from `rules.RuleEngine` on purpose — the engine's job is
"run rules against an inventory," full stop, and stays testable/usable
without a graph. Blast-radius escalation is a cross-cutting concern
that needs both the rule output and the graph at once, so it lives
one layer up, not inside the engine or inside graph.py.
"""

from __future__ import annotations

import networkx as nx

from agentcensus.core.graph import build_graph, downstream_agents
from agentcensus.core.models import Finding, Inventory
from agentcensus.core.rules import default_engine
from agentcensus.core.severity import (
    SeverityConfig,
    apply_confidence_cap,
    escalate_for_blast_radius,
)


def escalate_findings(findings: list[Finding], graph: nx.DiGraph) -> None:
    """Mutates `findings` in place, escalating any whose subject (a
    credential or tool node) has a large enough blast radius in `graph`.
    Factored out from `run_scan` so the multi-connector CLI path
    (core/correlate.py's merged + cross-platform-correlated graph) can
    reuse the exact same escalation logic against a graph that wasn't
    built by this function — a credential's blast radius should count
    agents reachable via a `same_identity_as` edge into another platform
    exactly the same way it counts a direct `runs_as`/`uses` edge within
    one platform; there's no reason for two separate escalation rules.
    """
    for finding in findings:
        # Node ids are "{kind}:{id}" and Finding.subject_type is always
        # one of "agent" | "tool" | "credential" — the same vocabulary
        # build_graph uses for node kind, so this always resolves to a
        # real (or absent) node without a lookup table.
        node_id = f"{finding.subject_type}:{finding.subject_id}"
        downstream = downstream_agents(graph, node_id)
        if not downstream:
            continue

        # Written unconditionally, even when the cap below prevents any
        # escalation: a large blast radius on an unconfirmed finding is
        # exactly the reason to prioritise VERIFYING it, so the reader
        # needs the number whether or not it moved the severity.
        finding.evidence["downstream_agent_count"] = len(downstream)

        raised = escalate_for_blast_radius(finding.severity, len(downstream))
        # A heuristic keyword match does not become a verdict because
        # other things depend on it. Escalation raises; the confidence
        # cap is what stops it raising past what the evidence supports.
        escalated = apply_confidence_cap(raised, finding.confidence)

        if raised != escalated:
            # Say so in the report rather than silently flattening it —
            # "this would be CRITICAL if confirmed" is actionable, and a
            # reader comparing two MEDIUM findings otherwise has no way
            # to tell which one is worth chasing first.
            finding.evidence["severity_capped_by_confidence"] = True
            finding.evidence["severity_if_confirmed"] = raised.value

        if escalated != finding.severity:
            finding.evidence["severity_before_blast_radius"] = finding.severity.value
            finding.severity = escalated


def run_scan(
    inventory: Inventory, config: SeverityConfig | None = None
) -> tuple[list[Finding], nx.DiGraph]:
    """Runs every registered rule, builds the dependency graph, and
    escalates each finding whose subject has a large enough blast
    radius. Returns (findings, graph) — findings are mutated in place
    (Finding is a plain dataclass) rather than copied, since nothing
    else holds a reference to the pre-escalation objects.
    """
    config = config or SeverityConfig()
    findings = default_engine().run(inventory, config)
    graph = build_graph(inventory)
    escalate_findings(findings, graph)
    return findings, graph
