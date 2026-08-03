"""CLI integration tests against a stub connector — no live platform,
no network. Registers a throwaway connector under a test-only platform
id via the same `core.registry.register` real connectors use, so this
exercises the actual `cli.main` code path (argument parsing, SeverityConfig
construction from --sensitive-table/--sensitive-role, run_scan wiring,
write_json with the graph) rather than calling internal functions
directly.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from agentcensus.cli import main
from agentcensus.core import registry
from agentcensus.core.connector import Connector
from agentcensus.core.models import (
    AccountType,
    Agent,
    Credential,
    Inventory,
    Tool,
)


class _StubConnector(Connector):
    platform_id = "stub-test-platform"

    def test_connection(self) -> bool:
        return True

    def fetch_inventory(self, **options) -> Inventory:
        cred = Credential(
            id="c1", name="svc", account_type=AccountType.UNKNOWN,
            owner_id=None, has_audit_logging=False,
            correlation_key="shared-identity@example.com",
        )
        tool = Tool(id="t1", name="tool1", description="d", credential_id="c1")
        agent = Agent(
            id="a1", name="Agent One", description="d", owner_id=None,
            tool_ids=["t1"], target_table="incident",
        )
        return Inventory(
            platform=self.platform_id,
            scanned_at=datetime.now(timezone.utc),
            agents=[agent], tools=[tool], credentials=[cred], owners=[],
        )


class _StubConnectorB(Connector):
    """A second stub platform whose credential shares stub A's
    correlation_key — simulates the same real-world identity (e.g. the
    same OAuth client or service account) showing up on two different
    platforms, which is exactly the "agent connected to both
    simultaneously" scenario core/correlate.py exists for."""

    platform_id = "stub-test-platform-b"

    def test_connection(self) -> bool:
        return True

    def fetch_inventory(self, **options) -> Inventory:
        cred = Credential(
            id="c1", name="svc-b", account_type=AccountType.UNKNOWN,  # same literal id "c1"
            owner_id=None, has_audit_logging=False,                   # as stub A on purpose —
            correlation_key="shared-identity@example.com",            # proves namespacing
        )
        tool = Tool(id="t1", name="tool1", description="d", credential_id="c1")
        agent = Agent(id="b1", name="Agent B", description="d", owner_id=None, tool_ids=["t1"])
        return Inventory(
            platform=self.platform_id,
            scanned_at=datetime.now(timezone.utc),
            agents=[agent], tools=[tool], credentials=[cred], owners=[],
        )


registry.register(_StubConnector.platform_id, _StubConnector)
registry.register(_StubConnectorB.platform_id, _StubConnectorB)


def test_scan_writes_report_with_dependency_graph_and_sensitive_table_finding(tmp_path):
    out = tmp_path / "report.json"
    exit_code = main([
        "scan",
        "--connector", "stub-test-platform",
        "--output", str(out),
        "--sensitive-table", "incident",
    ])

    assert exit_code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))

    assert "dependency_graph" in payload
    assert any(n["id"] == "agent:a1" for n in payload["dependency_graph"]["nodes"])

    rule_ids = {f["rule_id"] for f in payload["findings"]}
    # --sensitive-table incident should make SensitiveTableAccessRule fire
    # for the stub agent, whose target_table is "incident"
    assert "access.sensitive_table_write" in rule_ids


def test_scan_without_sensitive_table_flag_does_not_fire_the_rule(tmp_path):
    out = tmp_path / "report.json"
    main(["scan", "--connector", "stub-test-platform", "--output", str(out)])

    payload = json.loads(out.read_text(encoding="utf-8"))
    rule_ids = {f["rule_id"] for f in payload["findings"]}
    assert "access.sensitive_table_write" not in rule_ids


def test_multi_connector_scan_merges_and_correlates_across_platforms(tmp_path):
    """The scenario named explicitly in scoping: an agent (well, its
    credential here) connected to two platforms simultaneously should
    show up as one correlated graph, not two disjoint reports. Both
    stub connectors deliberately reuse the literal id "c1" for their
    credential — proves namespacing prevents an accidental collision —
    while sharing the same correlation_key, which SHOULD merge them via
    a same_identity_as edge."""
    out = tmp_path / "report.json"
    exit_code = main([
        "scan",
        "--connector", "stub-test-platform",
        "--connector", "stub-test-platform-b",
        "--output", str(out),
    ])
    assert exit_code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))

    node_ids = {n["id"] for n in payload["dependency_graph"]["nodes"]}
    assert "agent:stub-test-platform::a1" in node_ids
    assert "agent:stub-test-platform-b::b1" in node_ids
    assert "credential:stub-test-platform::c1" in node_ids
    assert "credential:stub-test-platform-b::c1" in node_ids

    same_identity_edges = [
        e for e in payload["dependency_graph"]["edges"] if e["relation"] == "same_identity_as"
    ]
    assert any(
        {e["source"], e["target"]} == {"credential:stub-test-platform::c1", "credential:stub-test-platform-b::c1"}
        for e in same_identity_edges
    )

    # blast radius for the no-audit-logging finding on either platform's
    # credential now counts both platforms' agents, via the
    # same_identity_as edge — this is the actual payoff, not just the
    # edge existing cosmetically
    audit_findings = [f for f in payload["findings"] if f["rule_id"] == "access.no_audit_logging"]
    assert len(audit_findings) == 2
    for f in audit_findings:
        assert f["evidence"]["downstream_agent_count"] == 2


def test_repeating_the_same_connector_is_rejected(tmp_path):
    out = tmp_path / "report.json"
    exit_code = main([
        "scan",
        "--connector", "stub-test-platform",
        "--connector", "stub-test-platform",
        "--output", str(out),
    ])
    assert exit_code == 1
    assert not out.exists()


def _tiny_inventory():
    from datetime import datetime, timezone

    from agentcensus.core.models import (
        Agent, Confidence, Finding, FindingClass, Inventory, Provenance, Severity,
    )
    inv = Inventory(
        platform="servicenow",
        scanned_at=datetime.now(timezone.utc),
        agents=[Agent(id="a1", name="ShadowBot", description=None, owner_id=None,
                      provenance=Provenance.SYNTHESIZED, confidence=Confidence.NEEDS_REVIEW,
                      detection_signal="shadow:script_keyword:script_include:anthropic")],
        scan_notes=["Access denied reading 'sys_script' — the scan credential lacks read access."],
    )
    findings = [
        Finding(rule_id="r.high", finding_class=FindingClass.UNGOVERNED, severity=Severity.HIGH,
                subject_type="agent", subject_id="a1", title="Ungoverned agent",
                explanation="No native governance record.", recommended_action="Register it."),
        Finding(rule_id="r.low", finding_class=FindingClass.CONSTRUCTION, severity=Severity.LOW,
                subject_type="agent", subject_id="a1", title="No description",
                explanation="Empty description.", recommended_action="Add one."),
    ]
    return inv, findings


def test_html_report_summarises_coverage_early_and_details_it_late(tmp_path):
    """REVERSED from the original rule, after a reader saw the rendered
    report for the first time.

    The old requirement was that scan notes come BEFORE the findings,
    reasoning that a partial scan which looks complete is the most
    dangerous output this tool can produce. The reasoning holds. The
    execution did not: twelve access-requirement rows and nineteen
    coverage notes ran ahead of every finding, and the effect on a reader
    was that the tool looked like it hadn't worked. Accuracy that costs
    you the reader before they reach the results is not a good trade.

    So the constraint is now split. A one-line banner carries the
    'this is incomplete' warning above the findings; the full detail
    lives at the bottom, where someone acting on it will look. Both
    halves are asserted, because dropping either one recreates a
    different failure — a silent partial scan, or a wall of caveats.
    """
    from agentcensus.core.report import render_html

    inv, findings = _tiny_inventory()
    inv.agents[0].name = "<script>alert(1)</script>"
    out = render_html(inv, findings)

    # Warning first...
    assert out.index("coverage") < out.index("<h2>Findings</h2>")
    # ...detail last.
    assert out.index("<h2>Findings</h2>") < out.index("could not see")
    assert out.index("<h2>Findings</h2>") < out.index("Access needed")
    assert "sys_script" in out
    assert "<script>alert(1)</script>" not in out   # escaped, not injected
    assert "&lt;script&gt;" in out
    # severity ordering: high before low
    assert out.index("Ungoverned agent") < out.index("No description")


def test_fail_on_exits_2_when_threshold_breached(tmp_path, monkeypatch):
    """Exit 2, not 1: everywhere else in this CLI exit 1 means 'the scan
    could not run'. A CI job has to tell that apart from 'ran fine, found
    something bad' — they call for opposite responses."""
    from agentcensus import cli

    inv, findings = _tiny_inventory()
    monkeypatch.setattr(cli.registry, "get", lambda p: _stub_connector(inv))
    monkeypatch.setattr(cli, "run_scan", lambda inventory, config: (findings, _empty_graph()))

    out = tmp_path / "r.json"
    assert cli.main(["scan", "--connector", "servicenow", "-o", str(out), "--fail-on", "high"]) == 2
    assert cli.main(["scan", "--connector", "servicenow", "-o", str(out), "--fail-on", "critical"]) == 0


def test_script_excerpts_without_script_scan_is_rejected_not_ignored():
    """A flag that silently does nothing teaches users their input
    doesn't matter."""
    from agentcensus import cli
    assert cli.main(["scan", "--connector", "servicenow", "--include-script-excerpts"]) == 1


def _empty_graph():
    import networkx as nx
    return nx.DiGraph()


def _stub_connector(inv):
    class _C:
        platform_id = "servicenow"

        def __init__(self, *a, **k):
            pass

        def test_connection(self):
            return True

        def fetch_inventory(self, **options):
            return inv

    return _C
