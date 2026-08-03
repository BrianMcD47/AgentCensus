from datetime import datetime, timedelta, timezone

from agentcensus.core.graph import build_graph, downstream_agents
from agentcensus.core.models import (
    AccountType,
    Agent,
    Confidence,
    Credential,
    Inventory,
    Owner,
    OwnerStatus,
    Severity,
    Tool,
)
from agentcensus.core.rules import default_engine
from agentcensus.core.scan import run_scan
from agentcensus.core.severity import SeverityConfig, escalate_for_blast_radius, score


def test_severity_table_is_monotonic_in_impact_and_exposure():
    # higher impact at fixed exposure should never produce a *lower* severity
    order = [Severity.INFORMATIONAL, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    for exposure in range(4):
        prev = -1
        for impact in range(4):
            idx = order.index(score(impact, exposure))
            assert idx >= prev
            prev = idx


def test_escalate_for_blast_radius_never_lowers_severity():
    base = Severity.LOW
    assert escalate_for_blast_radius(base, downstream_count=0) == Severity.LOW
    assert escalate_for_blast_radius(base, downstream_count=3) == Severity.MEDIUM
    assert escalate_for_blast_radius(base, downstream_count=10) == Severity.HIGH


def test_needs_review_confidence_caps_severity_at_medium():
    from agentcensus.core.models import Confidence

    # (3, 3) would be CRITICAL at CONFIRMED confidence
    assert score(3, 3, confidence=Confidence.CONFIRMED) == Severity.CRITICAL
    assert score(3, 3, confidence=Confidence.NEEDS_REVIEW) == Severity.MEDIUM
    # a NEEDS_REVIEW finding that would already be below the cap is untouched
    assert score(0, 1, confidence=Confidence.NEEDS_REVIEW) == Severity.INFORMATIONAL


def _sample_inventory() -> Inventory:
    inactive_owner = Owner(id="u1", display_name="Departed Person", status=OwnerStatus.INACTIVE)
    agent = Agent(
        id="a1",
        name="Ticket Triage Bot",
        description=None,
        owner_id="u1",
        tool_ids=["t1"],
        account_type=AccountType.SHARED_HUMAN_ACCOUNT,
        last_active_at=datetime.now(timezone.utc) - timedelta(days=200),
        successful_outcomes=0,
    )
    tool = Tool(id="t1", name="close_ticket", description=None, credential_id="c1", is_irreversible=True)
    return Inventory(
        platform="test",
        scanned_at=datetime.now(timezone.utc),
        agents=[agent],
        tools=[tool],
        credentials=[],
        owners=[inactive_owner],
    )


def test_rule_engine_flags_orphaned_agent_with_inactive_owner():
    inventory = _sample_inventory()
    engine = default_engine()
    findings = engine.run(inventory, SeverityConfig())
    rule_ids = {f.rule_id for f in findings}
    assert "orphaned.creator_inactive" in rule_ids
    assert "access.shared_human_account" in rule_ids
    assert "construction.missing_description" in rule_ids
    assert "redundancy.no_successful_outcomes" in rule_ids


def test_graph_blast_radius():
    inventory = _sample_inventory()
    g = build_graph(inventory)
    downstream = downstream_agents(g, "credential:c1")
    assert downstream == {"agent:a1"}


def test_report_to_json_round_trips_enums_and_datetimes():
    import json

    from agentcensus.core.report import to_json

    inventory = _sample_inventory()
    engine = default_engine()
    findings = engine.run(inventory, SeverityConfig())

    raw = to_json(inventory, findings)
    parsed = json.loads(raw)  # raises if serialization produced invalid JSON

    assert parsed["platform"] == "test"
    assert parsed["counts"]["agents"] == 1
    assert parsed["counts"]["findings"] == len(findings)
    # enums serialize as their plain string value, not repr("Severity.HIGH")
    assert all(f["severity"] in {s.value for s in Severity} for f in parsed["findings"])
    assert all(f["confidence"] in {"confirmed", "needs_review"} for f in parsed["findings"])


def _blast_radius_inventory(n_agents: int, cred_id: str = "c1", tool_id: str = "t1") -> Inventory:
    """n_agents agents share one tool, which runs as one credential with
    no audit logging — so access.no_audit_logging fires once on the
    credential, and downstream_agents(graph, 'credential:c1') should
    find all n_agents through the agent -> tool -> credential chain."""
    cred = Credential(
        id=cred_id, name="shared_svc_account", account_type=AccountType.UNKNOWN,
        owner_id=None, has_audit_logging=False,
    )
    tool = Tool(id=tool_id, name="do_thing", description="does a thing", credential_id=cred_id)
    agents = [
        Agent(id=f"a{i}", name=f"Agent {i}", description="does things", owner_id=None, tool_ids=[tool_id])
        for i in range(n_agents)
    ]
    return Inventory(
        platform="test", scanned_at=datetime.now(timezone.utc),
        agents=agents, tools=[tool], credentials=[cred], owners=[],
    )


def test_run_scan_escalates_severity_for_credential_with_large_blast_radius():
    """This is the thing core/scan.py exists for: before it, nothing in
    the real scan path ever called escalate_for_blast_radius — the
    graph was built and tested in isolation but never actually fed
    back into a finding's severity."""
    inventory = _blast_radius_inventory(n_agents=3)
    findings, graph = run_scan(inventory, SeverityConfig())

    cred_finding = next(f for f in findings if f.rule_id == "access.no_audit_logging")
    # base severity is score(impact=2, exposure=2) == HIGH; 3 downstream
    # agents crosses the >=3 threshold for a one-tier bump -> CRITICAL
    assert cred_finding.severity == Severity.CRITICAL
    assert cred_finding.evidence["downstream_agent_count"] == 3
    assert cred_finding.evidence["severity_before_blast_radius"] == "high"

    assert graph.number_of_nodes() > 0
    assert "agent:a0" in graph


def test_run_scan_does_not_escalate_below_threshold():
    inventory = _blast_radius_inventory(n_agents=1)
    findings, _ = run_scan(inventory, SeverityConfig())

    cred_finding = next(f for f in findings if f.rule_id == "access.no_audit_logging")
    # only 1 downstream agent, below the >=3 escalation threshold
    assert cred_finding.severity == Severity.HIGH
    assert cred_finding.evidence["downstream_agent_count"] == 1
    assert "severity_before_blast_radius" not in cred_finding.evidence


def test_report_to_json_includes_dependency_graph_when_provided():
    import json

    from agentcensus.core.report import to_json

    inventory = _sample_inventory()
    findings, graph = run_scan(inventory, SeverityConfig())
    parsed = json.loads(to_json(inventory, findings, graph))

    assert "dependency_graph" in parsed
    assert any(n["id"] == "agent:a1" for n in parsed["dependency_graph"]["nodes"])
    assert any(e["relation"] == "uses" for e in parsed["dependency_graph"]["edges"])
    # omitting graph entirely (existing callers, older reports) still works
    assert "dependency_graph" not in json.loads(to_json(inventory, findings))


def test_sensitive_table_rule_only_fires_when_configured_and_known():
    sensitive_agent = Agent(
        id="a_sensitive", name="PII Scrubber", description="d", owner_id=None, target_table="sys_user",
    )
    unknown_agent = Agent(
        id="a_unknown", name="Mystery Bot", description="d", owner_id=None, target_table=None,
    )
    other_table_agent = Agent(
        id="a_other", name="Ticket Bot", description="d", owner_id=None, target_table="incident",
    )
    inventory = Inventory(
        platform="test", scanned_at=datetime.now(timezone.utc),
        agents=[sensitive_agent, unknown_agent, other_table_agent], tools=[], credentials=[], owners=[],
    )

    # unconfigured -> silent even though target_table is populated
    findings = default_engine().run(inventory, SeverityConfig())
    assert not any(f.rule_id == "access.sensitive_table_write" for f in findings)

    # configured -> fires only for the agent whose target_table matches,
    # never for the one with an unknown (None) target_table
    findings = default_engine().run(inventory, SeverityConfig(sensitive_tables={"sys_user"}))
    hits = [f for f in findings if f.rule_id == "access.sensitive_table_write"]
    assert {f.subject_id for f in hits} == {"a_sensitive"}


def test_sensitive_table_rule_respects_needs_review_severity_cap():
    agent = Agent(
        id="a1", name="Shadow Bot", description="d", owner_id=None,
        target_table="sys_user", confidence=Confidence.NEEDS_REVIEW,
    )
    inventory = Inventory(
        platform="test", scanned_at=datetime.now(timezone.utc),
        agents=[agent], tools=[], credentials=[], owners=[],
    )
    findings = default_engine().run(inventory, SeverityConfig(sensitive_tables={"sys_user"}))
    hit = next(f for f in findings if f.rule_id == "access.sensitive_table_write")
    # locks in that the rule threads agent.confidence through to both
    # Finding.confidence and severity.score's confidence param, rather
    # than hardcoding CONFIRMED regardless of the agent's real confidence
    assert hit.confidence == Confidence.NEEDS_REVIEW
    assert hit.severity == score(impact=2, exposure=1, confidence=Confidence.NEEDS_REVIEW)
