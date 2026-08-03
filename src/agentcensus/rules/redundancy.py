"""Redundancy and waste (project plan section 6, class 4)."""

from __future__ import annotations

from collections import defaultdict

from agentcensus.core.models import Finding, FindingClass, Inventory
from agentcensus.core.rules import Rule
from agentcensus.core.severity import SeverityConfig, score


class NoSuccessfulOutcomesRule(Rule):
    rule_id = "redundancy.no_successful_outcomes"

    def evaluate(self, inventory: Inventory, config: SeverityConfig) -> list[Finding]:
        findings = []
        for agent in inventory.agents:
            if agent.successful_outcomes == 0:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        finding_class=FindingClass.REDUNDANCY,
                        severity=score(impact=0, exposure=1),
                        subject_type="agent",
                        subject_id=agent.id,
                        title=f"Agent '{agent.name}' has zero recorded successful outcomes",
                        explanation=(
                            f"'{agent.name}' is consuming resources (credentials, tool "
                            "access, compute) with no recorded successful outcome. It may "
                            "have never worked, or may no longer be invoked."
                        ),
                        recommended_action="Investigate usage; decommission if it has no path to a successful outcome.",
                        evidence={},
                    )
                )
        return findings


class DuplicateAgentNameRule(Rule):
    """Coarse first pass at 'duplicate or near-duplicate agents across
    teams' — exact name collisions only. Real near-duplicate detection
    (similar descriptions/tool sets across owners) is a phase 2+
    problem; this rule exists so the finding class isn't empty in v1."""

    rule_id = "redundancy.duplicate_name"

    def evaluate(self, inventory: Inventory, config: SeverityConfig) -> list[Finding]:
        by_name: dict[str, list[str]] = defaultdict(list)
        for agent in inventory.agents:
            by_name[agent.name.strip().lower()].append(agent.id)

        findings = []
        for name, ids in by_name.items():
            if len(ids) > 1:
                for agent_id in ids:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            finding_class=FindingClass.REDUNDANCY,
                            severity=score(impact=0, exposure=0),
                            subject_type="agent",
                            subject_id=agent_id,
                            title=f"Agent name '{name}' is duplicated across {len(ids)} agents",
                            explanation=(
                                f"{len(ids)} agents share the name '{name}'. This may be "
                                "intentional (per-team copies) or may indicate the same "
                                "capability was rebuilt more than once."
                            ),
                            recommended_action="Review whether these are true duplicates and consolidate if so.",
                            evidence={"duplicate_agent_ids": ids},
                        )
                    )
        return findings


REDUNDANCY_RULES = [
    NoSuccessfulOutcomesRule(),
    DuplicateAgentNameRule(),
]
