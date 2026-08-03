"""Construction quality (project plan section 6, class 3)."""

from __future__ import annotations

from agentcensus.core.models import Finding, FindingClass, Inventory, Provenance
from agentcensus.core.rules import Rule
from agentcensus.core.severity import SeverityConfig, score


class MissingDescriptionRule(Rule):
    rule_id = "construction.missing_description"

    def evaluate(self, inventory: Inventory, config: SeverityConfig) -> list[Finding]:
        findings = []
        for agent in inventory.agents:
            # SYNTHESIZED agents have no description because AgentCensus
            # invented them from a Script Include or a Flow, and those
            # artifacts have no field meaning what this rule means.
            # Reporting them describes a gap in OUR OWN synthesis as a
            # construction defect in the customer's environment — one per
            # shadow agent, with a recommended action nobody can take
            # ("add a description" to a record with nowhere to put one).
            # This rule is about agents someone authored in a registry
            # that HAS the field.
            if agent.provenance != Provenance.NATIVE:
                continue
            if not agent.description or not agent.description.strip():
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        finding_class=FindingClass.CONSTRUCTION,
                        severity=score(impact=0, exposure=1),
                        subject_type="agent",
                        subject_id=agent.id,
                        title=f"Agent '{agent.name}' has no description",
                        explanation=(
                            f"'{agent.name}' has an empty or missing description. Beyond "
                            "governance review, this affects model routing behavior in "
                            "platforms that select agents/tools based on their descriptions."
                        ),
                        recommended_action="Add a description covering purpose, scope, and owner.",
                        evidence={},
                    )
                )
        return findings


class UndefinedFallbackRule(Rule):
    rule_id = "construction.undefined_fallback"

    def evaluate(self, inventory: Inventory, config: SeverityConfig) -> list[Finding]:
        findings = []
        for agent in inventory.agents:
            if agent.has_defined_fallback is False:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        finding_class=FindingClass.CONSTRUCTION,
                        severity=score(impact=1, exposure=1),
                        subject_type="agent",
                        subject_id=agent.id,
                        title=f"Agent '{agent.name}' has no defined failure/fallback behavior",
                        explanation=(
                            f"'{agent.name}' has no configured behavior for when a tool call "
                            "fails or returns an unexpected result. Undefined failure "
                            "behavior tends to surface as silent errors or retries against "
                            "downstream systems."
                        ),
                        recommended_action="Define explicit fallback/failure handling for this agent.",
                        evidence={},
                    )
                )
        return findings


CONSTRUCTION_RULES = [
    MissingDescriptionRule(),
    UndefinedFallbackRule(),
]
