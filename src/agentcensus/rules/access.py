"""Access and permission risk (project plan section 6, class 2)."""

from __future__ import annotations

from agentcensus.core.models import AccountType, Finding, FindingClass, Inventory
from agentcensus.core.rules import Rule
from agentcensus.core.severity import SeverityConfig, score


class SharedAccountRule(Rule):
    rule_id = "access.shared_human_account"

    def evaluate(self, inventory: Inventory, config: SeverityConfig) -> list[Finding]:
        findings = []
        for agent in inventory.agents:
            if agent.account_type == AccountType.SHARED_HUMAN_ACCOUNT:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        finding_class=FindingClass.ACCESS,
                        severity=score(impact=2, exposure=1),
                        subject_type="agent",
                        subject_id=agent.id,
                        title=f"Agent '{agent.name}' runs as a human account, not a scoped service account",
                        explanation=(
                            f"'{agent.name}' operates under what appears to be a shared or "
                            "personal human account rather than a scoped service account. "
                            "Its actions are indistinguishable from that person's own "
                            "actions in the audit trail, and its access is whatever that "
                            "person has — not what the agent actually needs."
                        ),
                        recommended_action=(
                            "Migrate to a dedicated, scoped service account with the minimum "
                            "permissions the agent's tools actually require."
                        ),
                        evidence={"run_as": agent.raw.get("run_as")},
                    )
                )
        return findings


class IrreversibleWithoutApprovalRule(Rule):
    rule_id = "access.irreversible_no_approval_gate"
    # `is False`, not `not ...`: None means the gate status was never
    # DETERMINED, and this rule asserts "no configured human approval
    # gate" as fact, at HIGH and at CONFIRMED confidence. No shipped
    # connector populates is_irreversible yet, so the rule is currently
    # unreachable — which is exactly why this costs nothing to fix now
    # and would be a live false-accusation bug the day one does.

    def evaluate(self, inventory: Inventory, config: SeverityConfig) -> list[Finding]:
        tools_by_id = {t.id: t for t in inventory.tools}
        findings = []
        for agent in inventory.agents:
            has_irreversible = any(
                tools_by_id[tid].is_irreversible
                for tid in agent.tool_ids
                if tid in tools_by_id and tools_by_id[tid].is_irreversible
            )
            if has_irreversible and agent.has_approval_gate is False:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        finding_class=FindingClass.ACCESS,
                        severity=score(impact=3, exposure=1),
                        subject_type="agent",
                        subject_id=agent.id,
                        title=f"Agent '{agent.name}' can take irreversible action with no human approval",
                        explanation=(
                            f"'{agent.name}' has at least one tool capable of an "
                            "irreversible action (delete, send, approve, pay, etc.) and no "
                            "configured human approval gate before that action executes."
                        ),
                        recommended_action=(
                            "Add an approval step before irreversible actions, or scope the "
                            "agent's tools down to reversible actions only."
                        ),
                        evidence={"tool_ids": agent.tool_ids},
                    )
                )
        return findings


class NoAuditLoggingRule(Rule):
    rule_id = "access.no_audit_logging"

    def evaluate(self, inventory: Inventory, config: SeverityConfig) -> list[Finding]:
        findings = []
        for cred in inventory.credentials:
            if cred.has_audit_logging is False:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        finding_class=FindingClass.ACCESS,
                        severity=score(impact=2, exposure=2),
                        subject_type="credential",
                        subject_id=cred.id,
                        title=f"Credential '{cred.name}' has no audit logging configured",
                        explanation=(
                            f"Actions taken under '{cred.name}' are not being logged. If "
                            "this credential is misused or compromised, there is no trail "
                            "to investigate."
                        ),
                        recommended_action="Enable audit logging for this credential/integration user.",
                        evidence={},
                    )
                )
        return findings


class SensitiveTableAccessRule(Rule):
    """Consumes `SeverityConfig.sensitive_tables` — see the design note
    at the top of core/severity.py: which tables count as sensitive is
    an environment fact a customer supplies, not something a rule
    should hardcode. Only fires when an agent's `target_table` is both
    known (currently: business-rule-sourced shadow agents populate it
    from the rule's `collection` field — see shadow.py's tier 4) and
    present in the configured set. An agent with target_table=None is
    "not determined", not "not sensitive", so it's silently skipped
    rather than assumed safe."""

    rule_id = "access.sensitive_table_write"

    def evaluate(self, inventory: Inventory, config: SeverityConfig) -> list[Finding]:
        if not config.sensitive_tables:
            return []

        findings = []
        for agent in inventory.agents:
            if not agent.target_table or agent.target_table not in config.sensitive_tables:
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    finding_class=FindingClass.ACCESS,
                    severity=score(impact=2, exposure=1, confidence=agent.confidence),
                    subject_type="agent",
                    subject_id=agent.id,
                    title=f"Agent '{agent.name}' writes against sensitive table '{agent.target_table}'",
                    explanation=(
                        f"'{agent.name}' operates against '{agent.target_table}', which this "
                        "environment's configuration marks as sensitive (SeverityConfig."
                        "sensitive_tables). An agent with standing write access to a "
                        "sensitive table is a higher-impact finding than the same agent "
                        "operating against an ordinary table, regardless of its other "
                        "governance signals."
                    ),
                    recommended_action=(
                        "Confirm this agent needs write access to this table specifically, "
                        "and that its owner and approval gates match the table's sensitivity."
                    ),
                    confidence=agent.confidence,
                    evidence={"target_table": agent.target_table},
                )
            )
        return findings


ACCESS_RULES = [
    SharedAccountRule(),
    IrreversibleWithoutApprovalRule(),
    NoAuditLoggingRule(),
    SensitiveTableAccessRule(),
]
