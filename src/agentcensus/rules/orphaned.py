"""Orphaned and abandoned (project plan section 6, class 1)."""

from __future__ import annotations

from datetime import datetime, timezone

from agentcensus.core.models import (
    Finding,
    FindingClass,
    Inventory,
    OwnerStatus,
    is_resolved_owner,
)
from agentcensus.core.rules import Rule
from agentcensus.core.severity import SeverityConfig, score
from agentcensus.rules.ungoverned import INTEGRATION_ACCOUNT_SOURCE


class CreatorInactiveRule(Rule):
    rule_id = "orphaned.creator_inactive"

    def evaluate(self, inventory: Inventory, config: SeverityConfig) -> list[Finding]:
        owners_by_id = {o.id: o for o in inventory.owners}
        findings = []
        for agent in inventory.agents:
            owner = owners_by_id.get(agent.owner_id) if agent.owner_id else None
            if owner and owner.status == OwnerStatus.INACTIVE:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        finding_class=FindingClass.ORPHANED,
                        severity=score(impact=1, exposure=2),
                        subject_type="agent",
                        subject_id=agent.id,
                        title=f"Agent '{agent.name}' was created by a deactivated user",
                        explanation=(
                            f"'{agent.name}' has no active owner. Its creator "
                            f"({owner.display_name}) is deactivated in the platform, "
                            "which means there is no one accountable for this agent's "
                            "continued operation, permissions, or removal."
                        ),
                        recommended_action=(
                            "Assign a new active owner or decommission the agent if it is "
                            "no longer needed."
                        ),
                        evidence={"owner_id": owner.id, "owner_status": owner.status.value},
                    )
                )
        return findings


class CreatorUnresolvedRule(Rule):
    rule_id = "orphaned.creator_unresolved"

    def evaluate(self, inventory: Inventory, config: SeverityConfig) -> list[Finding]:
        owners_by_id = {o.id: o for o in inventory.owners}
        findings = []
        for agent in inventory.agents:
            owner = owners_by_id.get(agent.owner_id) if agent.owner_id else None
            if agent.owner_id is None or (owner and owner.status == OwnerStatus.UNKNOWN):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        finding_class=FindingClass.ORPHANED,
                        severity=score(impact=1, exposure=3),
                        subject_type="agent",
                        subject_id=agent.id,
                        title=f"Agent '{agent.name}' has no resolvable owner",
                        explanation=(
                            f"'{agent.name}' has no owner record the scanner could resolve "
                            "at all — not even a deactivated one. This is a harder signal "
                            "than 'creator left the company': it means ownership was never "
                            "tracked, or the tracking has already broken."
                        ),
                        recommended_action=(
                            "Manually investigate and assign an owner immediately; treat as "
                            "higher priority than a merely-inactive creator."
                        ),
                        evidence={"owner_id": agent.owner_id},
                    )
                )
        return findings


class NoRecentActivityRule(Rule):
    rule_id = "orphaned.no_recent_activity"

    def __init__(self, window_days: int = 90):
        self.window_days = window_days

    def evaluate(self, inventory: Inventory, config: SeverityConfig) -> list[Finding]:
        now = datetime.now(timezone.utc)
        findings = []
        for agent in inventory.agents:
            if agent.last_active_at is None:
                continue
            age_days = (now - agent.last_active_at).days
            if age_days > self.window_days:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        finding_class=FindingClass.ORPHANED,
                        severity=score(impact=1, exposure=1),
                        subject_type="agent",
                        subject_id=agent.id,
                        title=f"Agent '{agent.name}' has had no activity in {age_days} days",
                        explanation=(
                            f"'{agent.name}' last showed activity {age_days} days ago, "
                            f"beyond the configured {self.window_days}-day window. It may "
                            "be dead weight still holding credentials and permissions."
                        ),
                        recommended_action="Confirm with the owner whether this agent is still needed.",
                        evidence={"age_days": age_days, "window_days": self.window_days},
                    )
                )
        return findings


class CredentialNoOwnerRule(Rule):
    """The Credential-side counterpart to CreatorUnresolvedRule. Every
    other orphaned-and-abandoned rule up to this point only looked at
    Agent.owner_id — Credential.owner_id existed on the model from the
    start but nothing ever checked it. That gap mattered more once
    connectors that produce credentials with no corresponding native
    agent (anthropic.py's API keys/service accounts, splunk.py's HEC
    tokens, servicenow's integration_accounts.py) existed: an
    unattributed API key with standing access is exactly the same
    "no one accountable for this" risk as an unattributed agent, and
    deserves the same rule, not a gap where the object type happens to
    be Credential instead of Agent."""

    rule_id = "orphaned.credential_no_owner"

    def evaluate(self, inventory: Inventory, config: SeverityConfig) -> list[Finding]:
        findings = []
        # De-duplicated against UnattributedIntegrationAccountRule, but
        # only where the two rules genuinely say the same thing.
        # An earlier pass skipped integration accounts here to cut
        # duplicate findings, which was defensible on volume but went one
        # step too far: this rule then became structurally unable to
        # report its single most important case, an API-only account that
        # nobody owns. The two rules also say genuinely different things —
        # "nobody is accountable for this identity" versus "nothing in the
        # scan explains what uses it" — with different remediations.
        #
        # The distinction that matters:
        #   * No creator recorded at all — the unattributed rule already
        #     reports it, scores on ownership, and gives the remediation
        #     specific to that population. A second finding adds nothing.
        #   * A creator WAS recorded and could not be resolved (the
        #     `unresolved:` placeholder) — that is positive evidence that
        #     someone built this and is now gone, a strictly stronger
        #     orphan signal than an empty field, and exactly the case
        #     this rule exists for. An earlier pass skipped it too, which
        #     made this rule structurally unable to report its single
        #     most important case.
        placeholder_owners = {
            o.id for o in inventory.owners
            if not is_resolved_owner(o.id)
        }
        for cred in inventory.credentials:
            # is_resolved_owner, not a None-check: a synthesized
            # `unresolved:<username>` placeholder is the ABSENCE of an
            # owner wearing an owner's shape.
            if is_resolved_owner(cred.owner_id):
                continue
            if (
                cred.source == INTEGRATION_ACCOUNT_SOURCE
                and cred.owner_id not in placeholder_owners
                and cred.is_disabled is not True
                and cred.id not in {t.credential_id for t in inventory.tools if t.credential_id}
            ):
                continue

            # Scored against severity.py's OWN documented exposure scale
            # instead of a hardcoded 3. That scale reads:
            #   2 = orphaned OR no audit logging OR no owner — ONE hard signal
            #   3 = orphaned AND no audit logging AND no owner — COMPOUNDING
            # "No resolvable owner" is one hard signal, so it is a 2. It was
            # pinned at 3, which made every ownerless credential CRITICAL —
            # 100 of them on a fake instance with 200 ordinary API-only
            # accounts, drowning two real LLM integrations.
            #
            # Compounding signals still reach 3, which is the point of having
            # a scale: a credential with no owner AND no audit logging is
            # genuinely worse than one with only the first.
            compounding = cred.has_audit_logging is False
            exposure = 3 if compounding else 2

            # A credential the platform says cannot authenticate is a
            # cleanup task, not a standing risk. Still REPORTED (is_disabled
            # is None on connectors that can't determine it, and None must
            # never be read as "enabled"), just not at the severity of a
            # live one. Previously a disabled Splunk HEC token with no owner
            # scored CRITICAL identically to a live one, because `_disabled`
            # was computed, stored in raw, and read by nothing.
            if cred.is_disabled:
                exposure = max(0, exposure - 1)

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    finding_class=FindingClass.ORPHANED,
                    severity=score(impact=2, exposure=exposure, confidence=cred.confidence),
                    subject_type="credential",
                    subject_id=cred.id,
                    title=f"Credential '{cred.name}' has no resolvable owner",
                    explanation=(
                        f"'{cred.name}' has standing access to whatever it authenticates "
                        "to, and no owner record this scan could resolve. Nobody is "
                        "accountable for rotating, scoping, or revoking it."
                    ),
                    recommended_action=(
                        "Identify who provisioned or is responsible for this credential and "
                        "assign ownership; if nobody can, treat as a priority to rotate or "
                        "revoke."
                    ),
                    confidence=cred.confidence,
                    evidence={
                        "exposure": exposure,
                        "is_disabled": cred.is_disabled,
                        "severity_basis": (
                            "no resolvable owner"
                            + (" + no audit logging (compounding)" if compounding else "")
                            + (" — lowered: platform reports this identity disabled"
                               if cred.is_disabled else "")
                        ),
                    },
                )
            )
        return findings


ORPHANED_RULES = [
    CreatorInactiveRule(),
    CreatorUnresolvedRule(),
    NoRecentActivityRule(),
    CredentialNoOwnerRule(),
]
