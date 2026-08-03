"""Ungoverned integration (project plan section 1's headline stat, made
into a finding class of its own: agents/tools/credentials AgentCensus
found by inference, not by reading a native governance table).

Every finding here fires off `provenance == SYNTHESIZED` on the subject
and passes the subject's own `confidence` straight into `severity.score`
— see core/severity.py for why NEEDS_REVIEW gets capped at MEDIUM
regardless of impact/exposure. A CONFIRMED shadow finding (a real
outbound REST message to a known LLM host) is treated exactly as
seriously as a native one; a NEEDS_REVIEW finding (a keyword match) is
a lead, not a verdict.
"""

from __future__ import annotations

from agentcensus.core.models import (
    Finding,
    FindingClass,
    Inventory,
    Provenance,
    is_resolved_owner,
)
from agentcensus.core.rules import Rule
from agentcensus.core.severity import SeverityConfig, score

# Kept as a literal rather than importing the connector, so core rules
# stay platform-agnostic (see core/connector.py). The producer sets the
# same string; a mismatch is caught by test_round4_defects.py.
INTEGRATION_ACCOUNT_SOURCE = "servicenow.integration_accounts"


class ShadowAgentRule(Rule):
    rule_id = "ungoverned.shadow_agent"

    def evaluate(self, inventory: Inventory, config: SeverityConfig) -> list[Finding]:
        findings = []
        for agent in inventory.agents:
            if agent.provenance != Provenance.SYNTHESIZED:
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    finding_class=FindingClass.UNGOVERNED,
                    severity=score(impact=2, exposure=2, confidence=agent.confidence),
                    subject_type="agent",
                    subject_id=agent.id,
                    title=f"'{agent.name}' appears to be an LLM integration with no native governance record",
                    explanation=(
                        f"AgentCensus inferred '{agent.name}' is an agentic integration "
                        f"from platform artifacts ({agent.detection_signal}), not from any "
                        "native 'AI agent' table. It won't show up in whatever governance "
                        "surface this platform ships, because that surface doesn't know it "
                        "exists."
                    ),
                    recommended_action=(
                        "Verify this is a real integration, then register it properly "
                        "(native agent registry if one exists, or at minimum document "
                        "owner, purpose, and credential) so it's visible to governance."
                    ),
                    confidence=agent.confidence,
                    evidence={"detection_signal": agent.detection_signal},
                )
            )
        return findings


class ShadowToolRule(Rule):
    rule_id = "ungoverned.shadow_tool"

    def evaluate(self, inventory: Inventory, config: SeverityConfig) -> list[Finding]:
        findings = []
        for tool in inventory.tools:
            if tool.provenance != Provenance.SYNTHESIZED:
                continue
            direction_note = {
                "outbound": "calls out to an external LLM provider",
                "inbound": "may expose a tool/MCP surface to external callers",
            }.get(tool.direction, "has an unclear call direction")
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    finding_class=FindingClass.UNGOVERNED,
                    severity=score(impact=2, exposure=1, confidence=tool.confidence),
                    subject_type="tool",
                    subject_id=tool.id,
                    title=f"'{tool.name}' {direction_note}, outside any native tool registry",
                    explanation=tool.description or "",
                    recommended_action=(
                        "Confirm intent and ownership. If this is a legitimate integration, "
                        "document it; if it's forgotten scaffolding, decommission it."
                    ),
                    confidence=tool.confidence,
                    evidence={"direction": tool.direction},
                )
            )
        return findings


class ShadowCredentialRule(Rule):
    rule_id = "ungoverned.shadow_credential"

    def evaluate(self, inventory: Inventory, config: SeverityConfig) -> list[Finding]:
        findings = []
        for cred in inventory.credentials:
            if cred.provenance != Provenance.SYNTHESIZED:
                continue
            # Integration accounts belong to UnattributedIntegrationAccountRule,
            # which is written for that population and describes it accurately.
            # Without this skip, every API-only sys_user produced TWO HIGH
            # findings: this one and that one. On a fake instance with 200
            # such accounts (unremarkable for an enterprise — MID servers,
            # spokes, monitoring, ITOM discovery) that was 405 HIGH findings,
            # of which 11 concerned anything AI-related. A report a governance
            # lead cannot triage is not a governance report.
            #
            # It also removed a false claim: the title and explanation below
            # say "authenticates to an external provider", "found via OAuth
            # entity or REST message inspection". integration_accounts.py
            # deliberately sets provider=None and reads sys_user. Neither
            # sentence was true of those rows.
            if cred.source == INTEGRATION_ACCOUNT_SOURCE:
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    finding_class=FindingClass.UNGOVERNED,
                    severity=score(impact=2, exposure=2, confidence=cred.confidence),
                    subject_type="credential",
                    subject_id=cred.id,
                    title=f"Credential '{cred.name}' authenticates to {cred.provider or 'an external provider'}, outside native governance",
                    explanation=(
                        "This credential was found via OAuth entity or REST message "
                        "inspection, not a native credential registry. AgentCensus never "
                        "reads the secret value itself — only that the credential exists "
                        "and what it appears to authenticate to."
                    ),
                    recommended_action="Confirm ownership, rotate if unclear, and bring under normal credential governance.",
                    confidence=cred.confidence,
                    evidence={"provider": cred.provider},
                )
            )
        return findings


class UnattributedIntegrationAccountRule(Rule):
    """The provider-agnostic catch-all — see connectors/servicenow/
    integration_accounts.py's module docstring for the full reasoning.
    Only looks at credentials that module produced (marked by
    `web_service_access_only` being present in `raw`), and only fires
    for the ones nothing ELSE in this scan can explain: not locked out
    (still active), and not referenced by any tool's credential_id.
    That combination is the closest a single-platform scan can get to
    seeing an external agent — on any platform, including one this
    project has no connector for at all — that authenticates in and
    leaves no other trace."""

    rule_id = "ungoverned.unattributed_integration_account"

    def evaluate(self, inventory: Inventory, config: SeverityConfig) -> list[Finding]:
        referenced_cred_ids = {t.credential_id for t in inventory.tools if t.credential_id}
        findings = []
        for cred in inventory.credentials:
            if cred.source != INTEGRATION_ACCOUNT_SOURCE:
                continue
            # Reads the normalised model field rather than ServiceNow's
            # private `_locked_out` raw key, so the same rule works for
            # Splunk's `_disabled` and any future connector. `is True`,
            # not truthiness: None means "not determined" and must keep
            # the finding, since suppressing a lead is worse than
            # surfacing one.
            if cred.is_disabled is True:
                continue
            if cred.id in referenced_cred_ids:
                continue

            # Exposure reflects what is actually KNOWN about this account,
            # rather than being hardcoded. `owner_resolved` was already
            # computed here and then thrown into evidence unused, while
            # every account — owned or not — scored HIGH.
            #
            # That is the difference between a lead and a finding. An
            # API-only account nobody owns, that nothing references, is a
            # genuine HIGH: there is no one to ask what it does. The same
            # account with a resolvable, active owner is a question for
            # that owner, not an incident. An enterprise has hundreds of
            # the second kind (MID servers, spokes, monitoring, discovery)
            # and flagging them all HIGH buries the first kind.
            #
            # Impact stays 2: an API-only identity that can authenticate is
            # a real capability regardless of who owns it.
            owner_resolved = is_resolved_owner(cred.owner_id)
            exposure = 1 if owner_resolved else 2

            # A ServiceNow-shipped account with no scan-visible consumer
            # is expected, not alarming: the platform created it, ships
            # it on every instance, and the customer often cannot remove
            # it. Measured live, ten of these dominated a stock PDI's
            # report at HIGH.
            #
            # Lowered, not suppressed — a shipped account can still be
            # abused or repurposed, and silently dropping it is the
            # over-correction failure this project keeps hitting.
            if cred.is_platform_shipped:
                exposure = max(0, exposure - 1)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    finding_class=FindingClass.UNGOVERNED,
                    severity=score(impact=2, exposure=exposure, confidence=cred.confidence),
                    subject_type="credential",
                    subject_id=cred.id,
                    title=f"Integration account '{cred.name}' is active with no scan-visible consumer",
                    explanation=(
                        f"'{cred.name}' is configured for API-only access "
                        "(web_service_access_only) and is not locked out, but nothing else "
                        "in this scan — no REST message, no Scripted REST API, no Script "
                        "Include/Business Rule/Scheduled Job, no Flow — references it. "
                        "Something authenticates as this identity; this scan cannot tell "
                        "you what, only that no governed record here explains it. That "
                        "includes agents built on other platforms entirely (Splunk, a "
                        "homegrown script, something running on Anthropic's own "
                        "infrastructure) that this connector has no visibility into beyond "
                        "the credential they authenticate with."
                    ),
                    recommended_action=(
                        "Identify what actually calls in as this account (check access "
                        "logs, not just this scan) and document it. If nothing does, "
                        "disable the account."
                    ),
                    confidence=cred.confidence,
                    evidence={
                        "owner_resolved": owner_resolved,
                        # Named explicitly so a reader can see WHY two
                        # otherwise-identical findings scored differently,
                        # rather than having to infer it from the table in
                        # severity.py.
                        "platform_shipped": cred.is_platform_shipped,
                        "severity_basis": (
                            (
                                "owner resolved — a question for that owner"
                                if owner_resolved
                                else "no resolvable owner — nobody to ask what this does"
                            )
                            + (
                                "; lowered: ServiceNow ships this account on every "
                                "instance, so its presence is expected"
                                if cred.is_platform_shipped
                                else ""
                            )
                        ),
                    },
                )
            )
        return findings


UNGOVERNED_RULES = [
    ShadowAgentRule(),
    ShadowToolRule(),
    ShadowCredentialRule(),
    UnattributedIntegrationAccountRule(),
]
