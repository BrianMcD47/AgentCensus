"""Deterministic rule engine.

Hard constraint from the project plan (section 7): detection logic is
rule-based and reproducible. An LLM, if used anywhere in this project,
is confined to summarizing/explaining findings a rule already produced
— never to deciding whether something is a finding. Nothing in this
module or anything it calls should involve model inference.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from agentcensus.core.models import Confidence, Finding, Inventory
from agentcensus.core.severity import SeverityConfig


class Rule(ABC):
    """One detection rule = one finding class member.

    Keep rules small and single-purpose (one rule per bullet in the
    project plan's section 6 is the right grain) rather than folding
    several checks into one rule — it keeps `rule_id` meaningful for
    suppression/config later and keeps each rule's severity rationale
    honest.
    """

    #: stable id, e.g. "orphaned.creator_inactive"
    rule_id: str

    @abstractmethod
    def evaluate(self, inventory: Inventory, config: SeverityConfig) -> list[Finding]:
        raise NotImplementedError


class RuleEngine:
    def __init__(self, rules: list[Rule] | None = None):
        self.rules: list[Rule] = rules or []

    def register(self, rule: Rule) -> None:
        self.rules.append(rule)

    def run(self, inventory: Inventory, config: SeverityConfig | None = None) -> list[Finding]:
        config = config or SeverityConfig()
        findings: list[Finding] = []
        for rule in self.rules:
            findings.extend(rule.evaluate(inventory, config))
        _inherit_subject_confidence(findings, inventory)
        return findings


def _inherit_subject_confidence(findings: list[Finding], inventory: Inventory) -> None:
    """A finding can never be more confident than the thing it is about.

    `Finding.confidence` defaults to CONFIRMED, and only 4 of 12 rules
    passed the subject's confidence through — so a shadow agent detected
    by a bare keyword match was reported at HIGH / `confirmed` in the
    findings table, while the SAME report's agent-inventory row said
    `needs_review` and its footer said needs_review findings are capped
    at MEDIUM. Three contradictory statements about one record in one
    document, which is worse for a reader than any of them being wrong
    alone: it makes the whole artifact untrustworthy.

    Enforced here, once, rather than by adding `confidence=` to ten call
    sites — that fix would be correct today and silently wrong the
    moment an eleventh rule is written, which is the exact shape this
    project keeps rediscovering. Rules stay free to declare a LOWER
    confidence than their subject; they simply cannot claim a higher
    one.

    Severity is then re-capped, because lowering confidence can newly
    trip the NEEDS_REVIEW ceiling.
    """
    from agentcensus.core.severity import apply_confidence_cap

    subjects: dict[tuple[str, str], object] = {}
    for kind, items in (
        ("agent", inventory.agents),
        ("tool", inventory.tools),
        ("credential", inventory.credentials),
    ):
        for item in items:
            subjects[(kind, item.id)] = item

    order = [Confidence.NEEDS_REVIEW, Confidence.CONFIRMED]
    for finding in findings:
        subject = subjects.get((finding.subject_type, finding.subject_id))
        if subject is None:
            continue
        subject_confidence = getattr(subject, "confidence", None)
        if subject_confidence is None:
            continue
        if order.index(subject_confidence) < order.index(finding.confidence):
            finding.confidence = subject_confidence
            finding.severity = apply_confidence_cap(finding.severity, finding.confidence)


def default_engine() -> RuleEngine:
    """Wires up every built-in rule. Import is local to avoid a circular
    import between `rules.py` and the rule modules that import `Rule`
    from here."""
    from agentcensus.rules.access import ACCESS_RULES
    from agentcensus.rules.construction import CONSTRUCTION_RULES
    from agentcensus.rules.orphaned import ORPHANED_RULES
    from agentcensus.rules.redundancy import REDUNDANCY_RULES
    from agentcensus.rules.ungoverned import UNGOVERNED_RULES

    engine = RuleEngine()
    for rule in [
        *ORPHANED_RULES,
        *ACCESS_RULES,
        *CONSTRUCTION_RULES,
        *REDUNDANCY_RULES,
        *UNGOVERNED_RULES,
    ]:
        engine.register(rule)
    return engine
