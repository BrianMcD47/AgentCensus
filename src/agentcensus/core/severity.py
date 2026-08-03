"""Severity model.

Design (see project plan section 13, open question 5):

Severity = f(Impact, Exposure), both scored 0-3 by deterministic rule
logic — never by an LLM, never by a free-form heuristic. A rule sets
its own (impact, exposure) pair when it fires; this module turns that
pair into a Severity via a fixed lookup table, then applies one
optional escalation: blast radius from the dependency graph.

Impact — what's the worst this subject can do / enable:
    0  read-only, low sensitivity surface
    1  write access to non-sensitive records
    2  write access to sensitive tables/records, OR irreversible action
       gated by human approval
    3  irreversible action with NO human approval gate, OR credential
       with broad standing access and no scoping

Exposure — how likely is this to actually go wrong / go unnoticed:
    0  actively owned, monitored, audited, recently used
    1  one weak signal (e.g. owner role changed, but still active)
    2  orphaned OR no audit logging OR no owner — one hard signal
    3  orphaned AND no audit logging AND no owner — compounding signals

The base severity is fixed by this table so scans are reproducible.
What IS configurable (see `SeverityConfig`) is which tables/roles count
as "sensitive" for the purposes of Impact scoring — that's an environment
fact, not a judgment call, and rules read it rather than each rule
hardcoding its own list.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agentcensus.core.models import Confidence, Severity

# NEEDS_REVIEW findings are capped here regardless of impact/exposure. A
# heuristic keyword match in a script body is a lead for a human to chase,
# not a confirmed critical risk — see the provenance/confidence design
# note at the top of core/models.py. This is the one deliberate exception
# to "the table is the whole story"; it's still a fixed rule, not a
# judgment call, so it doesn't compromise reproducibility.
_NEEDS_REVIEW_CAP = Severity.MEDIUM

# (impact, exposure) -> Severity. Deliberately a plain table, not a
# formula, so it's auditable at a glance and a PR changing it is a
# one-line diff someone can actually review.
_TABLE: dict[tuple[int, int], Severity] = {
    (3, 3): Severity.CRITICAL,
    (3, 2): Severity.CRITICAL,
    (2, 3): Severity.CRITICAL,
    (3, 1): Severity.HIGH,
    (2, 2): Severity.HIGH,
    (1, 3): Severity.HIGH,
    (3, 0): Severity.MEDIUM,
    (2, 1): Severity.MEDIUM,
    (1, 2): Severity.MEDIUM,
    (0, 3): Severity.MEDIUM,
    (2, 0): Severity.LOW,
    (1, 1): Severity.LOW,
    (0, 2): Severity.LOW,
    (1, 0): Severity.INFORMATIONAL,
    (0, 1): Severity.INFORMATIONAL,
    (0, 0): Severity.INFORMATIONAL,
}


@dataclass
class SeverityConfig:
    """Environment-specific facts, not environment-specific opinions.

    `sensitive_tables` / `sensitive_roles` let a customer tell the
    scanner "this table holds PII/financials/prod creds" so Impact
    scoring reflects their environment. Everything else about how
    severity is computed stays fixed.
    """
    sensitive_tables: set[str] = field(default_factory=set)
    sensitive_roles: set[str] = field(default_factory=set)


_ORDER = [
    Severity.INFORMATIONAL,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


def apply_confidence_cap(severity: Severity, confidence: Confidence) -> Severity:
    """The NEEDS_REVIEW ceiling, as a function rather than an inline
    check, so that EVERY path capable of raising a severity is required
    to route through it.

    It was previously inline in `score()` only. `scan.escalate_findings`
    then raised severity by up to two tiers from blast radius without
    consulting confidence at all — so a NEEDS_REVIEW credential with ten
    dependent agents was capped to MEDIUM at creation and then rendered
    CRITICAL, while the HTML footer told the reader in as many words
    that needs_review findings are "capped at MEDIUM severity, not
    verdicts."

    Fixing that at the escalation call site would have been the same
    too-shallow shape this project keeps repeating: correct for today's
    two callers, wrong the moment a third appears. The cap belongs to
    the severity model, so it lives here and both callers use it."""
    if confidence == Confidence.NEEDS_REVIEW and _ORDER.index(severity) > _ORDER.index(_NEEDS_REVIEW_CAP):
        return _NEEDS_REVIEW_CAP
    return severity


def score(impact: int, exposure: int, confidence: Confidence = Confidence.CONFIRMED) -> Severity:
    impact = max(0, min(3, impact))
    exposure = max(0, min(3, exposure))
    return apply_confidence_cap(_TABLE[(impact, exposure)], confidence)


def escalate_for_blast_radius(base: Severity, downstream_count: int) -> Severity:
    """A LOW/INFORMATIONAL finding on a credential or tool with a large
    number of dependent agents (per the dependency graph) gets bumped —
    the finding itself may be mundane, but what breaks if it's ignored
    is not. This is the one place graph structure feeds back into
    severity; it never lowers a severity, only raises it, and only by
    one tier at a time.
    """
    if downstream_count >= 10:
        bump = 2
    elif downstream_count >= 3:
        bump = 1
    else:
        bump = 0
    idx = min(_ORDER.index(base) + bump, len(_ORDER) - 1)
    return _ORDER[idx]
