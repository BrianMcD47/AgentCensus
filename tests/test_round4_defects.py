"""Round 4 review — failing tests for the defects found this round.

Every test here FAILS against the current tree and describes the
behaviour the report should have. Ordered by the dimension they belong
to in the review report.
"""

from __future__ import annotations

import datetime
from collections import Counter

import pytest

from agentcensus.connectors.servicenow import integration_accounts
from agentcensus.connectors.servicenow import tables as T
from agentcensus.core.models import (
    Agent,
    Confidence,
    Inventory,
    Provenance,
    Severity,
    Tool,
)
from agentcensus.core.redaction import REDACTED, scrub_values
from agentcensus.core.scan import run_scan
from agentcensus.core.severity import SeverityConfig
from tests.servicenow_fakes import FakeClient


def _inv(**kw) -> Inventory:
    return Inventory(
        platform="servicenow", scanned_at=datetime.datetime.now(datetime.timezone.utc), **kw
    )


def _accounts(rows) -> Inventory:
    client = FakeClient({T.USER_TABLE: rows})
    creds, owners = integration_accounts.fetch_integration_accounts(client, [])
    return _inv(credentials=creds, owners=owners)


# --------------------------------------------------------------------
# ACCURACY A1 — an unresolvable owner counted as a resolved one
# --------------------------------------------------------------------

def test_placeholder_owner_is_not_a_resolved_owner():
    """`fetch_owners` manufactures Owner(id='unresolved:<user>',
    status=UNKNOWN) for a creator whose sys_user row could not be read
    (deleted, ACL-filtered, other domain). The credential rules test
    only `owner_id is not None`, so that placeholder reads as ownership.

    Effect: the account is scored MEDIUM instead of HIGH, its evidence
    says "owner resolved — a question for that owner" (false), and
    orphaned.credential_no_owner stops firing altogether.

    CreatorUnresolvedRule on the agent side already gets this right by
    checking `owner.status == OwnerStatus.UNKNOWN`; the credential-side
    rules must do the same.
    """
    row = {
        "sys_id": "svc1", "user_name": "svc.a", "name": "A",
        "web_service_access_only": "true", "locked_out": "false",
        "active": "true", "sys_created_by": "deploybot",  # no sys_user row for this user
    }
    findings, _ = run_scan(_accounts([row]), SeverityConfig())

    unattributed = [f for f in findings if f.rule_id.endswith("unattributed_integration_account")]
    assert len(unattributed) == 1
    assert unattributed[0].evidence["owner_resolved"] is False
    assert unattributed[0].severity == Severity.HIGH
    assert "no resolvable owner" in unattributed[0].evidence["severity_basis"]

    assert any(f.rule_id == "orphaned.credential_no_owner" for f in findings), (
        "a credential whose only owner is an 'unresolved:' placeholder has no "
        "resolvable owner and must still be reported by CredentialNoOwnerRule"
    )


# --------------------------------------------------------------------
# ACCURACY A2 — NEEDS_REVIEW subjects reported as CONFIRMED
# --------------------------------------------------------------------

def test_findings_inherit_subject_confidence():
    """Only the ungoverned.* rules and SensitiveTableAccessRule pass the
    subject's confidence into score()/Finding. Everything else takes the
    CONFIRMED default, so a heuristic keyword-matched shadow agent is
    reported at HIGH with confidence=confirmed — contradicting the same
    HTML report's agent-inventory row (needs_review) and its footer
    ("needs_review findings are ... capped at MEDIUM severity").
    """
    agent = Agent(
        id="si2", name="LegacyGptSummarizer", description=None, owner_id=None,
        tool_ids=["t1"], provenance=Provenance.SYNTHESIZED,
        confidence=Confidence.NEEDS_REVIEW,
        detection_signal="shadow:script_keyword:script_include:openai",
    )
    tool = Tool(
        id="t1", name="inline", description=None, credential_id=None,
        provenance=Provenance.SYNTHESIZED, confidence=Confidence.NEEDS_REVIEW,
    )
    findings, _ = run_scan(_inv(agents=[agent], tools=[tool]), SeverityConfig())

    for finding in findings:
        if finding.subject_id == "si2":
            assert finding.confidence == Confidence.NEEDS_REVIEW, (
                f"{finding.rule_id} reports confidence={finding.confidence.value} "
                "about a needs_review agent"
            )
            assert finding.severity in (
                Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL
            ), f"{finding.rule_id} escaped the documented NEEDS_REVIEW MEDIUM cap"


# --------------------------------------------------------------------
# ACCURACY A3 — construction.missing_description on synthesized agents
# --------------------------------------------------------------------

def test_missing_description_does_not_fire_on_synthesized_agents():
    """shadow.py always constructs its agents with description=None,
    because a Script Include has no description field that means what
    this rule means. The rule then reports, on every shadow agent,
    "has an empty or missing description ... affects model routing
    behavior" — a construction defect in AgentCensus's own synthesis,
    not in the customer's environment, and not actionable.
    """
    agent = Agent(
        id="si1", name="ClaudeTriageHelper", description=None, owner_id="u1",
        provenance=Provenance.SYNTHESIZED, confidence=Confidence.CONFIRMED,
        detection_signal="shadow:script_include_calls_confirmed_tool:X",
    )
    findings, _ = run_scan(_inv(agents=[agent]), SeverityConfig())
    assert not [f for f in findings if f.rule_id == "construction.missing_description"]


# --------------------------------------------------------------------
# ADAPTABILITY B1 — field-level ACL regresses the round-3 volume bug
# --------------------------------------------------------------------

def test_integration_accounts_survive_field_level_acl_on_the_marker_field():
    """The round-3 fix keys off `"web_service_access_only" in cred.raw`.
    `raw` only carries keys ServiceNow actually returned, and
    integration_accounts.py's own docstring records `locked_out` coming
    back silently absent from a live instance under a field-level ACL
    while other fields on the same row returned fine.

    When that happens to `web_service_access_only`, both the
    ShadowCredentialRule skip and the CredentialNoOwnerRule skip stop
    applying, and every ordinary API-only account produces two HIGH
    findings again — including ShadowCredentialRule's "found via OAuth
    entity or REST message inspection", the false claim round 3 removed.

    The marker must not be the presence of a response field. Tag the
    Credential at construction (e.g. raw["_integration_account"] = True)
    where the module already knows what it produced.
    """
    rows = [
        {"sys_id": f"svc{i:03d}", "user_name": f"svc.integration{i:03d}",
         "name": f"I{i}", "locked_out": "false", "active": "true"}
        for i in range(60)
    ]
    findings, _ = run_scan(_accounts(rows), SeverityConfig())
    by_rule = Counter(f.rule_id for f in findings)

    assert by_rule["ungoverned.shadow_credential"] == 0, (
        "ordinary integration accounts must not be described as 'found via OAuth "
        "entity or REST message inspection'"
    )
    assert by_rule["orphaned.credential_no_owner"] == 0, (
        "duplicate of ungoverned.unattributed_integration_account"
    )
    assert Counter(f.severity.value for f in findings)["high"] <= 60


# --------------------------------------------------------------------
# SECURITY / OVER-CORRECTION D1 — credential_id destroyed in the JSON
# --------------------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        '"credential_id": "bap1"',
        '"token_url": "https://instance.service-now.com/oauth_token.do"',
    ],
)
def test_non_secret_keys_containing_a_secret_word_survive(text):
    """`_JSON_PAIR_SECRET_PATTERN` matches any key *containing* a secret
    word, so `_final_scrub` over the serialized report replaces the
    value of `"credential_id"` — a sys_id, and the only representation
    of the tool->credential link in `inventory`. The report then
    contradicts its own `dependency_graph`, which still carries
    `tool:rm1 --runs_as--> credential:bap1`.
    """
    assert scrub_values(text) == text


@pytest.mark.parametrize(
    "text",
    [
        '"api_key": "sk-live-abcdefghijkl"',
        '"anthropic_api_key": "zzzzzzzz"',
        '"client_secret": "shhhhhhh"',
        '"session_token": "abc123def456"',
    ],
)
def test_genuine_json_secret_pairs_are_still_redacted(text):
    """Non-vacuity guard for the fix above."""
    assert REDACTED in scrub_values(text)


def test_prose_mentioning_basic_authentication_is_not_redacted():
    """`_HEADER_SECRET_PATTERN`'s `\\b(?:bearer|basic)\\s+` arm swallows
    the next 8+ word characters whatever they are, so an ordinary
    sentence loses a word."""
    text = "Basic authentication is configured on this REST message"
    assert scrub_values(text) == text
