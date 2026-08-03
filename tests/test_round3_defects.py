"""Regression tests for the round-3 independent review (defects A-F).

The review shipped its own test files; they did not reach this repo, so
these were written from its written reproductions. Each one fails on the
pre-fix code and states the concrete harm rather than the mechanism.

Every test here carries a NON-VACUITY assertion — that the scan still
detects what it should, and that legitimate content survives. Three of
the six defects are over-correction in the opposite direction
(over-redaction, over-exclusion, hardcoded severity burying real
findings), and this codebase's thinnest coverage has consistently been
against destroying findings rather than missing them.
"""

from __future__ import annotations

import datetime
import json
import subprocess
import sys
import textwrap

from agentcensus.core.models import (
    AccountType,
    Confidence,
    Credential,
    Finding,
    FindingClass,
    Inventory,
    Provenance,
    Severity,
    Tool,
)
from agentcensus.core.redaction import REDACTED, scrub_values
from agentcensus.core.scan import escalate_findings, run_scan
from tests.servicenow_fakes import FakeClient

_TOK = "corp_tok_9f3a1c2d4e5f6a7b8c9d"


# --------------------------------------------------------------------------
# E — a hardcoded bearer token reached the report
# --------------------------------------------------------------------------

def test_bearer_and_header_credentials_are_redacted():
    """`_ASSIGNED_SECRET_PATTERN` listed `bearer` among its names, so it
    read as covered — but it requires `[:=]` between the name and the
    value, i.e. `bearer = "X"`, which nobody writes. The two forms that
    appear in real ServiceNow script are a space (`Bearer <tok>`) and an
    argument boundary (`setRequestHeader('x-api-key', '<tok>')`), and
    neither has a `[:=]`. The pattern never fired on either.

    This shipped under `--include-script-excerpts`, whose documented
    contract is that excerpts are secret-scrubbed."""
    for src in [
        f"r.setRequestHeader('Authorization', 'Bearer {_TOK}');",
        f"r.setRequestHeader('x-api-key', '{_TOK}');",
        f"Authorization: Bearer {_TOK}",
    ]:
        out = scrub_values(src)
        assert _TOK not in out, f"leaked: {src}"
        # The label survives, so the reader still learns a hardcoded
        # credential is present — itself the finding worth acting on.
        assert REDACTED in out


def test_json_serialized_secret_pairs_are_redacted():
    """After `json.dumps`, a secret-named field is `"api_key": "X"` — the
    key's own closing quote sits exactly where the assignment pattern
    requires `\\s*[:=]\\s*`, so that pattern is structurally incapable of
    matching anything `_final_scrub` backstops."""
    blob = json.dumps({"name": "ok", "api_key": _TOK, "nested": {"client_secret": _TOK}})
    out = scrub_values(blob)
    assert _TOK not in out
    assert json.loads(out)["name"] == "ok"          # structure intact


def test_assignment_forms_that_already_worked_still_work():
    """Control. A new pattern must not break the four forms round 1 and 2
    established, and must not start redacting ordinary content."""
    for src in [f'var apiKey = "{_TOK}";', f"var token = '{_TOK}';"]:
        assert _TOK not in scrub_values(src)

    for benign in [
        "https://api.anthropic.com/v1/messages?model=claude-3-5-sonnet&max_tokens=1024",
        "sys_id 6bb871dbc3164310f4a9d075e4013151",
        "https://x/api/now/table/incident?sysparm_query=number=INC0010001",
        'var greeting = "hello world";',
    ]:
        assert scrub_values(benign) == benign, f"over-redacted: {benign}"


# --------------------------------------------------------------------------
# A — the NEEDS_REVIEW severity cap did not survive blast-radius escalation
# --------------------------------------------------------------------------

def _needs_review_finding(severity=Severity.MEDIUM):
    return Finding(
        rule_id="ungoverned.shadow_credential",
        finding_class=FindingClass.UNGOVERNED,
        severity=severity,
        subject_type="credential",
        subject_id="c1",
        title="t",
        explanation="e",
        recommended_action="a",
        confidence=Confidence.NEEDS_REVIEW,
    )


def test_needs_review_cannot_reach_critical_via_blast_radius():
    """`score()` capped NEEDS_REVIEW at MEDIUM; `escalate_findings` then
    raised by up to two tiers without ever consulting confidence. A
    heuristic keyword match with ten dependent agents rendered CRITICAL
    while the HTML footer told the reader, verbatim, that needs_review
    findings are capped at MEDIUM.

    Reachable on an ordinary instance, not just synthetically: one shared
    LLM REST message gives its credential exactly that fan-out."""
    import networkx as nx

    graph = nx.DiGraph()
    graph.add_node("credential:c1", kind="credential")
    for i in range(12):
        graph.add_node(f"agent:a{i}", kind="agent")
        graph.add_edge(f"agent:a{i}", "credential:c1", relation="uses")

    finding = _needs_review_finding()
    escalate_findings([finding], graph)

    assert finding.severity == Severity.MEDIUM
    # The blast radius is still reported — it is the reason to prioritise
    # VERIFYING this finding, so suppressing the number would trade one
    # kind of misinformation for another.
    assert finding.evidence["downstream_agent_count"] == 12
    assert finding.evidence["severity_capped_by_confidence"] is True
    assert finding.evidence["severity_if_confirmed"] == "critical"


def test_confirmed_findings_still_escalate():
    """Control: the cap must not disable escalation generally."""
    import networkx as nx

    graph = nx.DiGraph()
    graph.add_node("credential:c1", kind="credential")
    for i in range(12):
        graph.add_node(f"agent:a{i}", kind="agent")
        graph.add_edge(f"agent:a{i}", "credential:c1", relation="uses")

    confirmed = _needs_review_finding()
    confirmed.confidence = Confidence.CONFIRMED
    escalate_findings([confirmed], graph)
    assert confirmed.severity == Severity.CRITICAL


def test_apply_confidence_cap_is_the_shared_choke_point():
    """The cap lives in severity.py rather than at the escalation call
    site on purpose: a local clamp is correct for today's two callers and
    wrong the moment a third appears — the too-shallow shape this project
    keeps repeating."""
    # Imported here rather than at module scope so this file still
    # COLLECTS against pre-fix source, where the function doesn't exist —
    # otherwise one missing symbol masks whether the other twelve tests
    # actually fail, and a regression suite that can't run against the
    # bug it documents proves nothing.
    from agentcensus.core.severity import apply_confidence_cap

    assert apply_confidence_cap(Severity.CRITICAL, Confidence.NEEDS_REVIEW) == Severity.MEDIUM
    assert apply_confidence_cap(Severity.CRITICAL, Confidence.CONFIRMED) == Severity.CRITICAL
    assert apply_confidence_cap(Severity.LOW, Confidence.NEEDS_REVIEW) == Severity.LOW


# --------------------------------------------------------------------------
# B — determinism, which a single-process test loop cannot see
# --------------------------------------------------------------------------

_DET_SCRIPT = textwrap.dedent("""
    import sys
    sys.path.insert(0, {root!r})
    from agentcensus.connectors.servicenow.owners import fetch_owners
    from tests.servicenow_fakes import FakeClient
    owners, _ = fetch_owners(FakeClient({{}}, deny={{"sys_user"}}),
                             {{"zoe", "alice", "mike", "bob", "carol"}})
    print("|".join(owners.keys()))
""")


def test_owner_ordering_is_stable_across_hash_seeds(tmp_path):
    """CPython randomises str hashing PER PROCESS, so set-iteration order
    is stable within one interpreter and varies between them. A five-run
    in-process loop passes while the report reorders on every real
    invocation — which is why this test shells out.

    The ordering flows into `inventory.owners` and `dependency_graph.nodes`,
    so scan-to-scan diffing was useless. Worst exactly where it matters
    most: if `sys_user` is ACL-denied, every owner is unresolved and the
    whole section reshuffles."""
    import pathlib

    root = str(pathlib.Path(__file__).resolve().parents[1])
    script = tmp_path / "det.py"
    script.write_text(_DET_SCRIPT.format(root=root))

    outputs = set()
    for seed in range(6):
        result = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True, text=True, env={"PYTHONHASHSEED": str(seed), "PATH": "/usr/bin:/bin"},
        )
        assert result.returncode == 0, result.stderr
        outputs.add(result.stdout.strip())

    assert len(outputs) == 1, f"owner order varies by hash seed: {outputs}"
    # Non-vacuous: the owners really were produced, and sorted.
    assert outputs.pop() == "alice|bob|carol|mike|zoe"


# --------------------------------------------------------------------------
# D — signal-to-noise, and inert credentials scored like live ones
# --------------------------------------------------------------------------

def _integration_account(i: int, *, owned: bool, disabled: bool = False) -> Credential:
    return Credential(
        id=f"u{i}",
        name=f"svc_acct_{i}",
        account_type=AccountType.SCOPED_SERVICE_ACCOUNT,
        owner_id=("owner1" if owned else None),
        provenance=Provenance.SYNTHESIZED,
        confidence=Confidence.CONFIRMED,
        is_disabled=disabled,
        # `source` is DECLARED by the producer, not inferred from the
        # presence of `web_service_access_only` in the wire response.
        # Round 4 showed why: a field-level ACL can drop that field from
        # a row while the rest returns fine, at which point two separate
        # rule skips fail open at once and this whole defect returns.
        # This fixture mirrors the real producer.
        source="servicenow.integration_accounts",
        raw={"web_service_access_only": "true", "_locked_out": disabled},
    )


def test_ordinary_api_accounts_do_not_bury_the_real_findings():
    """Measured before the fix on 200 API-only accounts (unremarkable for
    an enterprise: MID servers, spokes, monitoring, ITOM discovery) plus
    one genuine LLM integration: 416 findings, 405 HIGH, of which 11
    concerned anything AI-related. Each ordinary account produced two
    HIGH findings from two different rules, one of which described it
    with two sentences that were both false of that population.

    A report a governance lead cannot triage is not a governance report."""
    creds = [_integration_account(i, owned=(i % 10 != 0)) for i in range(200)]
    real_tool = Tool(
        id="rm1", name="Anthropic REST", description="Outbound REST message to Anthropic",
        credential_id=None, provenance=Provenance.SYNTHESIZED, confidence=Confidence.CONFIRMED,
        direction="outbound",
    )
    inv = Inventory(
        platform="servicenow", scanned_at=datetime.datetime(2026, 1, 1),
        tools=[real_tool], credentials=creds,
    )
    findings, _graph = run_scan(inv)
    high_plus = [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]

    assert len(high_plus) < 50, f"{len(high_plus)} HIGH+ findings from 200 ordinary accounts"

    # NON-VACUITY, and the whole point: passing by suppressing everything
    # would be the opposite-direction failure. The ownerless accounts —
    # the ones actually worth chasing — must still be HIGH.
    assert high_plus, "over-suppressed: nothing survived"
    ownerless = {f.subject_id for f in high_plus}
    assert "u0" in ownerless, "an account with no resolvable owner must still rank HIGH"

    # And no account is reported twice by two rules for the same fact.
    per_subject = {}
    for f in findings:
        per_subject.setdefault(f.subject_id, set()).add(f.rule_id)
    assert not any(
        {"ungoverned.shadow_credential", "ungoverned.unattributed_integration_account"} <= rules
        for rules in per_subject.values()
    ), "the same credential is reported by both rules"


def test_a_disabled_credential_is_not_scored_like_a_live_one():
    """`_locked_out` was read for ServiceNow; Splunk's `_disabled` and
    Anthropic's key status were computed, stored in `raw`, and read by
    nothing — so a DISABLED HEC token with no owner scored CRITICAL,
    identically to a live one. Normalised onto `Credential.is_disabled`
    rather than teaching every rule three connectors' private raw keys."""
    live = Credential(id="c1", name="live", account_type=AccountType.UNKNOWN, owner_id=None,
                      provenance=Provenance.SYNTHESIZED, is_disabled=False)
    dead = Credential(id="c2", name="dead", account_type=AccountType.UNKNOWN, owner_id=None,
                      provenance=Provenance.SYNTHESIZED, is_disabled=True)
    inv = Inventory(platform="splunk", scanned_at=datetime.datetime(2026, 1, 1),
                    credentials=[live, dead])
    findings, _ = run_scan(inv)

    by_subject = {f.subject_id: f for f in findings if f.rule_id == "orphaned.credential_no_owner"}
    order = [Severity.INFORMATIONAL, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    assert order.index(by_subject["c2"].severity) < order.index(by_subject["c1"].severity)
    # Still REPORTED, not suppressed — a disabled credential is a cleanup
    # task, and `None` (undetermined) must never be read as "enabled".
    assert "c2" in by_subject


# --------------------------------------------------------------------------
# C — two unrelated identities could be merged
# --------------------------------------------------------------------------

def test_a_shared_team_mailbox_does_not_merge_two_service_accounts():
    """`integration_accounts.py` set `correlation_key` from an email,
    which `models.py` explicitly forbids: the key means "same credential",
    and a team mailbox (integrations@corp.com — the ordinary way a service
    account gets an email at all) is shared by many. Two accounts were
    joined by `same_identity_as` edges, so one inherited the other's
    downstream agents, blast radius, and therefore severity.

    `correlate.py` argues at length that a false merge is worse than a
    missed one; this was the only producer of the key, and it invented it."""
    from agentcensus.connectors.servicenow.integration_accounts import (
        fetch_integration_accounts,
    )

    client = FakeClient({
        "sys_user": [
            {"sys_id": "u1", "user_name": "svc_hrbot", "name": "HR Bot", "active": "true",
             "web_service_access_only": "true", "email": "integrations@corp.com"},
            {"sys_id": "u2", "user_name": "svc_payroll", "name": "Payroll", "active": "true",
             "web_service_access_only": "true", "email": "integrations@corp.com"},
        ]
    })
    creds, _owners = fetch_integration_accounts(client, [])
    assert creds, "non-vacuous: the accounts were detected"
    assert all(c.correlation_key is None for c in creds)


def test_a_real_credential_identity_still_merges_case_insensitively():
    """The opposite direction, and the reason not to simply delete the
    feature: `Owner.email` was grouped `.strip().lower()`'d while
    `correlation_key` was grouped raw, so a genuine shared client_id
    differing only in case failed to merge."""
    from agentcensus.core.correlate import merge_and_correlate

    def inv(platform, key):
        return Inventory(
            platform=platform, scanned_at=datetime.datetime(2026, 1, 1),
            credentials=[Credential(id="c1", name="svc", account_type=AccountType.UNKNOWN,
                                    owner_id=None, provenance=Provenance.SYNTHESIZED,
                                    correlation_key=key)],
        )

    _merged, graph = merge_and_correlate(
        [inv("servicenow", "ABC-Client-ID"), inv("splunk", "  abc-client-id ")]
    )
    edges = [e for e in graph.edges(data=True) if e[2].get("relation") == "same_identity_as"]
    assert len(edges) == 2, "a genuine shared credential identity must still merge"


# --------------------------------------------------------------------------
# F — include_inactive reached exactly one detection surface
# --------------------------------------------------------------------------

def test_include_inactive_reaches_every_surface_that_fetches_active():
    """`active` is requested by 16 field lists; only shadow.py's tier 4
    consulted it. An inactive Flow, MCP registration, NASK mapping and
    connection alias were each reported as live, and `--include-inactive`
    could suppress none of them — while its help text said, without
    qualification, "include records marked inactive."

    Asserts both directions: suppressed by default, AND recoverable via
    the flag. Round 1 shipped an exclusion whose documented escape hatch
    did not exist end to end; this is that check."""
    from agentcensus.connectors.servicenow import (
        config_surfaces,
        flow_designer,
        mcp_server,
        nask,
    )
    from agentcensus.connectors.servicenow.llm_providers import load_providers

    providers = load_providers()
    client = FakeClient({
        "sys_hub_flow": [{"sys_id": "f1", "name": "Anthropic Summary Flow",
                          "active": "false", "sys_created_by": "admin"}],
        "auth_server_connection": [{"sys_id": "m1", "name": "MCP Reg",
                                    "active": "false", "sys_created_by": "admin"}],
        "sys_generative_ai_provider_mapping": [{"sys_id": "n1", "name": "NASK map",
                                                "active": "false", "sys_created_by": "admin"}],
        "http_connection": [{"sys_id": "h1", "name": "OpenAI",
                             "connection_url": "https://api.openai.com/v1",
                             "active": "false", "sys_created_by": "admin"}],
    })

    def counts(include_inactive):
        flows, _ft, _fo, _fn = flow_designer.fetch_flow_designer(
            client, providers, include_inactive=include_inactive)
        mcp, _mo, _mn = mcp_server.fetch_mcp_server_console(
            client, include_inactive=include_inactive)
        nsk, _nn = nask.fetch_nask(client, include_inactive=include_inactive)
        # mcp_server is deliberately NOT in this list any more. Its
        # inactive filter was removed: `auth_server_connection` has
        # no `active` column (confirmed from the UI list view — the API
        # denies the table), so the filter could never run and the note it
        # guarded could never print. A surface that cannot filter on
        # activity is not a surface `--include-inactive` reaches.
        cfg, _cn = config_surfaces.fetch_config_surfaces(
            client, providers, include_inactive=include_inactive)
        return (len(flows), len(mcp), len(nsk), len([t for t in cfg if t.name == "OpenAI"]))

    # MCP is 1 in BOTH cases: its inactive filter was removed because
    # `auth_server_connection` has no `active` column, so activity is
    # not a thing this surface can filter on.
    assert counts(False) == (0, 1, 0, 0), "inactive records leaked into the default scan"
    # Non-vacuous, and the check round 1 skipped: the flag actually works.
    assert counts(True) == (1, 1, 1, 1), "the documented escape hatch does not open"


def test_the_cli_exposes_the_flag_the_scan_notes_reference():
    from agentcensus.cli import build_parser

    args = build_parser().parse_args(
        ["scan", "--connector", "servicenow", "--include-inactive"]
    )
    assert args.include_inactive is True
