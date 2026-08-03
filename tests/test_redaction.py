"""Mechanical stops for the secret-handling guarantees.

The most important test in this file is
`test_a_hardcoded_key_in_a_scanned_script_never_reaches_the_report`.
It exists because the failure it guards against was REAL, found by
reading an actual report generated from an actual instance: the full
source of every matched Script Include, Business Rule, Scheduled Job,
and Scripted REST API resource was being written verbatim into the
JSON, system prompts and all.

That's not a cosmetic leak. The population this tool flags is, by
construction, the ungoverned integrations nobody reviewed — which
makes them the likeliest place on the whole instance to find a
hardcoded API key. Publishing their source into a report designed to
be handed to an auditor turns the scanner into a credential
exfiltration path aimed precisely at the highest-risk scripts it just
identified.

The pre-existing `test_no_secret_fields.py` did not catch this and
could not have: it checks field NAMES against a forbidden-substring
list, and `script` contains no forbidden substring. A field-name
allowlist is the wrong instrument for a field whose *contents* are
arbitrary. Hence this file, which tests values and end-to-end output.
"""

from __future__ import annotations

import json
import os
import stat

from agentcensus.connectors.servicenow.shadow import fetch_shadow
from agentcensus.core.models import Inventory
from agentcensus.core.redaction import REDACTED, scrub, scrub_values
from agentcensus.core.report import to_json, write_json
from tests.servicenow_fakes import FakeClient

# A key-shaped literal unique enough that finding it anywhere in the
# output is unambiguous proof of a leak, not a coincidental substring.
_PLANTED_KEY = "sk-ant-api03-UNIQUEMARKER9182736455647382910abcdefZZ"


def test_scrub_values_redacts_known_provider_key_shapes():
    for secret in [
        _PLANTED_KEY,
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "xoxb-1234567890-abcdefghijkl",
        "gsk_abcdefghijklmnopqrstuvwxyz01",
    ]:
        assert secret not in scrub_values(f"var k = {secret} // trailing")


def test_scrub_values_leaves_ordinary_identifiers_alone():
    """A ServiceNow sys_id is 32 hex chars and would trip almost any
    entropy-based secret heuristic. Redacting them would destroy the
    report — every finding is keyed by one. This is the concrete reason
    redaction.py uses documented key prefixes rather than entropy."""
    text = "sys_id 6bb871dbc3164310f4a9d075e4013151 and https://api.anthropic.com/v1/messages"
    assert scrub_values(text) == text


def test_scrub_values_redacts_credentials_embedded_in_urls():
    scrubbed = scrub_values("https://gw.corp/v1/chat?api_key=SUPERSECRET123&model=gpt-4")
    assert "SUPERSECRET123" not in scrubbed
    assert "model=gpt-4" in scrubbed          # non-secret params survive
    assert "gw.corp" in scrubbed              # host survives — tier 2 needs it

    netloc = scrub_values("https://admin:hunter2@internal.example.com/v1")
    assert "hunter2" not in netloc
    assert "internal.example.com" in netloc


def test_scrub_redacts_by_key_name_and_recurses():
    out = scrub({"name": "ok", "token": "live-secret", "nested": {"client_secret": "x"}})
    assert out["name"] == "ok"
    assert out["token"] == REDACTED
    assert out["nested"]["client_secret"] == REDACTED


def _instance_with_planted_secret():
    """A Script Include that both matches an LLM keyword (so it gets
    detected) and contains a hardcoded key (so we can prove the key
    doesn't survive detection)."""
    script = (
        "var ClaudeThing = Class.create();\n"
        f"var ANTHROPIC_KEY = '{_PLANTED_KEY}';\n"
        "// calls anthropic api\n"
        "request.setEndpoint('https://api.anthropic.com/v1/messages');\n"
    )
    return FakeClient(
        {
            "sys_script_include": [
                {
                    "sys_id": "abc123",
                    "name": "ClaudeThing",
                    "script": script,
                    "active": "true",
                    "access": "package_private",
                    "sys_created_by": "admin",
                }
            ]
        }
    )


def test_a_hardcoded_key_in_a_scanned_script_never_reaches_the_report():
    """End-to-end: a real secret goes in via a scanned script and the
    full serialized report comes out the other side. Mirrors the
    equivalent Splunk HEC-token test in test_no_secret_fields.py, for
    the connector that didn't have one."""
    client = _instance_with_planted_secret()
    agents, tools, creds, owners, notes = fetch_shadow(client, include_script_scan=True)

    inv = Inventory(platform="servicenow", scanned_at=None, agents=agents, tools=tools,
                    credentials=creds, owners=owners, scan_notes=notes)
    raw_json = to_json(inv, findings=[])

    assert _PLANTED_KEY not in raw_json
    # Not vacuous: the agent really was detected, so this test is
    # exercising the leak path rather than an empty scan.
    assert any(a.name == "ClaudeThing" for a in agents)


def test_script_body_is_never_stored_even_without_a_secret_in_it():
    """Redaction is the second line of defense, not the first. Script
    source is dropped wholesale — proprietary logic and system prompts
    are not ours to publish either, and no pattern list would catch a
    bespoke internal token format anyway."""
    client = _instance_with_planted_secret()
    agents, *_ = fetch_shadow(client, include_script_scan=True)
    raw = agents[0].raw

    assert "script" not in raw
    assert "var ClaudeThing" not in json.dumps(raw)
    # What replaces it is enough to diff scans over time.
    assert len(raw["script_sha256"]) == 64
    assert raw["script_length"] > 0
    assert raw["script_excerpt_included"] is False


def test_opt_in_excerpt_is_included_but_still_scrubbed():
    client = _instance_with_planted_secret()
    agents, *_ = fetch_shadow(client, include_script_scan=True, include_script_excerpts=True)
    raw = agents[0].raw

    assert raw["script_excerpt_included"] is True
    assert "script_excerpt" in raw
    assert _PLANTED_KEY not in json.dumps(raw)


def test_report_file_is_written_owner_readable_only(tmp_path):
    """The report maps every ungoverned integration, its owner, and its
    blast radius. Scans routinely run on a shared jump host where the
    default 0644 would expose that to every local account."""
    out = tmp_path / "report.json"
    inv = Inventory(platform="servicenow", scanned_at=None)
    write_json(inv, findings=[], path=out)

    mode = stat.S_IMODE(os.stat(out).st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_scan_notes_are_in_the_written_report():
    """Coverage gaps have to travel with the artifact. Notes recording
    denied tables, skipped tiers, and cap truncation used to exist only
    as CLI stdout, so anyone reading the file had no way to know the
    counts understated reality."""
    inv = Inventory(
        platform="servicenow", scanned_at=None,
        scan_notes=["Access denied reading 'sys_script' — the scan credential lacks read access."],
    )
    payload = json.loads(to_json(inv, findings=[]))
    assert "sys_script" in json.dumps(payload["scan_notes"])


def test_no_planted_secret_survives_any_field_of_either_output_format():
    """The adversarial catch-all. Plants a differently-shaped secret in
    every field a ServiceNow scan touches — script body, REST endpoint
    query string, encrypted property, an assignment with a bespoke
    (non-prefix-matching) value, a JWT — and asserts none of them
    survive into either output format, with script excerpts turned ON
    (the most permissive configuration available).

    This test found a real leak the per-field scrubbing missed: tier 2
    scrubbed its `raw` blob correctly but built a human-readable
    `description` from the same unscrubbed endpoint, so a `?api_key=`
    reached both outputs through a field nobody classified as
    sensitive. That's the argument for `report._final_scrub` existing
    at all — a per-call-site guard only covers the fields its author
    remembered, and the failure mode is silent.
    """
    import datetime

    from agentcensus.connectors.servicenow.config_surfaces import fetch_config_surfaces
    from agentcensus.connectors.servicenow.llm_providers import load_providers
    from agentcensus.core.report import render_html
    from agentcensus.core.scan import run_scan

    canaries = {
        "in_script": "sk-ant-api03-CANARYAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "aws_key": "AKIAIOSFODNN7CANARY",
        "url_query_param": "CANARYURLPARAMSECRET",
        "encrypted_property": "sk-ant-api03-CANARYBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "bespoke_assignment": "CANARYINTERNALTOKENFORMAT",
        "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJDQU5BUlkifQ.QUJDREVGR0hJSktMTU5P",
    }
    client = FakeClient({
        "sys_script_include": [{
            "sys_id": "a1", "name": "Bot", "sys_created_by": "admin",
            "script": (
                f"var k='{canaries['in_script']}';"
                f"var aws='{canaries['aws_key']}';"
                f"var password = '{canaries['bespoke_assignment']}';"
                f"var t='{canaries['jwt']}'; // anthropic"
            ),
        }],
        "sys_rest_message": [{
            "sys_id": "r1", "name": "LLM", "sys_created_by": "admin",
            "rest_endpoint": f"https://api.openai.com/v1?api_key={canaries['url_query_param']}",
        }],
        "sys_properties": [{
            "sys_id": "p1", "name": "x.key", "type": "password",
            "value": canaries["encrypted_property"],
        }],
    })

    agents, tools, creds, owners, notes = fetch_shadow(
        client, include_script_scan=True, include_script_excerpts=True
    )
    config_tools, config_notes = fetch_config_surfaces(client, load_providers())
    inv = Inventory(
        platform="servicenow",
        scanned_at=datetime.datetime.now(datetime.timezone.utc),
        agents=agents, tools=tools + config_tools, credentials=creds, owners=owners,
        scan_notes=notes + config_notes,
    )
    findings, graph = run_scan(inv)

    json_out = to_json(inv, findings, graph)
    html_out = render_html(inv, findings, graph)

    leaked = {
        name: secret for name, secret in canaries.items()
        if secret in json_out or secret in html_out
    }
    assert not leaked, f"secrets survived into the report: {sorted(leaked)}"

    # Not vacuous on two counts: the scan really ran, and redaction
    # preserved the evidence a reviewer needs (the host) while removing
    # only the credential.
    assert json.loads(json_out)["counts"]["agents"] >= 1
    assert "api.openai.com" in json_out
    assert REDACTED in json_out
