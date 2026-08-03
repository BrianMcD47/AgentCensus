"""Enforces the 'never read or store secret material' promise
mechanically, instead of relying on every contributor remembering it by
hand — across all three connectors that now exist, each of which
enforces it a different way:

  - ServiceNow (tables.py): the safety model is a hand-picked field
    ALLOWLIST — every table read requests `sysparm_fields=<explicit
    list>`, never `*`, and no list has ever included a field that would
    hold a real secret value. `test_no_table_field_list_requests_a_secret_bearing_field`
    is the mechanical stop against a future PR adding one by accident.

  - Splunk (connector.py): Splunk's config-read REST endpoints have no
    field-projection option the way ServiceNow's Table API does — a GET
    against a saved search, app, or HEC token stanza always returns its
    *entire* content blob, whatever fields that happens to include. The
    safety model here is runtime REDACTION (`_scrub_secrets`) applied to
    every `raw` blob built from Splunk content, confirmed concretely
    against the one known case where it matters: the HEC token
    management endpoint returns the token's actual usable secret value
    in cleartext. `test_splunk_scrub_secrets_redacts_known_secret_shaped_keys`
    is the mechanical stop for this connector.

  - Anthropic (connector.py): no allowlist or redaction step exists here
    because none is needed — the Admin API's own documented behavior
    never returns a usable secret value via any list/get endpoint this
    connector calls. API keys expose a `partial_key_hint` (an
    intentionally masked value, Anthropic's own design), never the full
    key. There is nothing to allowlist or redact because the upstream
    API itself doesn't hand back the thing being protected against. No
    mechanical test is added for this connector for the same reason
    there's no test proving water isn't on fire — but this paragraph is
    the record of that reasoning being deliberate, not an oversight.

Keep the two forbidden-substring lists below in sync in spirit (not
necessarily identical) — if you add a marker to one because a real field
name needed it, consider whether the other connector's model has the
same blind spot.
"""

from __future__ import annotations

import json

from agentcensus.connectors.servicenow import tables
from agentcensus.connectors.servicenow.llm_providers import load_providers
from agentcensus.connectors.splunk import endpoints
from agentcensus.connectors.splunk.connector import (
    _scrub_secrets,
    fetch_splunk_inventory,
)
from agentcensus.core.report import to_json
from tests.splunk_fakes import FakeSplunkClient

_FORBIDDEN_SUBSTRINGS = [
    "secret", "password", "passwd", "private_key", "client_secret", "token", "api_key", "apikey",
]

# Fields that match a forbidden substring but are verified safe to read.
_ALLOWED_EXCEPTIONS: set[str] = set()


def _all_field_lists():
    for name in dir(tables):
        if name.endswith("_FIELDS"):
            yield name, getattr(tables, name)


def test_no_table_field_list_requests_a_secret_bearing_field():
    violations = []
    for list_name, fields in _all_field_lists():
        for field in fields:
            if field in _ALLOWED_EXCEPTIONS:
                continue
            lowered = field.lower()
            if any(bad in lowered for bad in _FORBIDDEN_SUBSTRINGS):
                violations.append(f"{list_name} requests '{field}'")

    assert not violations, (
        "Field list(s) request what looks like a secret-bearing field — "
        "AgentCensus must never read credential values, only metadata "
        "about them:\n" + "\n".join(violations)
    )


def test_splunk_scrub_secrets_redacts_known_secret_shaped_keys():
    content = {
        "token": "B4F1C2D3-real-secret-value",
        "password": "hunter2",
        "session_key": "abcdef123456",
        "index": "main",          # not secret — must survive untouched
        "disabled": "0",          # not secret — must survive untouched
    }
    scrubbed = _scrub_secrets(content)

    assert scrubbed["token"] == "<redacted-by-agentcensus>"
    assert scrubbed["password"] == "<redacted-by-agentcensus>"
    assert scrubbed["session_key"] == "<redacted-by-agentcensus>"
    assert scrubbed["index"] == "main"
    assert scrubbed["disabled"] == "0"
    assert "B4F1C2D3-real-secret-value" not in str(scrubbed)


def test_a_real_secret_never_survives_into_the_written_json_report():
    """End-to-end proof, not just a unit test of `_scrub_secrets` in
    isolation: a HEC token's real secret value goes in one end
    (fetch_splunk_inventory) and the full report JSON (what actually
    gets written to disk by `write_json`/`agentcensus scan`) comes out
    the other — the secret must not survive that whole path anywhere,
    not just in the one field `_scrub_secrets` was written to catch."""
    secret = "B4F1C2D3-a-genuinely-unique-marker-4F2E9A"
    data = {endpoints.HEC_TOKENS_ENDPOINT: [{"name": "tok1", "content": {"token": secret}}]}
    client = FakeSplunkClient(data)

    inv = fetch_splunk_inventory(client, load_providers())
    raw_json = to_json(inv, findings=[])

    assert secret not in raw_json
    # sanity check the test itself isn't vacuous — the token's *name* should
    # still be there, proving this scan actually ran and wasn't just empty
    assert "tok1" in json.loads(raw_json)["inventory"]["credentials"][0]["name"]
