from agentcensus.connectors.servicenow.llm_providers import load_providers
from agentcensus.connectors.splunk import endpoints
from agentcensus.connectors.splunk.connector import fetch_splunk_inventory
from agentcensus.core.models import Confidence, Provenance
from tests.splunk_fakes import FakeSplunkClient

SAVED_SEARCHES = [
    {
        "name": "Claude Webhook Alert",
        "acl": {"owner": "brian"},
        "content": {
            "actions": "webhook",
            "action.webhook.param.url": "https://api.anthropic.com/v1/messages",
            "search": "index=main",
            "description": "notifies on high severity",
        },
    },
    {
        "name": "OpenAI SPL Search",
        "acl": {"owner": "brian"},
        "content": {"actions": "", "search": "| openaicompletion prompt=foo", "description": ""},
    },
    {
        "name": "Unrelated Search",
        "acl": {"owner": "brian"},
        "content": {"actions": "email", "search": "index=main error", "description": "just an alert"},
    },
]

APPS = [
    {"name": "mcp_server_for_splunk", "content": {"label": "MCP Server for Splunk"}},
    {"name": "unrelated_app", "content": {"label": "Unrelated App"}},
]

HEC_TOKENS = [
    {
        "name": "external_agent_token",
        "acl": {"owner": "brian"},
        # Splunk's real HEC token management endpoint returns the token's
        # actual usable secret in cleartext here — this fixture models
        # that so the redaction fix (_scrub_secrets) has something real
        # to prove itself against.
        "content": {"disabled": "0", "index": "main", "token": "B4F1C2D3-SECRET-VALUE"},
    }
]

USERS = [{"name": "brian", "content": {"realname": "Brian", "email": "brian@example.com", "roles": ["admin"]}}]

DATA = {
    endpoints.SAVED_SEARCHES_ENDPOINT: SAVED_SEARCHES,
    endpoints.APPS_ENDPOINT: APPS,
    endpoints.HEC_TOKENS_ENDPOINT: HEC_TOKENS,
    endpoints.USERS_ENDPOINT: USERS,
}


def test_webhook_alert_confirmed_and_correlated_to_its_tool():
    client = FakeSplunkClient(DATA)
    inv = fetch_splunk_inventory(client, load_providers())

    confirmed = next(a for a in inv.agents if a.name == "Claude Webhook Alert")
    assert confirmed.provenance == Provenance.SYNTHESIZED
    assert confirmed.confidence == Confidence.CONFIRMED
    assert confirmed.owner_id == "brian"
    assert len(confirmed.tool_ids) == 1
    tool = next(t for t in inv.tools if t.id in confirmed.tool_ids)
    assert "Anthropic" in tool.description


def test_spl_keyword_match_needs_review_and_connected_to_placeholder_tool():
    client = FakeSplunkClient(DATA)
    inv = fetch_splunk_inventory(client, load_providers())

    ad_hoc = next(a for a in inv.agents if a.name == "OpenAI SPL Search")
    assert ad_hoc.confidence == Confidence.NEEDS_REVIEW
    assert len(ad_hoc.tool_ids) == 1  # not floating, same fix as shadow.py tier 4


def test_unrelated_search_not_flagged():
    client = FakeSplunkClient(DATA)
    inv = fetch_splunk_inventory(client, load_providers())
    assert not any(a.name == "Unrelated Search" for a in inv.agents)


def test_mcp_app_detected_distinctly_from_llm_provider_app():
    client = FakeSplunkClient(DATA)
    inv = fetch_splunk_inventory(client, load_providers())

    mcp_tool = next(t for t in inv.tools if t.id == "mcp_server_for_splunk")
    assert "MCP" in mcp_tool.description
    assert not any(t.id == "unrelated_app" for t in inv.tools)


def test_hec_tokens_become_native_confirmed_credentials():
    client = FakeSplunkClient(DATA)
    inv = fetch_splunk_inventory(client, load_providers())

    assert len(inv.credentials) == 1
    cred = inv.credentials[0]
    assert cred.id == "external_agent_token"
    assert cred.provenance == Provenance.NATIVE
    assert cred.confidence == Confidence.CONFIRMED
    assert cred.raw["_disabled"] is False


def test_hec_token_owner_resolved_from_acl_owner():
    """HEC token stanzas carry the same acl.owner field saved searches
    already use for agent-owner resolution in this same file — it was
    just never read for HEC credentials, so every one unconditionally
    tripped orphaned.credential_no_owner regardless of whether Splunk
    actually had an owner on record. Second fresh-eyes audit pass."""
    client = FakeSplunkClient(DATA)
    inv = fetch_splunk_inventory(client, load_providers())

    cred = inv.credentials[0]
    assert cred.owner_id == "brian"


def test_hec_token_secret_value_is_never_stored_in_raw():
    """Splunk's real HEC token endpoint returns the token's actual usable
    secret in cleartext — AgentCensus's core guarantee (see Credential's
    docstring in core/models.py) is that it never reads or stores secret
    material, only metadata about a credential. This is the one place in
    the whole project where that guarantee could have silently broken,
    since Splunk's config endpoints have no field-allowlist the way
    ServiceNow's Table API does."""
    client = FakeSplunkClient(DATA)
    inv = fetch_splunk_inventory(client, load_providers())

    cred = inv.credentials[0]
    assert cred.raw.get("token") != "B4F1C2D3-SECRET-VALUE"
    assert "B4F1C2D3-SECRET-VALUE" not in str(cred.raw)
    assert cred.raw["token"] == "<redacted-by-agentcensus>"


def test_degrades_gracefully_when_saved_searches_denied():
    client = FakeSplunkClient(DATA, deny={endpoints.SAVED_SEARCHES_ENDPOINT})
    inv = fetch_splunk_inventory(client, load_providers())

    assert inv.agents == []
    assert any("access denied" in n.lower() for n in inv.scan_notes)
    # apps/HEC/users are independent reads — still populated
    assert len(inv.credentials) == 1


def test_splunk_get_all_continues_past_a_short_nonempty_page():
    """Same bug class as the one found live in the ServiceNow client
    (see test_servicenow_http.py's short-page test): treating a page
    shorter than requested as end-of-data silently truncates everything
    after it. Splunk applies per-user ACL filtering to saved searches
    and other knowledge objects, so a short-but-not-final page is
    available here too. Fixed here before it was ever observed on a
    live Splunk instance, because the ServiceNow case proved the
    reasoning is unsound in general — not that one vendor implements
    paging badly."""
    from unittest.mock import MagicMock, patch

    from agentcensus.connectors.splunk.http import SplunkClient

    def _resp(entries):
        r = MagicMock()
        r.status_code = 200
        r.headers = {}
        r.json.return_value = {"entry": entries}
        r.raise_for_status.side_effect = None
        return r

    page1 = [{"name": f"a{i}"} for i in range(100)]
    page2 = [{"name": f"b{i}"} for i in range(99)]   # one short, NOT the end
    page3 = [{"name": f"c{i}"} for i in range(100)]
    responses = [_resp(page1), _resp(page2), _resp(page3), _resp([])]

    client = SplunkClient(base_url="https://splunk.example.com:8089", token="t")
    with patch("requests.get", side_effect=responses) as mock_get:
        rows = client.get_all("/services/saved/searches")

    assert len(rows) == 299  # 100 + 99 + 100 — not 199
    assert mock_get.call_count == 4


def test_splunk_safe_get_all_reports_truncation_at_the_safety_cap():
    from unittest.mock import MagicMock, patch

    from agentcensus.connectors.splunk.http import SplunkClient

    full = MagicMock()
    full.status_code = 200
    full.headers = {}
    full.json.return_value = {"entry": [{"name": str(i)} for i in range(100)]}
    full.raise_for_status.side_effect = None

    client = SplunkClient(base_url="https://splunk.example.com:8089", token="t", max_records=250)
    with patch("requests.get", return_value=full):
        rows, note = client.safe_get_all("/services/saved/searches")

    assert len(rows) == 250          # capped, not an infinite mock feed
    assert note is not None and "safety cap" in note
