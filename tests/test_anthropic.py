from agentcensus.connectors.anthropic.connector import fetch_anthropic_inventory
from agentcensus.core.models import Confidence, OwnerStatus, Provenance
from agentcensus.core.rules import default_engine
from agentcensus.core.severity import SeverityConfig
from tests.anthropic_fakes import FakeAnthropicClient

USERS = [
    {"id": "user_1", "name": "Brian", "email": "brian@example.com", "role": "admin"},
    {"id": "user_2", "name": "Casey", "email": "casey@example.com", "role": "developer"},
]

API_KEYS = [
    {"id": "apikey_1", "name": "prod-key", "status": "active", "created_by": {"id": "user_1"}, "expires_at": None},
    # created_by references a user_id not present in USERS -> unresolved owner
    {"id": "apikey_2", "name": "orphan-key", "status": "active", "created_by": {"id": "user_999"}, "expires_at": None},
]

SERVICE_ACCOUNTS = [{"id": "svac_1", "name": "ci-bot"}]

DATA = {"/users": USERS, "/api_keys": API_KEYS, "/service_accounts": SERVICE_ACCOUNTS}


def test_api_keys_become_credentials_with_owner_resolved_from_created_by():
    client = FakeAnthropicClient(DATA)
    inv = fetch_anthropic_inventory(client)

    assert len(inv.credentials) == 2  # api keys only, no oauth token -> no service accounts
    assert inv.agents == []  # deliberately never synthesized — see module docstring

    prod_key = next(c for c in inv.credentials if c.id == "apikey_1")
    assert prod_key.owner_id == "user_1"
    assert prod_key.provenance == Provenance.NATIVE
    assert prod_key.confidence == Confidence.CONFIRMED
    assert prod_key.provider == "anthropic"

    orphan_key = next(c for c in inv.credentials if c.id == "apikey_2")
    assert orphan_key.owner_id is None  # user_999 doesn't resolve to any known member

    # every returned member is ACTIVE — this connector has no verified way
    # to detect a deactivated/removed member (see _owner_from_member's
    # docstring), so it says so honestly rather than guessing
    assert all(o.status == OwnerStatus.ACTIVE for o in inv.owners)

    assert any("Service account" in n and "skipped" in n for n in inv.scan_notes)


def test_service_accounts_included_only_with_oauth_token():
    client = FakeAnthropicClient(DATA, oauth_token="fake-oauth-token")
    inv = fetch_anthropic_inventory(client)

    assert len(inv.credentials) == 3
    svc = next(c for c in inv.credentials if c.id == "svac_1")
    assert svc.raw["_is_service_account"] is True


def test_degrades_gracefully_when_api_keys_endpoint_denied():
    client = FakeAnthropicClient(DATA, deny={"/api_keys"})
    inv = fetch_anthropic_inventory(client)

    assert inv.credentials == []
    assert any("access denied" in n.lower() for n in inv.scan_notes)
    # /users still succeeded independently — one denied endpoint doesn't
    # take down the rest of the scan
    assert len(inv.owners) == 2


def test_orphaned_credential_rule_fires_for_unattributed_api_key_only():
    client = FakeAnthropicClient(DATA)
    inv = fetch_anthropic_inventory(client)

    findings = default_engine().run(inv, SeverityConfig())
    hits = {f.subject_id for f in findings if f.rule_id == "orphaned.credential_no_owner"}

    assert "apikey_2" in hits
    assert "apikey_1" not in hits
