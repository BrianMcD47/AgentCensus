"""Anthropic connector — the "agent lives on the model provider's own
infrastructure" case named explicitly in scoping: "connecting to
Anthropic externally, and having things like agents and tools be kept
there."

WHAT THIS CAN AND CANNOT SEE, STATED PLAINLY: Anthropic's Admin API is
an organization/workspace/API-key/member management surface, not an
agent registry — Anthropic does not track what its customers build with
an API key. This connector cannot tell you "here is the list of agents
running on Claude." What it CAN tell you: which API keys exist, which
workspace and (best-effort) which human created each one, whether a key
is active or archived, and whether that creator is still a member of the
org. That's real signal — an active, non-expiring API key created by
someone no longer in the organization's member list is exactly the
"orphaned credential with standing access" finding class this project
is built around — but it is a credential/identity inventory, not an
agent inventory. `Agent` objects are deliberately NOT synthesized here;
inventing a fictional agent from an API key would misrepresent what's
actually known.

Read-only, enforced the same way as every other connector: `http.py`
only exposes GET. See its docstring for the two accepted credential
types and what's confirmed vs. inferred about the API shape.
"""

from __future__ import annotations

from datetime import datetime, timezone

from agentcensus.connectors.anthropic.http import AnthropicAdminClient
from agentcensus.core.connector import Connector
from agentcensus.core.models import (
    AccountType,
    Confidence,
    Credential,
    Inventory,
    Owner,
    OwnerStatus,
    Provenance,
)
from agentcensus.core.redaction import scrub


def _owner_from_member(m: dict) -> Owner:
    return Owner(
        id=m.get("id", "unknown"),
        display_name=m.get("name") or m.get("email") or m.get("id", "unknown"),
        # Anthropic's documented organization roles (user, claude_code_user,
        # developer, billing, admin — see http.py's verification-status
        # note) don't include a "removed" or "deactivated" value, and the
        # /organizations/users list endpoint most likely only returns
        # current members in the first place (a removed member probably
        # just stops appearing, rather than appearing with some inactive
        # status). An earlier version of this function checked for a
        # `role == "removed"` sentinel that doesn't correspond to anything
        # Anthropic actually documents — that wasn't a verified signal, it
        # was a guess dressed up as one. Every member returned here is
        # marked ACTIVE honestly, not because inactivity was checked and
        # ruled out, but because this connector has no verified way to
        # detect it at all. `orphaned.creator_unresolved` still catches
        # the case where a credential's `created_by` doesn't resolve to
        # any current member — that's the real signal this connector can
        # actually stand behind.
        status=OwnerStatus.ACTIVE,
        email=m.get("email") or None,
        raw=scrub(m),
    )


def _credential_from_api_key(row: dict, owners_by_id: dict[str, Owner]) -> Credential:
    # Defensive throughout — see http.py's verification-status note.
    # created_by may come back as a plain user id string or as a nested
    # {"id": ...} object depending on API version; handle both.
    created_by = row.get("created_by")
    creator_id = created_by.get("id") if isinstance(created_by, dict) else created_by
    owner = owners_by_id.get(creator_id) if creator_id else None

    return Credential(
        id=row.get("id", "unknown"),
        name=row.get("name") or row.get("id", "unknown"),
        account_type=AccountType.SCOPED_SERVICE_ACCOUNT,
        owner_id=owner.id if owner else None,
        provenance=Provenance.NATIVE,  # read from Anthropic's own API key registry,
                                        # not inferred from a lower-level artifact
        confidence=Confidence.CONFIRMED,
        provider="anthropic",
        has_audit_logging=None,  # not exposed by this endpoint
        last_used_at=None,       # not exposed by this endpoint; see Usage/Cost API
                                  # (docs.anthropic.com manage-claude/usage-cost-api)
                                  # for a future extension point if per-key last-use
                                  # ever needs to feed the orphaned-credential rules
        correlation_key=None,    # no cross-platform identity signal at the credential
                                  # level for a bare API key — see core/correlate.py;
                                  # cross-platform correlation for Anthropic happens via
                                  # Owner.email instead
        raw=scrub(row),
    )


def _credential_from_service_account(row: dict) -> Credential:
    """Service accounts (`svac_...`) are the non-human identities
    Workload Identity Federation tokens act as — the closest thing
    Anthropic's platform has to a formal "this is an agent/automation,
    not a person" identity. Modeled as a Credential (not an Agent) for
    the same reason api_keys are: this connector knows an identity
    exists, not what it's used for."""
    return Credential(
        id=row.get("id", "unknown"),
        name=row.get("name") or row.get("id", "unknown"),
        account_type=AccountType.SCOPED_SERVICE_ACCOUNT,
        owner_id=None,
        provenance=Provenance.NATIVE,
        confidence=Confidence.CONFIRMED,
        provider="anthropic",
        raw={**scrub(row), "_is_service_account": True},
    )


def fetch_anthropic_inventory(client, platform_id: str = "anthropic") -> Inventory:
    """Takes any object with `.get`, `.safe_get_all`, and `.oauth_token`
    (AnthropicAdminClient's shape) — factored out from the Connector
    class specifically so tests can pass a fake client directly, the
    same pattern ServiceNow's native.py/shadow.py use, rather than
    needing real credentials or network access to exercise this logic.
    """
    notes: list[str] = []

    member_rows, err = client.safe_get_all("/users")
    if err:
        notes.append(err)
        member_rows = []
    owners = [_owner_from_member(m) for m in member_rows]
    owners_by_id = {o.id: o for o in owners}

    key_rows, err = client.safe_get_all("/api_keys")
    if err:
        notes.append(err)
        key_rows = []
    credentials = [_credential_from_api_key(r, owners_by_id) for r in key_rows]

    # Service accounts require an org:admin OAuth token specifically —
    # an Admin API key is explicitly not accepted on this endpoint per
    # Anthropic's own docs. Skip cleanly with a note rather than
    # attempting a call we already know will be denied.
    if client.oauth_token:
        svc_rows, err = client.safe_get_all("/service_accounts")
        if err:
            notes.append(err)
            svc_rows = []
        credentials.extend(_credential_from_service_account(r) for r in svc_rows)
    else:
        notes.append(
            "Service account (WIF non-human identity) listing skipped — requires an "
            "org:admin OAuth bearer token, not an Admin API key. Pass oauth_token= "
            "(or set AGENTCENSUS_ANTHROPIC_OAUTH_TOKEN) to include these."
        )

    notes.append(
        f"Anthropic Admin API: {len(owners)} organization member(s), {len(credentials)} "
        "credential(s) (API keys and, if an OAuth token was used, service accounts). "
        "No Agent objects are synthesized from this connector — see module docstring "
        "for why an API key or service account is a credential, not an agent."
    )

    return Inventory(
        platform=platform_id,
        scanned_at=datetime.now(timezone.utc),
        agents=[],
        tools=[],
        credentials=credentials,
        owners=owners,
        scan_notes=notes,
    )


class AnthropicConnector(Connector):
    platform_id = "anthropic"

    def __init__(
        self,
        admin_api_key: str | None = None,
        oauth_token: str | None = None,
        timeout_seconds: int = 30,
    ):
        self.client = AnthropicAdminClient(
            admin_api_key=admin_api_key, oauth_token=oauth_token, timeout_seconds=timeout_seconds
        )

    def test_connection(self) -> bool:
        try:
            self.client.get("/me")
            return True
        except Exception:  # noqa: BLE001 — see servicenow/connector.py's identical
            # test_connection for why this is intentionally blanket, not an oversight.
            return False

    def fetch_inventory(self, **options) -> Inventory:
        return fetch_anthropic_inventory(self.client, self.platform_id)
