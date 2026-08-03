"""Splunk connector — connector two, no longer a stub.

Mirrors the ServiceNow connector's shape and honesty conventions
deliberately, so both read the same way to anyone auditing this
project: read-only (http.py enforces GET-only), fault-isolated (every
endpoint read goes through `safe_get_all`, one denied endpoint degrades
to a scan note, not a crash), and explicit about provenance/confidence
per finding (see core/models.py's design note).

Three detection angles, roughly mirroring shadow.py's tiers:

  1. Saved searches (alerts are saved searches with alerting enabled —
     see endpoints.py) whose webhook alert action URL matches a known
     LLM provider host — CONFIRMED, structural, same reasoning as
     shadow.py tier 2. The saved search becomes an Agent (it's an
     automation that fires on a schedule/condition and calls out), the
     webhook action becomes a synthesized outbound Tool.
  2. Saved searches whose SPL query text matches an LLM provider
     keyword with no confirmed webhook match — NEEDS_REVIEW, same
     reasoning as shadow.py tier 4's ad hoc case (e.g. a custom search
     command wrapping an LLM call, `| customllmcommand`).
  3. Installed apps matching an LLM provider or "mcp" — NEEDS_REVIEW,
     same reasoning as flow_designer.py's installed-spoke detection;
     also the surface where MCP Server for Splunk itself, Splunk's own
     native OOB MCP offering (GA Feb 2026), would show up if installed.

Plus one provider-agnostic angle with no ServiceNow equivalent in the
outbound direction: HTTP Event Collector tokens (endpoints.py) are
Splunk's own native registry of credentials external systems authenticate
with to send data IN. Every token becomes a Credential regardless of
what's on the other end — the same "we can't see the caller, but we can
see the door" reasoning as integration_accounts.py, mirrored for the
inbound direction Splunk is actually built around.

No native "AI agent" registry exists on the Splunk platform side to
check first (there's no sn_aia_agent equivalent) — every Agent this
connector produces is SYNTHESIZED, unlike ServiceNow where native.py
checks a real registry before falling back to shadow detection.
"""

from __future__ import annotations

from datetime import datetime, timezone

from agentcensus.connectors.servicenow.llm_providers import (
    # Reused as-is rather than duplicated — the provider list (which
    # hosts/keywords count as a known LLM) is a platform-agnostic fact,
    # not a ServiceNow-specific one. Living under connectors/servicenow/
    # is a naming artifact of build order, not a real dependency on
    # anything ServiceNow-specific; a future cleanup could hoist this to
    # a shared location once a third connector wants it too, but two
    # connectors sharing it via direct import is not worth a mechanical
    # refactor mid-session.
    Provider,
    match_host,
    match_keywords,
    resolve_providers,
)
from agentcensus.connectors.splunk import endpoints
from agentcensus.connectors.splunk.http import SplunkClient
from agentcensus.core.connector import Connector
from agentcensus.core.models import (
    AccountType,
    Agent,
    Confidence,
    Credential,
    Inventory,
    Owner,
    OwnerStatus,
    Provenance,
    Tool,
)
from agentcensus.core.redaction import scrub


def _scrub_secrets(content: dict) -> dict:
    """Splunk's config-read endpoints return the full content blob for a
    stanza with no field-projection option the way ServiceNow's Table
    API `sysparm_fields` offers (every ServiceNow read in this project
    explicitly allowlists fields — see tables.py — so this class of risk
    doesn't exist there). Most Splunk config fields are harmless, but at
    least one confirmed case is not: the HTTP Event Collector token
    management endpoint (`_fetch_hec_credentials`) returns the token's
    actual usable secret value in its content, not a masked hint the way
    Anthropic's Admin API returns `partial_key_hint` for API keys.

    AgentCensus's core guarantee — stated in `Credential`'s docstring in
    core/models.py — is that it reads metadata ABOUT a credential, never
    the credential's own secret material. Without this, the HEC-token
    tier would have silently broken that guarantee by writing live
    secrets straight into the JSON report. Applied to every `raw` blob
    built from Splunk `content`, not just the HEC tier, since the same
    "no field allowlist" risk applies anywhere a future Splunk stanza
    type happens to embed a secret-shaped field.
    Delegates to `core.redaction.scrub`, which applies TWO layers, not
    just this function's original key-name check: a field named `token`
    is redacted whatever it holds, AND any value that *looks* like a
    credential (a provider key prefix, a JWT, a `?api_key=` in a webhook
    URL) is redacted wherever it appears. That second layer matters
    specifically here — a saved search's webhook alert action stores a
    full URL in `action.webhook.param.url`, a field whose name is
    entirely innocent and whose value routinely carries the auth token
    in a query string.
    """
    return scrub(content)


def _owner_from_user_entry(entry: dict) -> Owner:
    content = entry.get("content", {})
    roles = content.get("roles") or []
    is_admin_role = "admin" in roles or "sc_admin" in roles
    return Owner(
        id=entry.get("name", "unknown"),
        display_name=content.get("realname") or entry.get("name", "unknown"),
        status=OwnerStatus.ACTIVE,  # Splunk's users endpoint doesn't expose a clean
                                     # "disabled" flag the way ServiceNow's sys_user.active
                                     # does on every instance — left ACTIVE rather than
                                     # guessing; orphaned-owner rules degrade gracefully to
                                     # "unresolved" for users this connector can't find at
                                     # all, which is the honest signal available here
        email=content.get("email") or None,
        raw={**_scrub_secrets(content), "_is_admin_role": is_admin_role},
    )


def _fetch_saved_search_agents(client: SplunkClient, providers: list[Provider], notes: list[str]):
    rows, err = client.safe_get_all(endpoints.SAVED_SEARCHES_ENDPOINT)
    if err:
        notes.append(err)
        return [], []

    agents: list[Agent] = []
    tools: list[Tool] = []

    for entry in rows:
        content = entry.get("content", {})
        name = entry.get("name", "unknown")
        owner_username = entry.get("acl", {}).get("owner")

        webhook_url = content.get("action.webhook.param.url", "")
        actions = content.get("actions", "") or ""
        has_webhook_action = "webhook" in actions
        provider = match_host(webhook_url, providers) if has_webhook_action else None

        if provider:
            tool = Tool(
                id=f"{name}:webhook",
                name=f"{name} (webhook alert action)",
                description=f"Splunk alert action on saved search '{name}' — webhook to {provider.label} ({webhook_url}).",
                credential_id=None,
                provenance=Provenance.SYNTHESIZED,
                confidence=Confidence.CONFIRMED,
                direction="outbound",
                raw=_scrub_secrets(content),
            )
            tools.append(tool)
            agents.append(
                Agent(
                    id=name,
                    name=name,
                    description=content.get("description") or None,
                    owner_id=None,  # resolved by caller once owner list is available
                    tool_ids=[tool.id],
                    provenance=Provenance.SYNTHESIZED,
                    confidence=Confidence.CONFIRMED,
                    detection_signal=f"splunk:saved_search_webhook_confirmed_tool:{provider.id}",
                    raw=scrub({**entry, "content": _scrub_secrets(content), "_owner_username": owner_username}),
                )
            )
            continue

        search_text = content.get("search", "") or ""
        hit_providers = match_keywords(f"{search_text} {content.get('description', '')}", providers)
        if not hit_providers:
            continue

        placeholder = Tool(
            id=f"{name}:inline_llm_reference",
            name=f"{name} (SPL keyword match)",
            description=(
                f"Inferred from an LLM-provider keyword match in saved search '{name}''s SPL "
                f"or description ({', '.join(p.label for p in hit_providers)}) — no confirmed "
                "webhook alert action found for this search."
            ),
            credential_id=None,
            provenance=Provenance.SYNTHESIZED,
            confidence=Confidence.NEEDS_REVIEW,
            direction="outbound",
            raw={},
        )
        tools.append(placeholder)
        agents.append(
            Agent(
                id=name,
                name=name,
                description=content.get("description") or None,
                owner_id=None,
                tool_ids=[placeholder.id],
                provenance=Provenance.SYNTHESIZED,
                confidence=Confidence.NEEDS_REVIEW,
                detection_signal=f"splunk:saved_search_keyword:{','.join(p.id for p in hit_providers)}",
                raw=scrub({**entry, "content": _scrub_secrets(content), "_owner_username": owner_username}),
            )
        )

    return agents, tools


def _fetch_app_tools(client: SplunkClient, providers: list[Provider], notes: list[str]) -> list[Tool]:
    rows, err = client.safe_get_all(endpoints.APPS_ENDPOINT)
    if err:
        notes.append(err)
        return []

    tools = []
    for entry in rows:
        content = entry.get("content", {})
        name = entry.get("name", "unknown")
        label = content.get("label", "") or ""
        haystack = f"{name} {label}"
        hit_providers = match_keywords(haystack, providers)
        is_mcp_app = "mcp" in name.lower() or "mcp" in label.lower()

        if not hit_providers and not is_mcp_app:
            continue

        if is_mcp_app:
            description = (
                f"Installed Splunk app '{label or name}' appears to be an MCP server/client "
                "integration (name/label match) — the native OOB MCP surface for this "
                "platform (MCP Server for Splunk, GA Feb 2026) if that's what this is. "
                "Confirm via the app's own configuration."
            )
        else:
            description = (
                f"Installed Splunk app '{label or name}' matches a known LLM provider "
                f"({', '.join(p.label for p in hit_providers)}) — available on this instance "
                "whether or not any saved search currently uses it."
            )

        tools.append(
            Tool(
                id=name,
                name=label or name,
                description=description,
                credential_id=None,
                provenance=Provenance.SYNTHESIZED,
                confidence=Confidence.NEEDS_REVIEW,
                direction=None,
                raw=_scrub_secrets(content),
            )
        )
    return tools


def _fetch_hec_credentials(client: SplunkClient, notes: list[str]) -> list[Credential]:
    rows, err = client.safe_get_all(endpoints.HEC_TOKENS_ENDPOINT)
    if err:
        notes.append(err + " (inbound HEC-token credential detection skipped)")
        return []

    credentials = []
    for entry in rows:
        content = entry.get("content", {})
        disabled = content.get("disabled") in ("1", 1, True, "true")
        owner_username = entry.get("acl", {}).get("owner")
        credentials.append(
            Credential(
                id=entry.get("name", "unknown"),
                name=entry.get("name", "unknown"),
                account_type=AccountType.SCOPED_SERVICE_ACCOUNT,
                owner_id=None,  # resolved by fetch_splunk_inventory once the user list is
                                 # available — same two-pass pattern as saved-search agents
                                 # below, via "_owner_username" in raw. Splunk's ACL model
                                 # puts an `owner` on every stanza, HEC tokens included, the
                                 # same field saved searches already use for this connector's
                                 # agent-owner resolution — leaving it unread here (as an
                                 # earlier version of this function did) meant every HEC
                                 # credential unconditionally tripped
                                 # orphaned.credential_no_owner regardless of whether Splunk
                                 # actually had an owner on record, the same shape of gap
                                 # fixed for ServiceNow's shadow-tier credentials previously.
                provenance=Provenance.NATIVE,  # Splunk's own HEC token registry, not inferred
                confidence=Confidence.CONFIRMED,
                provider=None,  # unknown — see module docstring, this is the inbound-direction
                                 # "we see the door, not who's behind it" signal
                has_audit_logging=None,
                # _scrub_secrets is not optional here, it's the fix: this endpoint's
                # `content` includes the token's actual usable secret value in
                # cleartext (Splunk requires this so admins can copy the token
                # after creation) — see _scrub_secrets' docstring.
                is_disabled=disabled,
            raw={**_scrub_secrets(content), "_disabled": disabled, "_owner_username": owner_username},
            )
        )
    if credentials:
        notes.append(
            f"Splunk HEC token scan: {len(credentials)} token(s) found — inbound credentials "
            "external systems (any platform, any vendor) use to send data into Splunk."
        )
    return credentials


def fetch_splunk_inventory(client, providers: list[Provider], platform_id: str = "splunk") -> Inventory:
    """Takes any object with SplunkClient's `.get_all`/`.safe_get_all`
    shape — factored out from the Connector class so tests can pass a
    fake client directly, same reasoning as anthropic/connector.py's
    `fetch_anthropic_inventory`."""
    notes: list[str] = []

    user_rows, err = client.safe_get_all(endpoints.USERS_ENDPOINT)
    if err:
        notes.append(err)
        user_rows = []
    owners = [_owner_from_user_entry(u) for u in user_rows]
    owners_by_username = {o.id: o for o in owners}

    agents, search_tools = _fetch_saved_search_agents(client, providers, notes)
    for agent in agents:
        owner = owners_by_username.get(agent.raw.get("_owner_username"))
        if owner:
            agent.owner_id = owner.id

    app_tools = _fetch_app_tools(client, providers, notes)
    hec_credentials = _fetch_hec_credentials(client, notes)
    for cred in hec_credentials:
        owner = owners_by_username.get(cred.raw.get("_owner_username"))
        if owner:
            cred.owner_id = owner.id

    notes.append(
        f"Splunk scan: {len(agents)} saved-search-derived agent(s), "
        f"{len(search_tools) + len(app_tools)} tool(s), {len(hec_credentials)} HEC "
        "credential(s). No native AI-agent registry exists on this platform to check "
        "first (see module docstring) — every agent here is inferred, same status as "
        "shadow.py's findings on the ServiceNow side."
    )

    return Inventory(
        platform=platform_id,
        scanned_at=datetime.now(timezone.utc),
        agents=agents,
        tools=[*search_tools, *app_tools],
        credentials=hec_credentials,
        owners=owners,
        scan_notes=notes,
    )


class SplunkConnector(Connector):
    platform_id = "splunk"

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        timeout_seconds: int = 30,
        verify_ssl: bool = True,
    ):
        self.client = SplunkClient(
            base_url=base_url, token=token, username=username, password=password,
            timeout_seconds=timeout_seconds, verify_ssl=verify_ssl,
        )

    def test_connection(self) -> bool:
        try:
            self.client.get_all(endpoints.APPS_ENDPOINT, count=1)
            return True
        except Exception:  # noqa: BLE001 — see servicenow/connector.py's identical
            # test_connection for why this is intentionally blanket, not an oversight.
            return False

    def fetch_inventory(self, **options) -> Inventory:
        providers = resolve_providers(
            extra_path=options.get("llm_providers_extra"),
            override_path=options.get("llm_providers_config"),
        )
        return fetch_splunk_inventory(self.client, providers, self.platform_id)
