"""ServiceNow connector — connector one (project plan section 5).

Orchestrates two independent layers and merges them into one
Inventory:

  - native.py   — reads whichever native "AI agent" schema (if any) is
                  actually present on the instance.
  - shadow.py   — finds agentic integrations that were hand-built
                  directly on the platform and never touched a native
                  agent table at all: outbound REST calls to known LLM
                  API hosts, OAuth entities, and (opt-in — see below)
                  Scripted REST APIs and script source keyword matches.

Both layers matter — see core/models.py's provenance/confidence note
and tables.py's module docstring for why neither one alone is enough
to call this "universal" coverage.

Read-only, GET-only throughout — see http.py and core/connector.py.
Every table read is fault-isolated (see http.safe_get_all): a single
ACL-denied or failing table degrades to a scan_note, not a crash.

STATUS: verified live against two independent PDIs now, not one.
native.py's AI Agent Studio path is still written against public
schema docs only — `sn_aia_agent` doesn't exist on either PDI checked
so far (no Now Assist license on a free/dev instance, as expected).
Its Build Agent path, shadow.py's tier-2 (REST message) and tier-1
(OAuth entity) tables, sys_hub_flow, and both NASK provider/model
tables are now confirmed to exist against a second live instance too
— either read directly or confirmed present-but-ACL-restricted (a
"table exists, this account can't read it" error is a different,
informative signal from "table doesn't exist"). MCP Server Console's
guessed table was confirmed absent on that instance specifically (a
`sys_db_object` scan for any table matching "mcp_server" returned
zero rows) — this doesn't prove the guessed name is wrong, since the
scoped app itself may simply not be installed there, but it did
exercise the connector's honest "not detected" degrade path for real
rather than only in a test fixture. Tiers 3 and 4 of shadow.py are
still logically sound but not yet run against an instance that
actually has matching, readable data — the live account used so far
was denied on sys_script_include/sys_script/sys_ws_operation
specifically. See CONTRIBUTING.md and COVERAGE.md's live-verification
section before trusting any of this blind.

That same live pass caught a real bug, not just confirmed table names:
reference-type fields (sys_user.department, confirmed directly; run_as
and collection, defended against but not directly confirmed) come back
from ServiceNow's Table API as `{"link": "...", "value": "..."}` dicts
by default, not plain sys_id strings — this connector wasn't asking for
`sysparm_exclude_reference_link=true`, so every reference field read
outside the handful already routed through `ref()` was exposed to
storing a dict where a string was expected. Fixed at the client level
(`http.py`) plus defensively at each affected call site — see
owners.py, native.py, and shadow.py's tier 4.
"""

from __future__ import annotations

from datetime import datetime, timezone

from agentcensus.connectors.servicenow import (
    config_surfaces,
    domain_scope,
    flow_designer,
    integration_accounts,
    mcp_server,
    nask,
    native,
    shadow,
)
from agentcensus.connectors.servicenow.http import (
    OAuthClientCredentials,
    ServiceNowClient,
)
from agentcensus.connectors.servicenow.llm_providers import resolve_providers
from agentcensus.core.connector import Connector
from agentcensus.core.models import Inventory, Owner


class ServiceNowConnector(Connector):
    platform_id = "servicenow"

    def __init__(
        self,
        instance_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        oauth: OAuthClientCredentials | None = None,
        timeout_seconds: int = 30,
        max_records_per_table: int | None = None,
    ):
        kwargs = {}
        if max_records_per_table is not None:
            kwargs["max_records_per_table"] = max_records_per_table
        self.client = ServiceNowClient(
            instance_url, username, password, oauth, timeout_seconds, **kwargs
        )

    def test_connection(self) -> bool:
        try:
            # sysparm_fields is not optional here: without it the
            # Table API returns every field of a real user record — a
            # full PII row pulled and discarded on every single scan,
            # and the one place the deliberate field allowlist in
            # tables.py was being bypassed. sys_id alone proves
            # reachability and auth just as well.
            self.client.get("sys_user", {"sysparm_limit": 1, "sysparm_fields": "sys_id"})
            return True
        except Exception:  # noqa: BLE001 — intentionally blanket: test_connection's
            # contract (core/connector.py) is "never raise, return False for
            # ANY reason a scan wouldn't work" — auth failure, network
            # failure, unexpected response shape, anything. Narrowing this
            # to a specific exception type would violate that contract for
            # whatever failure mode isn't in the narrower list.
            return False

    def fetch_inventory(self, **options) -> Inventory:
        """Options:
            include_script_scan (bool, default False) — enables shadow
            detection tiers 3-4, which read Script Include/Business
            Rule/Scheduled Job/Scripted REST API script source. That's
            a broader permission grant than the default scan needs —
            see shadow.py's module docstring. CLI: --include-script-scan.

            include_script_excerpts (bool, default False) — additionally
            allow a short, secret-scrubbed excerpt of each matching
            script into the report. Reading script source to detect
            something and publishing it into a shareable artifact are
            separate risk decisions; this is the second one. Script
            bodies are never stored in full regardless. CLI:
            --include-script-excerpts.

            llm_providers_extra / llm_providers_config (str path,
            default None) — extend or replace the bundled LLM provider
            host/keyword list, e.g. to add an internal LLM gateway
            hostname. Falls back to the AGENTCENSUS_LLM_PROVIDERS_EXTRA
            / AGENTCENSUS_LLM_PROVIDERS_CONFIG env vars if not passed
            explicitly — see llm_providers.py. CLI: --llm-providers-extra
            / --llm-providers-config.
        """
        include_script_scan = bool(options.get("include_script_scan", False))
        include_script_excerpts = bool(options.get("include_script_excerpts", False))
        include_vendor_scope = bool(options.get("include_vendor_scope", False))
        include_inactive = bool(options.get("include_inactive", False))
        providers = resolve_providers(
            extra_path=options.get("llm_providers_extra"),
            override_path=options.get("llm_providers_config"),
        )

        native_agents, native_tools, native_creds, native_owners, native_notes = (
            native.detect_and_fetch(self.client)
        )
        shadow_agents, shadow_tools, shadow_creds, shadow_owners, shadow_notes = (
            shadow.fetch_shadow(
                self.client,
                providers=providers,
                include_script_scan=include_script_scan,
                include_script_excerpts=include_script_excerpts,
                include_vendor_scope=include_vendor_scope,
                include_inactive=include_inactive,
            )
        )
        flow_agents, flow_tools, flow_owners, flow_notes = flow_designer.fetch_flow_designer(
            self.client, providers=providers, include_inactive=include_inactive
        )
        mcp_tools, mcp_owners, mcp_notes = mcp_server.fetch_mcp_server_console(self.client, include_inactive=include_inactive)
        nask_tools, nask_notes = nask.fetch_nask(self.client, include_inactive=include_inactive)
        genai_creds, genai_notes = nask.fetch_genai_credentials(self.client)
        # Structural, default-on, no script source required — see
        # config_surfaces.py for why these are CONFIRMED-grade rather
        # than heuristics, and why a well-engineered integration is
        # otherwise LESS visible than a sloppy one.
        config_tools, config_notes = config_surfaces.fetch_config_surfaces(
            self.client, providers, include_inactive=include_inactive
        )

        # Must run regardless of what was found: a domain-scoped scan
        # silently returns a subset with no error, so the absence of a
        # warning here would itself be misleading. See domain_scope.py.
        domain_notes: list[str] = []
        domain_scope.check_domain_scope(self.client, domain_notes)

        integration_notes: list[str] = []
        integration_creds, integration_owners = integration_accounts.fetch_integration_accounts(
            self.client, integration_notes
        )

        owners_by_id: dict[str, Owner] = {}
        for owner in [*native_owners, *shadow_owners, *flow_owners, *mcp_owners, *integration_owners]:
            owners_by_id[owner.id] = owner

        return Inventory(
            platform=self.platform_id,
            scanned_at=datetime.now(timezone.utc),
            agents=[*native_agents, *shadow_agents, *flow_agents],
            tools=[
                *native_tools, *shadow_tools, *flow_tools, *mcp_tools, *nask_tools,
                *config_tools,
            ],
            credentials=[*native_creds, *shadow_creds, *integration_creds, *genai_creds],
            owners=list(owners_by_id.values()),
            # Read off the client at the END of the scan, so it reflects
            # every module's reads rather than whatever each one chose to
            # report. Nothing here needs collecting or forwarding, which
            # is the point — a surface added later is covered without its
            # author having to remember this exists.
            access_gaps=list(self.client.access_gaps),
            scan_notes=[
                # Domain scope first: it qualifies every count below it,
                # so it should be the first thing a reader sees.
                *domain_notes,
                *native_notes, *shadow_notes, *flow_notes, *mcp_notes, *nask_notes,
                *genai_notes, *config_notes, *integration_notes,
            ],
        )
