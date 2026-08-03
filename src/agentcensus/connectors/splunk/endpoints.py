"""Splunk REST API endpoint references — the Splunk equivalent of
ServiceNow's tables.py.

VERIFICATION STATUS, stated the same way ServiceNow's tables.py states
it: these are real, stable, documented Splunk REST endpoints
(management port 8089), not guessed — `/services/saved/searches`,
`/services/apps/local`, `/services/authentication/users`, and
`/services/data/inputs/http` (HTTP Event Collector token management)
are long-standing, version-stable parts of Splunk's REST API, unlike
some of the newer ServiceNow table names elsewhere in this project that
needed live-instance correction. What is NOT verified is this specific
project's read against a real Splunk instance end to end — no developer
instance was available this session, matching the same "structurally
sound, not yet run against live data" status this project already
applies to several of its own ServiceNow tiers (see shadow.py's module
docstring).
"""

# Alerts are saved searches with alerting enabled — Splunk's own REST
# docs are explicit that there is no separate "alerts" endpoint; look at
# saved/searches instead. Each entry's `content` dict carries `actions`
# (comma-separated enabled action names), `action.webhook.param.url`,
# `action.script.filename`, `search` (the SPL itself), `is_scheduled`,
# `author` (via the entry's `acl.owner`), and `updated`.
SAVED_SEARCHES_ENDPOINT = "/services/saved/searches"

# Installed apps — the Splunk analog of ServiceNow's sys_store_app spoke
# detection (flow_designer.py) and the surface where MCP Server for
# Splunk itself would show up as an installed app if configured.
APPS_ENDPOINT = "/services/apps/local"

# HTTP Event Collector tokens — Splunk's own native registry of
# credentials external systems use to send data IN. The clean, inbound-
# direction analog of ServiceNow's tier-3 Scripted REST API detection:
# every token here is a real, structural "something external
# authenticates to Splunk as this identity" signal, independent of
# whether that something is an LLM-labeled system at all — same
# provider-agnostic reasoning as integration_accounts.py on the
# ServiceNow side.
HEC_TOKENS_ENDPOINT = "/services/data/inputs/http"

# Splunk users — for author/owner resolution on saved searches.
USERS_ENDPOINT = "/services/authentication/users"
