"""ServiceNow table/field references.

Two things changed here after live verification against a real PDI
(2026-07), and both matter enough to explain:

1. There is no single native "AI agent" schema. `sn_aia_*` (AI Agent
   Studio) is enterprise-tier, part of paid Now Assist licensing, and
   does not exist on a free developer instance — confirmed directly,
   not assumed. A separate, lighter "Build Agent" trial app
   (`sn_build_agent_*`) exists instead on at least some instances, and
   is architecturally different: it's built around conversation/message/
   skill runtime tables rather than a flat agent registry. `native.py`
   detects which (if either) is present rather than assuming one.

2. Neither native schema captures agents someone hand-built directly on
   the platform (Script Include + Scripted REST API + Business Rule
   calling out to an LLM) — which is a real, common pattern, not a edge
   case. `shadow.py` finds those via the tables listed under
   "Shadow detection" below. This is the more important half of
   ServiceNow coverage, not a fallback for when the native tables are
   missing.

Required scope for all of this: read access to the tables below. Do
not request `admin`. The exact minimum role has NOT yet been verified
against a live instance with proper ACLs configured (a PDI's default
admin session doesn't tell you what a scoped read-only role can see) —
treat this as an open item, not a solved one.
"""

# -- Native, variant 1: AI Agent Studio (enterprise, Now Assist-licensed) --

AIA_AGENT_TABLE = "sn_aia_agent"
AIA_AGENT_FIELDS = [
    "sys_id", "name", "description", "instructions", "strategy",
    "run_as", "role", "active", "sys_created_by", "sys_updated_by",
    "sys_updated_on", "sys_domain",
]

AIA_AGENT_TOOL_M2M_TABLE = "sn_aia_agent_tool_m2m"
AIA_AGENT_TOOL_M2M_FIELDS = [
    "sys_id", "agent", "tool", "run_as", "execution_mode", "max_auto_executions",
]

# -- Native, variant 2: Build Agent (trial-tier, confirmed present on a
#    free PDI as of 2026-07). No flat "agent" registry table observed —
#    conversations reference an application_id/application_name instead.
#    Treat this mapping as a first draft pending further verification;
#    it was derived from `sys_dictionary`, not from reading live data.

BUILD_AGENT_CONVERSATION_TABLE = "sn_build_agent_conversation"
BUILD_AGENT_CONVERSATION_FIELDS = [
    "sys_id", "title", "user", "application_id", "application_name",
    "state", "active", "sys_created_by", "sys_created_on", "last_message_at",
]
BUILD_AGENT_SKILL_TABLE = "sn_build_agent_skill"
BUILD_AGENT_SKILL_FIELDS = ["sys_id", "name", "sys_created_by", "sys_updated_on"]
BUILD_AGENT_SKILL_RESOURCE_TABLE = "sn_build_agent_skill_resource"
# No `name` column — verified live (2026-08). Resources are identified by
# `filename` and belong to a skill by reference. `content` is deliberately
# NOT requested: it is the resource body, the same sensitivity class as
# script source, and it belongs behind --include-script-scan if it is ever
# wanted at all.
BUILD_AGENT_SKILL_RESOURCE_FIELDS = [
    "sys_id", "filename", "skill", "sys_created_by", "sys_updated_on",
]
# These two were defined here and read by nobody — dead constants for two
# releases, while native.py's docstring said in prose that Build Agent has
# no registry beyond conversations. Confirmed live (2026-08): both tables
# exist. They ARE the skill (tool) registry the module said didn't exist.
# Empty on that instance, which is why nothing forced the issue sooner:
# an unread table and an empty table produce the same report.

# -- Shadow detection: agents/tools that exist as hand-built platform
#    artifacts, not as rows in any native "agent" table. See shadow.py.

REST_MESSAGE_TABLE = "sys_rest_message"
# `rest_endpoint`, NOT `endpoint`. Verified against sys_dictionary on a
# live instance (2026-08) after the wrong name shipped for the entire life
# of the project.
#
# This is the single worst defect AgentCensus has had, and the mechanism is
# worth stating exactly: ServiceNow silently OMITS a requested field that
# does not exist — same response shape as a field-level ACL denial, no
# error anywhere. So tier 2, the only CONFIRMED-grade outbound detection in
# the product, asked for a column that has never existed, got silence, and
# reported "0 outbound LLM REST messages" on every instance it ever ran
# against.
#
# What made it survive four code reviews and two live runs: the
# field-blindness machinery — built specifically to stop the
# tool mistaking "could not see" for "nothing there" — turned the bug into
# a fluent, plausible note blaming the CUSTOMER'S ACLs. A crash would have
# been caught in an hour. An honest-sounding explanation for the wrong
# cause survived indefinitely, and sent users to request permissions that
# would have changed nothing.
#
# The lesson generalizing to every other connector: a diagnostic that can
# only name one cause will name that cause for every symptom. See
# `unreadable_fields`, which now consults sys_dictionary before deciding
# which of the two it is looking at.
REST_MESSAGE_FIELDS = [
    "sys_id", "name", "rest_endpoint", "authentication_type", "basic_auth_profile",
    "sys_created_by", "sys_updated_by", "sys_updated_on",
]

REST_MESSAGE_FN_TABLE = "sys_rest_message_fn"  # per-HTTP-method function records;
REST_MESSAGE_FN_FIELDS = [               # endpoint can be overridden per-function
    "sys_id", "rest_message", "function_name", "rest_endpoint", "http_method",
]

# The endpoint column, named once so the detection modules stop spelling
# it themselves. The bug above was two string literals in two files
# disagreeing with the platform; a constant makes that impossible.
REST_ENDPOINT_FIELD = "rest_endpoint"

WS_OPERATION_TABLE = "sys_ws_operation"  # Scripted REST API resources — inbound
WS_OPERATION_FIELDS = [                  # surface exposed *to* external callers
    "sys_id", "name", "web_service_definition", "http_method",
    "relative_path", "operation_script", "requires_authentication",
    "sys_created_by", "sys_updated_by", "sys_updated_on",
    "sys_scope",
    "sys_package",
]

WS_DEFINITION_TABLE = "sys_ws_definition"
WS_DEFINITION_FIELDS = ["sys_id", "name", "service_id", "sys_created_by"]

OAUTH_ENTITY_TABLE = "oauth_entity"
OAUTH_ENTITY_FIELDS = [
    "sys_id", "name", "client_id", "sys_created_by", "sys_updated_by", "sys_updated_on",
]

SCRIPT_INCLUDE_TABLE = "sys_script_include"
SCRIPT_INCLUDE_FIELDS = [
    "sys_id", "name", "script", "active", "access",
    "sys_created_by", "sys_updated_by", "sys_updated_on",
    "sys_scope",
    "sys_package",
]

BUSINESS_RULE_TABLE = "sys_script"
BUSINESS_RULE_FIELDS = [
    "sys_id", "name", "script", "active", "when", "collection",
    "sys_created_by", "sys_updated_by", "sys_updated_on",
    "sys_scope",
    "sys_package",
]

SCHEDULED_JOB_TABLE = "sysauto_script"
SCHEDULED_JOB_FIELDS = [
    "sys_id", "name", "script", "active", "run_as",
    "sys_created_by", "sys_updated_by", "sys_updated_on",
    "sys_scope",
    "sys_package",
]

# -- Flow Designer / IntegrationHub: the no-code agent-building surface.
#    NOT yet verified against a live instance — table names below are
#    from public ServiceNow documentation, same caveat status the
#    sn_aia_* tables had before live verification corrected them. This
#    is genuinely the more important surface to get right eventually:
#    the project plan's own thesis (section 1) is about *non-technical*
#    employees building agents in minutes, which is Flow Designer, not
#    someone hand-writing a Script Include. Treat this as a first draft.
#
#    Deliberately reading structured fields (flow name/description,
#    action step name) rather than the JSON-blob action input values —
#    those field names carry more version-to-version uncertainty and
#    weren't confirmed here. That means detection is shallower than the
#    script-keyword tier (a flow whose LLM call is buried only in an
#    action's configured input values, with nothing suggestive in the
#    flow or step name, won't be caught yet) but also lower-privilege:
#    flow/action metadata is a materially less sensitive read than raw
#    script source, so this runs in the default scan rather than
#    behind include_script_scan.

HUB_FLOW_TABLE = "sys_hub_flow"
HUB_FLOW_FIELDS = [
    "sys_id", "name", "description", "active", "type",
    "sys_created_by", "sys_updated_by", "sys_updated_on",
]

HUB_ACTION_INSTANCE_TABLE = "sys_hub_action_instance"
# This table has FIVE own columns, and neither `name` nor `active` is one
# of them. Verified live (2026-08). The step's human-readable name lives on
# the referenced action type, reached by dot-walk.
#
# `active` was not merely unreadable, it does not exist — so the
# include-inactive filtering this module applied to action steps was
# filtering on a field that was never there. It reported excluding inactive
# action steps; there is no such thing at this level. Activity belongs to
# the parent flow.
#
# `action_inputs` is the configured INPUT VALUES of the step (a glide_var
# referencing sys_hub_action_input). flow_designer.py's docstring has said
# since it was written that input values are invisible and only names can
# be matched. That was a consequence of never having read the real schema.
# Requested here so the limitation can be re-tested against actual data
# rather than restated.
HUB_ACTION_INSTANCE_FIELDS = [
    "sys_id", "flow", "action_type", "order", "sys_created_by", "sys_updated_by",
]

# The action TYPE, fetched as its own table and joined client-side.
#
# The obvious approach — request `action_type.name` and let the Table API
# dot-walk it — DOES NOT WORK. Measured live (2026-08): the response came
# back with `action_type` (a bare sys_id) and no `action_type.name` key at
# all. Same for `action_inputs` and `action_type_parent`, both of which
# exist in sys_dictionary and neither of which the Table API returned.
#
# Worth recording because the failure mode is the one this project keeps
# meeting: a dot-walk that isn't honoured is omitted exactly like a denied
# field and a nonexistent one. Three different causes, one symptom, and
# the fix for the previous two (checking sys_dictionary) does NOT catch
# this one — the base field is real, the dictionary confirms it, and the
# request still silently returns nothing.
#
# So: no dot-walks anywhere in this connector. A second read plus a
# client-side join is a few hundred extra rows and it is verifiable.
HUB_ACTION_TYPE_TABLE = "sys_hub_action_type_base"
HUB_ACTION_TYPE_FIELDS = ["sys_id", "name"]

# -- ServiceNow's OWN generative-AI plumbing, as it appears in Flow
#    Designer action names. Found by reading the action picker on a live
#    instance (2026-08) — every entry below is a real, installed action on
#    a plain PDI with no LLM spoke of any kind.
#
#    Why this exists as a separate list rather than entries in
#    llm_providers.yaml: those markers describe THIRD-PARTY providers, and
#    a match there is a finding. These describe the platform's own AI
#    stack, they appear throughout out-of-the-box content, and a match is
#    context rather than a problem. Putting them in the provider list
#    would have produced a large number of NEEDS_REVIEW findings about
#    ServiceNow's own shipped code — the "ten OOB service accounts at
#    HIGH" failure, one more time.
#
#    So these are reported as an informational note and deliberately do
#    NOT synthesize agents or tools: findings are generated from inventory
#    objects, so anything added there can reach the severity table through
#    a rule. A note states the fact and cannot inflate anything.
#
#    The detection this closes: a flow calling `OneExtend Invocation` IS
#    invoking an LLM, and until now that was completely invisible — the
#    provider list had never heard of any of these names.
PLATFORM_AI_ACTION_MARKERS: tuple[str, ...] = (
    "oneextend",        # ServiceNow's GenAI invocation framework
    "one api",          # the LLM routing layer ("One API - Feature Completion")
    "toolexecutor",     # GlobalToolExecutor / InlineToolExecutor — agent tool execution
    "now assist",
    "nowassist",
    "generative ai",
    "genai",
    "semantic search",  # embedding-backed retrieval
)

# Installed IntegrationHub spokes / store apps in general — a cheap,
# very low-sensitivity signal that an LLM-provider spoke is available
# to flows at all, independent of whether a specific flow uses it yet.
STORE_APP_TABLE = "sys_store_app"
STORE_APP_FIELDS = ["sys_id", "name", "scope", "short_description", "version"]

# -- MCP Server Console: the native OOB MCP server surface (mcp_server.py).
#    LOWER verification confidence than anything above — public reporting
#    confirms the scoped app (sn_mcp_server, Zurich Patch 9+/Australia
#    Patch 2+) is real and GA, but not the table schema below at the same
#    live-instance-confirmed level as sn_aia_agent was. See
#    mcp_server.py's module docstring for the full reasoning and why this
#    ships anyway rather than waiting for verification. Field set kept
#    deliberately broad/generic (present on virtually every ServiceNow
#    table) so a wrong guess about more specific field names doesn't
#    break the whole read.

# `auth_server_connection` — found by UI exploration (2026-08), after
# `sn_mcp_server_registry` turned out to be a name that exists nowhere.
#
# The trail: a `sys_db_object` search by LABEL (not name) surfaced
# `auth_server_connection_tool_scan_job` ("MCP Tool Scan Job") and
# `auth_server_connection_tool_scan_result` ("MCP Tool Scan Results").
# Their parent, `auth_server_connection`, is labelled "Auth Server
# Connections" and carries Authorization Type / Connection Alias /
# Resource / Access control enabled / Restricted Mode Opt-In — an OAuth
# resource-server registration, which is exactly what an MCP server
# connection is.
#
# Note what the guessed name cost: every scan reported "MCP Server
# Console not detected", and the real registry was sitting there under a
# name sharing no substring with the guess. Two separate searches for
# tables named like "mcp" could never have found it. The one that worked
# searched LABELS — because ServiceNow names tables after the mechanism
# and labels them after the concept.
MCP_REGISTRY_TABLE = "auth_server_connection"
MCP_REGISTRY_FIELDS = [
    "sys_id", "connection_alias", "authorization_type", "resource",
    "access_control_enabled", "sys_created_by", "sys_updated_on",
]
# Kept so an instance that DOES have the previously-guessed name is still
# checked. Costs one probe; the alternative is silently dropping a name
# that public reporting associated with this feature.
MCP_REGISTRY_FALLBACK_TABLE = "sn_mcp_server_registry"
# Checked live against a second PDI (2026-07): `sn_mcp_server_registry` and
# a plain `sn_mcp_server` were both "Invalid table", and a sys_db_object
# scan for any table name containing "mcp_server" returned zero rows —
# the scoped app isn't installed on that instance at all, not just this
# specific guessed name being wrong. That doesn't confirm or refute the
# name above (nothing to test it against there), but it did prove
# mcp_server.py's table_exists()-based "not detected" degrade fires
# correctly on a real instance, not just in a test fixture.

# CONFIRMED LIVE (2026-08), and the reason the single-table check above is
# no longer sufficient. A third PDI turned up four real MCP-governance
# tables, all answering 403 (denied — they EXIST), while the registry name
# guessed above stayed "Invalid table". The old code drew the only
# conclusion one table could support and printed "MCP Server Console not
# detected... either the app isn't installed, the instance is below Zurich
# Patch 9, or the guessed name is wrong" — three branches, on that
# instance the third was true, and nothing in the scan could say which.
# A reader takes that note as "no MCP here." It was false.
#
# These were found the long way round: two Business Rules
# (`validateMCPServerForMcpAuthScopes`, `validateMCPServerForAigPolicy`)
# surfaced as tier-4 agent hits, and their `collection` field named the
# tables they validate. Worth recording as method — the satellites of a
# feature are findable even when the feature's own registry is not,
# because something has to validate them.
#
# `mcp_auth_scopes.mcp_server` is a plain STRING, not a reference, so
# there is no dot-walk from here to the server table and no way to learn
# its real name from this side. Named as satellites, not as a registry.
MCP_SATELLITE_TABLES: tuple[tuple[str, list[str], str], ...] = (
    # The scan RESULT table is the richest AI-governance surface on the
    # platform: it is a list of the tools an MCP server actually exposes,
    # discovered by ServiceNow itself. Column names unverified — the table
    # was empty on the instance that revealed it — so this is a first
    # draft, flagged as such rather than presented as known.
    # Columns read off the ServiceNow UI list view (2026-08). These tables
    # are 403 to the API, so this schema could NOT have come from
    # sys_dictionary or from any query — a person looked at the screen and
    # typed out the column headers. Worth recording as a method: the UI is
    # a legitimate schema source for tables the API refuses, and it is the
    # only one available for the most valuable surface here.
    #
    # This is ServiceNow's OWN risk assessment of MCP tools — Tool Name,
    # Threat Category, Safety Score, Scan Status, Input Schema. The
    # platform is already scoring the tools an MCP server exposes. A scan
    # that could read this would be reporting the vendor's verdict rather
    # than a keyword guess, which is a categorically better finding than
    # anything else in this connector.
    #
    # `input_schema` is requested because an MCP tool's input schema is
    # what decides whether it can WRITE — the property that drives blast
    # radius — and it is structural rather than inferred.
    ("auth_server_connection_tool_scan_result",
     ["sys_id", "tool_name", "threat_category", "safety_score", "scan_status",
      "status", "active", "description", "input_schema", "version"],
     "MCP tool scan results — the tools an MCP server exposes, with ServiceNow's own "
     "threat category and safety score for each"),
    ("auth_server_connection_tool_scan_job", ["sys_id"],
     "MCP tool scan jobs"),
    ("mcp_auth_scopes", ["sys_id", "mcp_server", "tool_group"],
     "MCP auth scopes — names an MCP server and the tool group it exposes"),
    ("aig_scope_tool_mapping", ["sys_id", "mcp_scope", "tool_name"],
     "AI Gateway scope-to-tool mapping — which tools a scope grants"),
    ("aig_access_policy",
     ["sys_id", "name", "mcp_server", "status", "decision_type", "description"],
     "AI Gateway access policy"),
    ("aig_access_policy_scope_mapping", ["sys_id", "aig_access_policy", "mcp_scope"],
     "AI Gateway policy-to-scope mapping"),
)

# -- Generative-AI credential stores. Both confirmed live (2026-08);
#    `gen_ai_service_secret` had a row on an instance where every other
#    GenAI table was empty, which is precisely the case for enumerating
#    it: a credential can outlive, or precede, the thing that uses it.
#
#    METADATA ONLY, and the field lists below are the enforcement. Neither
#    table's secret column is named here, so tests/test_no_secret_fields.py
#    — which scans these lists mechanically — keeps it that way. The
#    finding is "a generative-AI service credential exists and here is who
#    made it"; the value is never a thing this tool has held.
GENAI_SECRET_TABLES: tuple[tuple[str, list[str], str], ...] = (
    # `name`, `purpose` and `state` are real columns here (verified live)
    # and are far better attribution than the audit stamps this account is
    # denied. `secret` is the credential value itself and is never
    # requested — the omission is the guarantee, enforced by
    # tests/test_no_secret_fields.py scanning this very list.
    ("gen_ai_service_secret",
     ["sys_id", "name", "purpose", "state", "sys_created_by", "sys_created_on", "sys_updated_on"],
     "generative-AI service secret"),
    ("sys_generative_ai_custom_header_api_key_credentials",
     ["sys_id", "sys_created_by", "sys_created_on", "sys_updated_on"],
     "custom-header API key credential for a generative-AI provider"),
)

# -- Now Assist Skill Kit (NASK): custom generative-AI-skill authoring
#    (nask.py). Same caveat class as MCP Server Console above — table
#    names are from public documentation/community sources describing
#    GenAI Controller configuration, not a live-instance read. See
#    nask.py's module docstring for why the actual prompt/usage-log
#    tables (sys_generative_ai_log, sys_gen_ai_usage_log) are
#    deliberately NOT read here — that's a sensitivity decision, not an
#    oversight.

NASK_PROVIDER_MAPPING_TABLE = "sys_generative_ai_provider_mapping"
# Neither NASK table has a `name` column — verified live (2026-08). The
# identifying fields are `provider` (a plain string) and `gen_ai_provider`
# (a reference), and for models `model` / `model_display_name`.
#
# `connection` is the find that matters: it references `sys_alias`, the
# Connection & Credential Alias table. So there is a STRUCTURAL chain from
# a configured Now Assist model to the host it actually calls:
#
#     model_config -> connection (sys_alias) -> sys_connection.host
#
# That is a CONFIRMED-grade path — no keyword matching anywhere in it —
# from "a generative-AI model is configured here" to "and it talks to this
# hostname." nask.py's docstring previously said which provider a skill
# uses "isn't visible from this table alone", which was true only because
# the wrong columns were being requested.
NASK_PROVIDER_MAPPING_FIELDS = [
    "sys_id", "provider", "gen_ai_provider", "provider_api", "connection",
    "active", "sys_created_by", "sys_updated_on",
]

NASK_MODEL_CONFIG_TABLE = "sys_generative_ai_model_config"
NASK_MODEL_CONFIG_FIELDS = [
    "sys_id", "model", "model_display_name", "provider", "connection",
    "model_source", "active", "sys_created_by", "sys_updated_on",
]
# Both confirmed live against a second PDI (2026-07): provider_mapping was
# directly readable (empty on that instance, but a real, correctly-named
# table — reconfirmed via a sys_db_object registry match too); model_config
# exists (a table-level 403 there, "unauthorized" not "invalid table") but
# wasn't readable by the account tested. The instance's sys_db_object
# registry also turned up several other real sys_generative_ai_* tables
# not read here (prompt_config, capability_definition, feedback_score,
# among others) — noted as a candidate follow-up, not added speculatively;
# prompt_config in particular likely holds literal prompt template text,
# which is exactly the sensitivity class this module's docstring already
# says to deliberately avoid, so it needs its own judgment call, not a
# reflexive "we found a table, read it."

# -- Shared: owner resolution --

USER_TABLE = "sys_user"
USER_FIELDS = [
    "sys_id", "user_name", "name", "active", "department", "email",
    "web_service_access_only", "locked_out", "last_login_time",
]


# -- Configuration-surface detection (config_surfaces.py) --
#
#    Two structural signals that are STRONGER than tier-1's keyword
#    guess and cheaper (privilege-wise) than tier-4's script read, and
#    that the original four tiers missed entirely.
#
#    1. sys_properties. The single most common way an LLM endpoint stays
#       OUT of a script body is `gs.getProperty('x_foo.llm_endpoint')`.
#       The script then contains no provider keyword at all and tier 4
#       never fires — but the property's VALUE is a literal hostname,
#       which is exactly what match_host() is for. This is a CONFIRMED-
#       grade signal, not a heuristic.
#
#       Password/encrypted-typed properties are excluded SERVER-SIDE via
#       SYS_PROPERTIES_QUERY, so their values are never transmitted.
#       config_surfaces.py then applies a second, fail-closed check on
#       `type` (NON_SECRET_PROPERTY_TYPES) plus a check on the property
#       NAME, because sys_properties is an entity-attribute-value table:
#       the semantic field name lives in a row's `name` value, not in a
#       dict key, so the key-name redaction layer cannot see it.
#
#    2. Connection & Credential Aliases. The modern, ServiceNow-
#       recommended way to configure an outbound connection — the URL
#       lives in a real `connection_url` field on a connection record
#       rather than being hardcoded in a REST message endpoint. An
#       instance that does integrations "properly" is therefore LESS
#       visible to tier 2 than one that does them sloppily, which is
#       backwards. shadow.py's tier-1 docstring has flagged this as a
#       known open item since it was written; this closes it.
#
#    VERIFICATION STATUS: sys_properties is one of the oldest and most
#    stable tables in the platform — name/value/type are not in doubt.
#    The connection tables are lower confidence: `sys_connection` is the
#    documented base, `http_connection` the HTTP-specific child, and
#    `connection_url` the documented URL field, but this has NOT been
#    read from a live instance yet. Both are read through
#    safe_get_all + table_exists, so a wrong guess degrades to a scan
#    note instead of a crash — same pattern as mcp_server.py.

SYS_PROPERTIES_TABLE = "sys_properties"
SYS_PROPERTIES_FIELDS = [
    "sys_id", "name", "value", "type", "description",
    "sys_created_by", "sys_updated_by", "sys_updated_on",
]

# Property `type` values that mean "this holds a secret". Checked
# before the value is ever examined or stored.
SECRET_PROPERTY_TYPES = {
    "password", "password2", "password (2 way encrypted)",
    "glide_encrypted", "encrypted",
}

# Types this connector has positively confirmed are NOT credential
# material. config_surfaces.py reads a property's value only if its
# type is in this set — the inverse of the old logic, which read the
# value unless the type was in SECRET_PROPERTY_TYPES and therefore
# failed OPEN on any type string nobody anticipated.
NON_SECRET_PROPERTY_TYPES = {
    # Confirmed live (2026-08). The first six were the original guess;
    # the rest were found by RUNNING a scan and reading the COVERAGE GAP
    # note, which reports every type the fail-closed check refused.
    #
    # Failing closed is right in principle — an unrecognised type could
    # be an encrypted variant — but a list built from imagination
    # excluded eight ordinary types on the first real instance it met.
    # `short_string` is a standard type that routinely holds a URL,
    # which is exactly what this tier exists to find; refusing to read
    # it is silent under-detection dressed as caution.
    #
    # None of these can hold a platform-encrypted value: ServiceNow only
    # masks the password/glide-encrypted types in SECRET_PROPERTY_TYPES.
    # A credential sitting in one of these is plaintext in a
    # non-encrypted property — itself a finding, and redacted on the way
    # into the report by config_surfaces + core.redaction.
    "string", "integer", "boolean", "choicelist", "", "none",
    "short_string", "color", "date_format", "time_format", "timezone",
    "image", "uploaded_image", "true", "false", "glide_list",
    "reference", "numeric", "url", "email",
}

# Server-side exclusion, so encrypted values are never transmitted at
# all. The previous comment here claimed the `value` field was "not
# requested for password-type properties" — it was: the field list is
# static and the filtering happened client-side, after every encrypted
# value had already crossed the network.
# Only the single-token type values go in the encoded query — a value
# containing spaces or parens is not safely expressible in ServiceNow
# encoded-query syntax. The client-side fail-closed check in
# config_surfaces.py is what actually guarantees coverage; this is
# defence in depth that keeps the common cases off the wire.
SYS_PROPERTIES_QUERY = (
    "^".join(f"type!={t}" for t in sorted(SECRET_PROPERTY_TYPES) if t and t.isidentifier())
    +
    # `^OR` the empty case, because **ServiceNow's `!=` does not match
    # NULL**. Measured live (2026-08): the table held 3,673 properties,
    # this query returned 3,657, and the 16 missing were 12 genuinely
    # encrypted ones (correct) plus **4 with an empty `type`** — silently
    # dropped at the database.
    #
    # Why that mattered more than four records: config_surfaces has a
    # client-side check that fails closed on an unrecognised type AND
    # emits a COVERAGE GAP note naming it, precisely so a property this
    # tier declines to read is still reported. The rows never arrived, so
    # the note could not fire. A guard and its own alarm, both bypassed by
    # a NULL.
    #
    # The fix lets them through to the client-side check, which is where
    # the actual guarantee lives — the server-side filter is defence in
    # depth for keeping encrypted VALUES off the wire, not the thing that
    # decides what gets examined.
    #
    # Generalizes to every `!=` and `NOT LIKE` in this connector: they
    # exclude empty values. `sys_scope.scopeNOT LIKE...` in shadow.py has
    # the same property — a record with no scope would be dropped from the
    # vendor filter. Left as-is there because a script always carries a
    # scope, but it is the same trap and is noted here rather than
    # discovered twice.
    "^ORtypeISEMPTY"
)

CONNECTION_TABLE = "sys_connection"
# `sys_connection` has NO `connection_url`. Verified live (2026-08): the
# base table stores the destination as separate `host` / `protocol` /
# `port` columns, and `connection_url` exists only on the `http_connection`
# child. Requesting it on the parent produced the same silent omission as
# the `rest_endpoint` bug above.
#
# The correction improves the detection rather than merely repairing it:
# host matching is what this tier actually wants, and `host` is the host
# already parsed by the platform — no URL splitting, no scheme handling,
# no query-string edge cases. The parser this tier would otherwise need
# was sitting in its own column.
CONNECTION_FIELDS = [
    "sys_id", "name", "host", "protocol", "port", "connection_alias",
    "credential", "active", "sys_created_by", "sys_updated_by", "sys_updated_on",
]

# The child table DOES carry a full URL, and that is why this bug hid: the
# field name was real, just on a different table, so a grep for
# `connection_url` in this file looked correct.
HTTP_CONNECTION_TABLE = "http_connection"
HTTP_CONNECTION_FIELDS = [
    "sys_id", "name", "connection_url", "connection_alias", "credential",
    "active", "sys_created_by", "sys_updated_by", "sys_updated_on",
]


# -- Additional script-bearing surfaces (shadow.py tier 4) --
#
#    Tier 4 originally read three tables (Script Include, Business Rule,
#    Scheduled Job). Those are where a *developer* would put an agent.
#    They are not the only places one ends up, and the omissions were
#    not edge cases:
#
#    - sp_widget: Service Portal widgets. This is where a chat UI lives.
#      A "talk to our AI assistant" widget has a server script that
#      calls the LLM directly, and nothing about it touches any of the
#      three original tables. Arguably the single most likely home for
#      a user-facing agent on a modern instance.
#    - sys_ui_action: the "Summarize this incident with AI" button. One
#      of the most common ways an LLM call gets bolted onto an existing
#      form by someone who isn't building an "integration" at all.
#    - sysevent_in_email_action: inbound email actions — an agent you
#      talk to by emailing it. Real pattern, entirely invisible to the
#      original three.
#    - sys_script_fix / sys_processor: fix scripts and processors.
#      Lower frequency, but a fix script is exactly where someone
#      prototypes a "quick" LLM call and then forgets it, which is the
#      literal definition of what this tool hunts.
#
#    Field lists are deliberately minimal (sys_id, name, the script
#    field, active/creator metadata) — every one of these is read
#    through safe_get_all, so a table that doesn't exist on a given
#    instance or version degrades to a scan note rather than a failure.
#
#    NOTE ON sys_ws_operation: it appears BOTH here and under shadow
#    detection above, on purpose. Tier 3 reads it to ask "does this
#    expose a tool surface *outward*?" Tier 4 reads the same script to
#    ask "does this call an LLM *outward*?" Those are different
#    questions with different answers, and the original code only ever
#    asked the first — so a Scripted REST API that both receives calls
#    AND calls an LLM itself (the standard shape of an MCP-style bridge
#    endpoint: receive request, call model, return answer) was
#    classified as inbound-only, and its outbound half was never
#    reported. Confirmed against a real custom app built independently
#    of this project, whose /start endpoint is exactly that shape.

WIDGET_TABLE = "sp_widget"
WIDGET_FIELDS = [
    "sys_id", "name", "id", "script", "sys_created_by", "sys_updated_by", "sys_updated_on",
    "sys_scope",
    "sys_package",
]

UI_ACTION_TABLE = "sys_ui_action"
UI_ACTION_FIELDS = [
    "sys_id", "name", "script", "active", "table",
    "sys_created_by", "sys_updated_by", "sys_updated_on",
    "sys_scope",
    "sys_package",
]

INBOUND_EMAIL_ACTION_TABLE = "sysevent_in_email_action"
INBOUND_EMAIL_ACTION_FIELDS = [
    "sys_id", "name", "script", "active", "table",
    "sys_created_by", "sys_updated_by", "sys_updated_on",
    "sys_scope",
    "sys_package",
]

FIX_SCRIPT_TABLE = "sys_script_fix"
FIX_SCRIPT_FIELDS = [
    "sys_id", "name", "script", "sys_created_by", "sys_updated_by", "sys_updated_on",
    "sys_scope",
    "sys_package",
]

PROCESSOR_TABLE = "sys_processor"
PROCESSOR_FIELDS = [
    "sys_id", "name", "script", "active", "path",
    "sys_created_by", "sys_updated_by", "sys_updated_on",
    "sys_scope",
    "sys_package",
]


# -- Application scope resolution (shadow.py tier 4 noise control) --
#
#    Tier 4 substring-matches provider keywords against the full source
#    of nine tables. On a stock instance those tables hold ~10-15k rows,
#    the overwhelming majority of them code ServiceNow itself shipped.
#    An instance with Now Assist, AI Search or Virtual Agent installed
#    has OOB script includes that legitimately contain "openai",
#    "azure openai", "gemini" and "bedrock" — every one of which became
#    a NEEDS_REVIEW shadow agent, a synthesized placeholder tool and a
#    finding. That is hundreds of false positives ahead of any real one.
#
#    `sys_scope` is fetched on every tier-4 table and resolved through
#    this table to an application scope string. Customer-authored code
#    is never in an `sn_`/`com.snc`/`com.glide` scope, so those are
#    excluded by default — with a scan note stating the count and the
#    flag to include them, because silently dropping findings is the
#    same class of failure as silently missing them.
#
#    NOT a complete control: `global` scope holds both OOB and customer
#    code, and nothing in the field set separates them. Records in
#    global are still reported. Narrowing that needs `sys_package`
#    semantics confirmed against a live instance — treat it as open.

APP_SCOPE_TABLE = "sys_scope"
APP_SCOPE_FIELDS = ["sys_id", "name", "scope"]

VENDOR_SCOPE_PREFIXES = ("sn_", "com.snc", "com.glide", "sn-")


# -- Read manifest -------------------------------------------------------
#
#    The single source of truth for "what does this tool read". cli.py's
#    `preflight` builds its probe list from here rather than from a
#    hand-maintained copy, because the hand-maintained copy drifted: it
#    listed 6 of the 9 tier-4 script tables (sysevent_in_email_action,
#    sys_script_fix and sys_processor — all added in the same round that
#    wrote the list — were missing), and omitted sys_rest_message_fn,
#    sys_ws_definition, sys_hub_action_instance, sys_connection,
#    http_connection, sys_db_object, sys_scope, both native agent
#    schemas and the MCP/NASK tables entirely.
#
#    A security team approves a grant based on preflight and then the
#    scan reads tables they were never shown. Deriving one from the
#    other makes that drift impossible.

# -- Domain separation (domain_scope.py) --

DOMAIN_TABLE = "domain"
DOMAIN_FIELDS = ["sys_id", "name", "active"]

# `sys_package` resolving to the literal string "global" rather than a
# real package sys_id means the record belongs to NO application — it
# was authored directly on the instance, not delivered by a plugin,
# store app or scoped app.
#
# Confirmed live (2026-08): three ServiceNow-shipped Script Includes
# sitting in `global` SCOPE all carried the same real package sys_id,
# while a hand-built custom agent in that same scope carried the
# literal "global". `sys_scope` and `sys_created_by` were identical
# across all four and so are useless discriminators; `sys_package`
# separated them perfectly.
#
# Used to ANNOTATE and RANK, never to exclude. The inverse does not
# hold — a customer's own scoped app also carries a real package, so
# "has a package" is not "vendor" — and every over-correction defect in
# this project came from dropping records on exactly this kind of
# signal.
UNPACKAGED_SENTINEL = "global"


# What a specific unreadable surface COSTS, in detection terms.
#
# Keyed by (table, field) for a column and (table, None) for a whole
# table. Every entry below was observed blind on a live instance — this
# is a record of measured consequences, not a guess at which fields might
# matter someday, which is why it is short and why entries should only be
# added when something is actually seen to go dark.
#
# The point is to answer the question a security admin actually has when
# handed a list of grants: "what do I get back?" A report that says
# `sys_rest_message.endpoint` was unreadable is honest; one that says
# tier 2 — the only CONFIRMED-grade outbound tier — cannot run at all is
# the same fact in a form somebody can take to a change request.
IMPACT_BY_SURFACE: dict[tuple[str, str | None], str] = {
    (REST_MESSAGE_TABLE, REST_ENDPOINT_FIELD):
        "Tier 2 (outbound REST message host matching) cannot run at all. This is the "
        "only CONFIRMED-grade outbound detection in the product; without it, every "
        "hardcoded LLM endpoint on this instance is invisible and the scan cannot tell "
        "'none exist' from 'none visible'.",
    (REST_MESSAGE_FN_TABLE, REST_ENDPOINT_FIELD):
        "Per-method endpoint overrides are missed — a REST message whose base endpoint "
        "is benign but whose individual HTTP methods point at a model provider.",
    (CONNECTION_TABLE, "host"):
        "Connection & Credential Aliases cannot be host-matched. This is the method "
        "ServiceNow RECOMMENDS over hardcoding an endpoint, so a well-engineered "
        "integration is the one that goes undetected here.",
    (HUB_ACTION_TYPE_TABLE, None):
        "Flow Designer action-step matching is blind; only flow-level name/description "
        "matches still fire. A flow with an innocuous name calling an LLM action step "
        "will not be found.",
    (NASK_PROVIDER_MAPPING_TABLE, "provider"):
        "Now Assist provider mappings are found but cannot be named, so the report can "
        "say a generative-AI provider is configured and not which one.",
    (NASK_MODEL_CONFIG_TABLE, "model_display_name"):
        "Now Assist model configurations are found but cannot be named.",
    (STORE_APP_TABLE, None):
        "Installed spokes/apps cannot be checked against known LLM providers — the "
        "cheapest signal that a provider integration is available to flows at all.",
    ("mcp_auth_scopes", None):
        "MCP servers and tool groups registered on this instance cannot be enumerated. "
        "The scan can prove an MCP surface EXISTS here and cannot say what it exposes.",
    ("aig_scope_tool_mapping", None):
        "Which tools an AI Gateway scope grants cannot be enumerated.",
    ("aig_access_policy", None):
        "AI Gateway access policies cannot be enumerated.",
    ("aig_access_policy_scope_mapping", None):
        "AI Gateway policy-to-scope mappings cannot be enumerated.",
    ("auth_server_connection", None):
        "The MCP server registry itself. Without it the scan can prove an MCP surface "
        "exists on this instance (the table is present) and cannot name a single server, "
        "its authorization type, or the connection alias it authenticates with.",
    ("auth_server_connection_tool_scan_result", None):
        "ServiceNow's OWN scan results for the tools each MCP server exposes — tool name, "
        "threat category, safety score and input schema. This is the richest AI-governance "
        "data on the platform and the only place a scan can report the vendor's assessment "
        "rather than its own keyword guess. Granting read here is the single highest-value "
        "grant on this list.",
    ("auth_server_connection_tool_scan_job", None):
        "When MCP tool scans last ran. Without it there is no way to tell a clean scan "
        "result from one that has never been performed.",
    ("gen_ai_service_secret", "sys_created_by"):
        "Generative-AI service credentials are detected but cannot be attributed — the "
        "report can say one exists and not who created it, which is the field that "
        "makes it actionable.",
}


def impact_for(table: str, fields: tuple[str, ...] = ()) -> str | None:
    """Best available impact string for a surface.

    Falls back from the specific field to the whole table, and returns
    None rather than inventing text — an unmapped gap still gets listed
    with its grant, just without a consequence claimed for it. Silence is
    correct there: asserting an impact this project hasn't measured is
    the same failure mode as the notes it just spent two rounds fixing.
    """
    for f in fields:
        if (table, f) in IMPACT_BY_SURFACE:
            return IMPACT_BY_SURFACE[(table, f)]
    return IMPACT_BY_SURFACE.get((table, None))


DEFAULT_READ_MANIFEST: tuple[tuple[str, list[str], str], ...] = (
    # (table, fields actually read, why). The FIELD LIST is load-bearing:
    # preflight probes with it, so a wrong FIELD name surfaces as well as
    # a wrong table name. Probing `sys_id` alone proved the table existed
    # and said nothing about the fields detection depends on — and every
    # one is read with `.get()`, so a wrong name silently yields None and
    # that surface quietly detects nothing.
    (REST_MESSAGE_TABLE, REST_MESSAGE_FIELDS, "outbound LLM REST messages (tier 2)"),
    (REST_MESSAGE_FN_TABLE, REST_MESSAGE_FN_FIELDS, "per-method endpoint overrides (tier 2)"),
    (OAUTH_ENTITY_TABLE, OAUTH_ENTITY_FIELDS, "OAuth entities (tier 1)"),
    (SYS_PROPERTIES_TABLE, SYS_PROPERTIES_FIELDS, "system properties holding LLM endpoints"),
    (CONNECTION_TABLE, CONNECTION_FIELDS, "Connection & Credential Aliases"),
    (HTTP_CONNECTION_TABLE, HTTP_CONNECTION_FIELDS, "HTTP connection records"),
    (HUB_FLOW_TABLE, HUB_FLOW_FIELDS, "Flow Designer flows"),
    (HUB_ACTION_INSTANCE_TABLE, HUB_ACTION_INSTANCE_FIELDS, "Flow Designer action steps"),
    (HUB_ACTION_TYPE_TABLE, HUB_ACTION_TYPE_FIELDS,
     "Flow Designer action type names (joined to steps client-side)"),
    (STORE_APP_TABLE, STORE_APP_FIELDS, "installed spokes/apps"),
    (AIA_AGENT_TABLE, AIA_AGENT_FIELDS, "AI Agent Studio agents (native, if licensed)"),
    (BUILD_AGENT_CONVERSATION_TABLE, BUILD_AGENT_CONVERSATION_FIELDS,
     "Build Agent conversations (native, if present)"),
    (BUILD_AGENT_SKILL_TABLE, BUILD_AGENT_SKILL_FIELDS,
     "Build Agent skills — the tool registry for that schema"),
    (BUILD_AGENT_SKILL_RESOURCE_TABLE, BUILD_AGENT_SKILL_RESOURCE_FIELDS,
     "Build Agent skill resources"),
    (MCP_REGISTRY_TABLE, MCP_REGISTRY_FIELDS, "MCP Server Console registry (if installed)"),
    # Probed so preflight reports them by NAME. On a least-privileged
    # account these come back `denied`, and that is the useful answer:
    # denied proves the MCP surface is present, which the registry probe
    # alone could never establish.
    *MCP_SATELLITE_TABLES,
    *GENAI_SECRET_TABLES,
    (NASK_PROVIDER_MAPPING_TABLE, NASK_PROVIDER_MAPPING_FIELDS, "NASK provider mappings"),
    (NASK_MODEL_CONFIG_TABLE, NASK_MODEL_CONFIG_FIELDS, "NASK model configs"),
    (USER_TABLE, USER_FIELDS, "owner resolution"),
    (APP_SCOPE_TABLE, APP_SCOPE_FIELDS, "application scope resolution"),
    # Was missing while domain_scope.py read it on every scan — the same
    # manifest drift this list exists to prevent, one round later.
    (DOMAIN_TABLE, DOMAIN_FIELDS, "domain-separation detection"),
    ("sys_db_object", ["sys_id"], "table existence checks (table_exists)"),
    # Read by `columns_of()` on every missing-field classification, and
    # undeclared until an independent review found it. Consequences of the
    # omission, both real: `preflight` never probed it, so a security team
    # approving a grant was never told this table is read — the specific
    # failure preflight exists to prevent; and when it IS restricted (which
    # is common on a least-privileged account) the entire schema-mismatch
    # apparatus silently reverts to its earlier behaviour, reporting every
    # missing field as the customer's ACL, with nothing in the report
    # saying the diagnostic is inoperative.
    #
    # DEFAULT_READ_MANIFEST's own comment claims deriving preflight from it
    # makes manifest drift "impossible". This was manifest drift, one
    # release after that sentence was written.
    ("sys_dictionary", ["name", "element"],
     "column-name verification — tells a genuine field-level ACL apart from a "
     "wrong column name in this tool"),
)

SCRIPT_READ_MANIFEST: tuple[tuple[str, list[str], str], ...] = (
    (SCRIPT_INCLUDE_TABLE, SCRIPT_INCLUDE_FIELDS, "Script Includes (tier 4)"),
    (BUSINESS_RULE_TABLE, BUSINESS_RULE_FIELDS, "Business Rules (tier 4)"),
    (SCHEDULED_JOB_TABLE, SCHEDULED_JOB_FIELDS, "Scheduled Jobs (tier 4)"),
    (WS_OPERATION_TABLE, WS_OPERATION_FIELDS, "Scripted REST APIs (tiers 3-4)"),
    (WIDGET_TABLE, WIDGET_FIELDS, "Service Portal widgets (tier 4)"),
    (UI_ACTION_TABLE, UI_ACTION_FIELDS, "UI Actions (tier 4)"),
    (INBOUND_EMAIL_ACTION_TABLE, INBOUND_EMAIL_ACTION_FIELDS, "Inbound email actions (tier 4)"),
    (FIX_SCRIPT_TABLE, FIX_SCRIPT_FIELDS, "Fix scripts (tier 4)"),
    (PROCESSOR_TABLE, PROCESSOR_FIELDS, "Processors (tier 4)"),
)
