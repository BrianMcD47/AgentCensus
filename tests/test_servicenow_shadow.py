"""Shadow-detection tests run entirely against a fake client — no live
instance needed, no network. The fixture REST message rows are shaped
like what we observed on a real PDI (Firebase, Yahoo Finance — neither
should match) plus one synthetic Anthropic entry to prove tier 2 fires
correctly and tier 4 correlates a caller to it instead of treating it
as a separate, disconnected finding.
"""

from agentcensus.connectors.servicenow import shadow
from agentcensus.connectors.servicenow.llm_providers import (
    load_providers,
    match_host,
    match_keywords,
)
from agentcensus.core.models import Confidence, Provenance
from tests.servicenow_fakes import FakeClient

REST_MESSAGES = [
    {"sys_id": "rm1", "name": "Firebase Cloud Messaging Send", "rest_endpoint": "https://fcm.googleapis.com/fcm/send", "authentication_type": "no_authentication", "basic_auth_profile": None},
    {"sys_id": "rm2", "name": "Yahoo Finance", "rest_endpoint": "http://finance.yahoo.com/d/quotes.csv", "authentication_type": "no_authentication", "basic_auth_profile": None},
    {"sys_id": "rm3", "name": "Claude Bridge", "rest_endpoint": "https://api.anthropic.com/v1/messages", "authentication_type": "basic", "basic_auth_profile": {"value": "cred1"}, "sys_created_by": "brian"},
]

OAUTH_ENTITIES = [
    {"sys_id": "oa1", "name": "Anthropic OAuth App", "client_id": "anthropic-client-123", "sys_created_by": "brian"},
]

USERS = [{"sys_id": "u_brian", "user_name": "brian", "name": "Brian", "active": "true", "department": "Eng", "email": "brian@example.com"}]

SCRIPT_INCLUDES = [
    {"sys_id": "si1", "name": "ClaudeBridgeHelper", "script": "// calls Claude Bridge for triage\nvar r = new sn_ws.RESTMessageV2('Claude Bridge', 'post');", "active": "true", "access": "package_private", "sys_created_by": "brian"},
    {"sys_id": "si2", "name": "AdHocOpenAICaller", "script": "var endpoint = 'https://api.openai.com/v1/chat/completions'; // inline, no REST message record", "active": "true", "access": "package_private", "sys_created_by": "brian"},
    {"sys_id": "si3", "name": "UnrelatedHelper", "script": "gs.info('nothing to see here');", "active": "true", "access": "package_private", "sys_created_by": "brian"},
]

FULL_TABLES = {
    "sys_rest_message": REST_MESSAGES,
    "sys_rest_message_fn": [],
    "sys_ws_operation": [],
    "oauth_entity": OAUTH_ENTITIES,
    "sys_script_include": SCRIPT_INCLUDES,
    "sys_script": [],
    "sysauto_script": [],
    "sys_user": USERS,
}


def test_provider_matching_basics():
    providers = load_providers()
    assert match_host("https://api.anthropic.com/v1/messages", providers).id == "anthropic"
    assert match_host("https://fcm.googleapis.com/fcm/send", providers) is None
    assert [p.id for p in match_keywords("uses openai gpt-4 under the hood", providers)] == ["openai"]


def test_generic_api_key_header_alone_does_not_match_anthropic():
    """x-api-key used to be listed as an Anthropic keyword, but it's a
    generic REST API header convention plenty of non-Anthropic services
    use too — a script authenticating to an unrelated API with that
    header was getting mislabeled as an Anthropic integration. Removed
    in the second fresh-eyes audit pass; host-based matching still
    catches every real api.anthropic.com reference at CONFIRMED
    confidence, this keyword tier just no longer over-triggers on it."""
    providers = load_providers()
    assert match_keywords("headers['x-api-key'] = some_other_vendor_key", providers) == []


def test_tier2_matches_only_the_llm_endpoint():
    client = FakeClient(FULL_TABLES)
    providers = load_providers()
    notes = []
    tools, credentials, tools_by_name = shadow._tier2_rest_message_tools(client, providers, notes)

    assert [t.name for t in tools] == ["Claude Bridge"]
    assert tools[0].provenance == Provenance.SYNTHESIZED
    assert tools[0].confidence == Confidence.CONFIRMED
    assert tools[0].direction == "outbound"
    assert set(tools_by_name) == {"Claude Bridge"}
    assert len(credentials) == 1
    assert credentials[0].provider == "anthropic"


def test_tier2_falls_back_to_name_keyword_when_endpoint_is_a_template_variable():
    """The confirmed, real gap this project's own docstring used to
    describe: a REST message endpoint like 'https://${host}/v1/messages'
    (observed live) never matches match_host no matter how complete the
    provider list is, because the real host is resolved by ServiceNow
    elsewhere. Before this fix such a message was silently dropped —
    zero finding, not even a lead. Now it falls back to a name keyword
    match at NEEDS_REVIEW instead of vanishing."""
    templated_messages = [
        {
            "sys_id": "rm_templated",
            "name": "Anthropic Gateway (env-specific)",
            "rest_endpoint": "https://${host}/v1/messages",
            "authentication_type": "no_authentication",
            "basic_auth_profile": None,
        },
        {
            "sys_id": "rm_templated_unrelated",
            "name": "Generic Internal API",
            "rest_endpoint": "https://${host}/v1/whatever",
            "authentication_type": "no_authentication",
            "basic_auth_profile": None,
        },
    ]
    client = FakeClient({**FULL_TABLES, "sys_rest_message": templated_messages})
    providers = load_providers()
    notes = []
    tools, _, tools_by_name = shadow._tier2_rest_message_tools(client, providers, notes)

    # only the one whose *name* carries a provider keyword gets a finding —
    # a templated endpoint with no other signal stays silently unmatched,
    # same as before, since there's still nothing to anchor a finding to
    assert [t.name for t in tools] == ["Anthropic Gateway (env-specific)"]
    assert tools[0].confidence == Confidence.NEEDS_REVIEW
    assert "template variable" in tools[0].description
    assert "Anthropic Gateway (env-specific)" in tools_by_name


def test_has_unresolved_template_var():
    assert shadow._has_unresolved_template_var("https://${host}/v1/messages")
    assert not shadow._has_unresolved_template_var("https://api.anthropic.com/v1/messages")
    assert not shadow._has_unresolved_template_var("")
    assert not shadow._has_unresolved_template_var(None)


def test_tier4_correlates_confirmed_caller_and_flags_ad_hoc_call_separately():
    """This is the bug the fresh-eyes review caught: the confirmed case
    (a script calling an already-matched REST message by name) used to
    produce NO agent at all, and the ad hoc case used to produce an
    agent with no tool_ids — floating, disconnected from the graph.
    Both are fixed here."""
    client = FakeClient({**FULL_TABLES})
    providers = load_providers()
    notes = []

    _, _, tools_by_name = shadow._tier2_rest_message_tools(client, providers, notes)
    agents, synthesized_tools = shadow._tier4_script_agents(client, providers, tools_by_name, notes)
    names = {a.name for a in agents}

    assert "UnrelatedHelper" not in names

    confirmed = next(a for a in agents if a.name == "ClaudeBridgeHelper")
    assert confirmed.provenance == Provenance.SYNTHESIZED
    assert confirmed.confidence == Confidence.CONFIRMED
    assert confirmed.tool_ids == ["rm3"]  # linked to the real Claude Bridge tool, not floating

    ad_hoc = next(a for a in agents if a.name == "AdHocOpenAICaller")
    assert ad_hoc.confidence == Confidence.NEEDS_REVIEW
    assert "openai" in ad_hoc.detection_signal
    assert len(ad_hoc.tool_ids) == 1  # linked to a synthesized placeholder tool, not floating
    assert synthesized_tools[0].id == ad_hoc.tool_ids[0]
    assert synthesized_tools[0].confidence == Confidence.NEEDS_REVIEW


def test_fetch_shadow_skips_script_scan_by_default():
    client = FakeClient(FULL_TABLES)
    agents, tools, credentials, owners, notes = shadow.fetch_shadow(client)

    # tier 2 still runs by default (metadata-only, lower privilege)
    assert len(tools) == 1
    # tiers 3-4 did not run
    assert len(agents) == 0
    assert any("skipped" in n.lower() for n in notes)


def test_fetch_shadow_with_script_scan_enabled():
    client = FakeClient(FULL_TABLES)
    agents, tools, credentials, owners, notes = shadow.fetch_shadow(client, include_script_scan=True)

    assert len(agents) == 2  # confirmed caller + ad hoc caller
    # 1 confirmed REST message tool + 1 synthesized placeholder tool for the ad hoc case
    assert len(tools) == 2


def test_fetch_shadow_degrades_gracefully_when_a_table_is_denied():
    client = FakeClient(FULL_TABLES, deny={"sys_rest_message"})
    agents, tools, credentials, owners, notes = shadow.fetch_shadow(client)

    assert tools == []
    assert any("access denied" in n.lower() and "sys_rest_message" in n for n in notes)


def test_references_tool_uses_word_boundaries_not_substring():
    """_references_tool's docstring always claimed word-boundary
    matching, but the implementation was a plain `re.search` over the
    escaped name with only a length floor guarding it — that's still a
    substring match. A REST message named 'Chat' would falsely match
    inside 'ChatHistoryUtils', an unrelated identifier that merely
    contains 'Chat' as a substring. Proves the fix without going
    through the full tier-4 pipeline."""
    assert shadow._references_tool("var x = new sn_ws.RESTMessageV2('Chat', 'post');", "Chat")
    assert not shadow._references_tool("var h = new ChatHistoryUtils();", "Chat")
    # still matches when surrounded by non-word boundary characters
    assert shadow._references_tool("call('Claude Bridge')", "Claude Bridge")


def test_tier1_and_tier2_credentials_get_owner_resolved():
    """sys_created_by (or the closest available proxy) was being fetched
    into every tier's raw data and then never actually used to resolve
    an owner for anything except tier-4 agents — a real accuracy gap.
    Both tier-1 OAuth credentials and tier-2 REST message credentials
    should now come back with owner_id resolved via fetch_shadow's
    unified owner-resolution pass."""
    client = FakeClient(FULL_TABLES)
    agents, tools, credentials, owners, notes = shadow.fetch_shadow(client)

    oauth_cred = next(c for c in credentials if c.id == "oa1")
    assert oauth_cred.owner_id == "u_brian"

    rest_cred = next(c for c in credentials if c.id == "cred1")
    assert rest_cred.owner_id == "u_brian"  # proxied from the REST message's creator

    assert any(o.id == "u_brian" for o in owners)


def test_tier4_populates_target_table_for_business_rules_only():
    """Business Rules carry a `collection` field — the table they fire
    against — which is real, already-fetched data (see tables.py's
    BUSINESS_RULE_FIELDS). Script Includes have no such field, so
    target_table should stay None there even though both get agents."""
    business_rules = [
        {
            "sys_id": "br1",
            "name": "IncidentClaudeSummarizer",
            "script": "// summarizes via Claude Bridge\nnew sn_ws.RESTMessageV2('Claude Bridge', 'post');",
            "active": "true",
            "when": "after",
            "collection": "incident",
            "sys_created_by": "brian",
        },
    ]
    tables = {**FULL_TABLES, "sys_script": business_rules}
    client = FakeClient(tables)
    providers = load_providers()
    notes = []

    _, _, tools_by_name = shadow._tier2_rest_message_tools(client, providers, notes)
    agents, _ = shadow._tier4_script_agents(client, providers, tools_by_name, notes)

    br_agent = next(a for a in agents if a.name == "IncidentClaudeSummarizer")
    assert br_agent.target_table == "incident"

    si_agent = next(a for a in agents if a.name == "ClaudeBridgeHelper")
    assert si_agent.target_table is None


def test_tier4_unwraps_a_dict_shaped_collection_reference_field():
    """collection (Business Rule -> table it fires on) is a reference
    field by long-standing ServiceNow convention. A raw {"link","value"}
    dict here — the same shape sys_user.department was directly observed
    to return live — would make SensitiveTableAccessRule's
    `target_table not in config.sensitive_tables` raise TypeError
    (unhashable dict), not just silently mismatch. ref() must unwrap it."""
    business_rules = [
        {
            "sys_id": "br2",
            "name": "IncidentClaudeSummarizerV2",
            "script": "// summarizes via Claude Bridge\nnew sn_ws.RESTMessageV2('Claude Bridge', 'post');",
            "active": "true",
            "when": "after",
            "collection": {"link": "https://x.service-now.com/api/now/table/sys_db_object/incident", "value": "incident"},
            "sys_created_by": "brian",
        },
    ]
    tables = {**FULL_TABLES, "sys_script": business_rules}
    client = FakeClient(tables)
    providers = load_providers()
    notes = []

    _, _, tools_by_name = shadow._tier2_rest_message_tools(client, providers, notes)
    agents, _ = shadow._tier4_script_agents(client, providers, tools_by_name, notes)  # must not raise

    br_agent = next(a for a in agents if a.name == "IncidentClaudeSummarizerV2")
    assert br_agent.target_table == "incident"  # unwrapped, not the dict


def test_scripted_rest_api_that_calls_an_llm_is_reported_outbound_too_not_just_inbound():
    """A bridge endpoint — receive request, call the model, return the
    answer — is BOTH an inbound surface and an outbound integration.
    Tier 3 only ever asked the inbound question, so the outbound half
    of exactly this shape went unreported.

    Not hypothetical: confirmed against a real custom app built
    independently of this project, whose /start endpoint has precisely
    this structure. Reporting only 'something can call into this
    instance' while staying silent on 'and it calls Anthropic' describes
    half an integration.
    """
    client = FakeClient({
        "sys_ws_operation": [{
            "sys_id": "op1",
            "name": "Start run",
            "relative_path": "/start",
            "http_method": "POST",
            "operation_script": (
                "var r = new sn_ws.RESTMessageV2();\n"
                "r.setEndpoint('https://api.anthropic.com/v1/messages');\n"
            ),
            "sys_created_by": "admin",
        }]
    })
    agents, tools, _creds, _owners, _notes = shadow.fetch_shadow(client, include_script_scan=True)

    inbound = [t for t in tools if t.direction == "inbound"]
    assert inbound, "tier 3 should still flag the inbound surface"

    outbound_agents = [a for a in agents if a.name == "Start run"]
    assert outbound_agents, "the outbound LLM call must be reported as an agent too"
    assert "scripted_rest_api" in outbound_agents[0].detection_signal
    assert outbound_agents[0].tool_ids, "must be graph-connected, not a floating node"


def test_service_portal_widget_calling_an_llm_is_detected():
    """Where a chat UI actually lives. Nothing about a widget touches
    Script Include / Business Rule / Scheduled Job, so the original
    tier-4 table set could not see a user-facing agent at all."""
    client = FakeClient({
        "sp_widget": [{
            "sys_id": "w1", "name": "AI Assistant", "id": "ai_assistant",
            "script": "data.reply = callAnthropic(input.prompt); // anthropic",
            "sys_created_by": "admin",
        }]
    })
    agents, _tools, _c, _o, _n = shadow.fetch_shadow(client, include_script_scan=True)
    assert any(a.name == "AI Assistant" for a in agents)
    assert "service_portal_widget" in agents[0].detection_signal


def test_ui_action_target_table_feeds_sensitive_table_scoring():
    """UI Actions carry the acted-on table as `table`, not `collection`
    — same signal, different field name. Without this the sensitive-table
    impact rule silently scored every UI-action agent as 'not
    determined'."""
    client = FakeClient({
        "sys_ui_action": [{
            "sys_id": "u1", "name": "Summarize with AI", "table": "incident",
            "active": "true", "script": "// calls openai for a summary",
            "sys_created_by": "admin",
        }]
    })
    agents, *_ = shadow.fetch_shadow(client, include_script_scan=True)
    assert agents[0].target_table == "incident"
