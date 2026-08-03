"""Tests for the config-surface tier (system properties, connection
aliases) and domain-scope awareness.

The scenario driving most of these is the one the original four tiers
were structurally blind to: an integration that does everything RIGHT —
endpoint in a system property or a connection alias instead of
hardcoded in a script — and was therefore less visible than a sloppy
one. That inversion is the bug these tests pin down.
"""

from __future__ import annotations

import json

from agentcensus.connectors.servicenow import domain_scope
from agentcensus.connectors.servicenow.config_surfaces import fetch_config_surfaces
from agentcensus.connectors.servicenow.llm_providers import load_providers
from agentcensus.core.models import Confidence
from tests.servicenow_fakes import FakeClient


def _providers():
    return load_providers()


def test_property_holding_a_provider_url_is_confirmed_not_heuristic():
    """The whole point: this is a literal hostname in a dedicated
    value field, structurally identical evidence to tier 2's REST
    message endpoint, so it earns tier 2's confidence."""
    client = FakeClient({
        "sys_properties": [{
            "sys_id": "p1", "name": "x_acme.llm_endpoint", "type": "string",
            "value": "https://api.anthropic.com/v1/messages", "sys_created_by": "admin",
        }]
    })
    tools, notes = fetch_config_surfaces(client, _providers())

    assert len(tools) == 1
    assert tools[0].confidence == Confidence.CONFIRMED
    assert tools[0].direction == "outbound"
    assert "Anthropic" in tools[0].description


def test_password_typed_property_is_skipped_without_reading_its_value():
    """sys_properties is the one table here whose value field can
    legitimately hold an API key — it's where a well-built integration
    is *supposed* to put one. A correctly-stored key must be invisible
    to this scan, and must not leak into the notes either."""
    secret = "sk-ant-api03-MUSTNOTAPPEAR000000000000000000"
    client = FakeClient({
        "sys_properties": [{
            "sys_id": "p1", "name": "x_acme.anthropic_api_key",
            "type": "password (2 way encrypted)", "value": secret,
            "sys_created_by": "admin",
        }]
    })
    tools, notes = fetch_config_surfaces(client, _providers())

    assert tools == []
    blob = json.dumps(notes)
    assert secret not in blob
    assert "never reads credential material" in blob


def test_plaintext_key_in_a_string_typed_property_is_redacted_not_republished():
    """A key stored in a `string` property is a real finding — the
    customer needs to know it's there. The report just must not repeat
    it, or the scanner becomes the leak."""
    secret = "sk-ant-api03-PLAINTEXTLEAK00000000000000000000"
    client = FakeClient({
        "sys_properties": [{
            "sys_id": "p1", "name": "x_acme.llm_gateway_url", "type": "string",
            "value": f"https://api.anthropic.com/v1?api_key={secret}",
            "sys_created_by": "admin",
        }]
    })
    tools, _ = fetch_config_surfaces(client, _providers())

    blob = json.dumps({"desc": tools[0].description, "raw": tools[0].raw})
    assert secret not in blob
    assert "api.anthropic.com" in blob  # host survives; it's the evidence


def test_internal_gateway_url_is_flagged_for_review_not_dropped():
    """An internal hostname can't match any bundled provider list, ever.
    Dropping it silently would mean the customers who took AI governance
    most seriously (and built a gateway) get the emptiest reports."""
    client = FakeClient({
        "sys_properties": [{
            "sys_id": "p1", "name": "x_acme.llm_gateway_url", "type": "string",
            "value": "https://ai-gateway.internal.acme.corp/v1/chat",
            "sys_created_by": "admin",
        }]
    })
    tools, _ = fetch_config_surfaces(client, _providers())

    assert len(tools) == 1
    assert tools[0].confidence == Confidence.NEEDS_REVIEW
    assert "--llm-providers-extra" in tools[0].description


def test_ordinary_properties_are_ignored():
    client = FakeClient({
        "sys_properties": [
            {"sys_id": "p1", "name": "glide.ui.polaris", "type": "boolean", "value": "true"},
            {"sys_id": "p2", "name": "glide.email.smtp.host", "type": "string",
             "value": "smtp.acme.com"},
        ]
    })
    tools, _ = fetch_config_surfaces(client, _providers())
    assert tools == []


def test_connection_alias_pointing_at_a_provider_is_detected():
    """The ServiceNow-recommended alternative to hardcoding an endpoint
    on a REST message — invisible to tier 2 by construction."""
    client = FakeClient({
        "http_connection": [{
            "sys_id": "c1", "name": "OpenAI Prod",
            "connection_url": "https://api.openai.com/v1", "active": "true",
            "sys_created_by": "admin",
        }]
    })
    tools, _ = fetch_config_surfaces(client, _providers())

    names = [t.name for t in tools]
    assert "OpenAI Prod" in names
    assert all(t.confidence == Confidence.CONFIRMED for t in tools if t.name == "OpenAI Prod")


def test_denied_property_table_degrades_to_a_note_not_a_crash():
    client = FakeClient({"sys_properties": []}, deny={"sys_properties"})
    tools, notes = fetch_config_surfaces(client, _providers())
    assert tools == []
    assert any("Access denied" in n for n in notes)


def test_domain_separation_is_reported_when_present():
    """Silent under-reporting is the failure mode. An MSP scanning from
    a child domain gets a clean, complete-looking report covering one
    tenant — with nothing to prompt anyone to question the numbers."""
    client = FakeClient({
        "domain": [
            {"sys_id": "d0", "name": "global", "active": "true"},
            {"sys_id": "d1", "name": "ACME Corp", "active": "true"},
            {"sys_id": "d2", "name": "Beta Ltd", "active": "true"},
        ]
    })
    notes: list[str] = []
    domain_scope.check_domain_scope(client, notes)

    joined = " ".join(notes)
    assert "DOMAIN SEPARATION IS ACTIVE" in joined
    assert "ACME Corp" in joined
    assert "does not attempt to escalate" in joined


def test_no_domain_note_on_a_normal_single_domain_instance():
    """Only 'global' exists on every non-separated instance — warning
    about it would train users to ignore the warning."""
    client = FakeClient({"domain": [{"sys_id": "d0", "name": "global", "active": "true"}]})
    notes: list[str] = []
    domain_scope.check_domain_scope(client, notes)
    assert notes == []


def test_no_domain_note_when_the_plugin_is_absent():
    client = FakeClient({})
    notes: list[str] = []
    domain_scope.check_domain_scope(client, notes)
    assert notes == []
