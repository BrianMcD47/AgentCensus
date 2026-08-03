"""Failing tests demonstrating defects found in independent review.

Every test in this file FAILS against the current implementation. Each
one is a concrete input -> wrong behaviour, not a style objection. They
are grouped by the guard that misses them.

The common shape, matching this project's existing bug history: a guard
that is well-built and well-reasoned but aimed one level too shallow,
so it passes its own test while the thing it protects against walks
past it.
"""

from __future__ import annotations

import datetime
import html as htmlmod
import json

from agentcensus.connectors.servicenow.config_surfaces import fetch_config_surfaces
from agentcensus.connectors.servicenow.llm_providers import load_providers
from agentcensus.connectors.servicenow.shadow import fetch_shadow
from agentcensus.connectors.splunk.http import SplunkClient
from agentcensus.core.models import Inventory
from agentcensus.core.redaction import scrub_values
from agentcensus.core.report import render_html, to_json
from agentcensus.core.scan import run_scan
from tests.servicenow_fakes import FakeClient

_SECRET = "REVIEWCANARY9182736455SECRET"


def _inventory(**kw):
    return Inventory(
        platform="servicenow",
        scanned_at=datetime.datetime.now(datetime.timezone.utc),
        **kw,
    )


# ---------------------------------------------------------------------
# 1. _final_scrub is format-dependent, not universal.
#
#    report._final_scrub runs AFTER json.dumps and AFTER html.escape.
#    Both of those rewrite the exact delimiter characters the redaction
#    patterns key on:
#       html.escape:  &  ->  &amp;     "  ->  &quot;    '  ->  &#x27;
#       json.dumps:   "  ->  \"
#    So the "no path around it, no field it doesn't cover" backstop has
#    large holes that depend only on output format and token position.
# ---------------------------------------------------------------------


def test_final_scrub_redacts_a_secret_query_param_that_is_not_the_first_param():
    """html.escape turns `&` into `&amp;`, so parse_qsl splits the query
    on the wrong boundary and yields the parameter name `amp;api_key`,
    which is not in _SECRET_QUERY_PARAMS. The secret survives, AND the
    URL is corrupted to `&amp%3Bapi_key=` in the process.

    The existing adversarial test
    (test_redaction.test_no_planted_secret_survives_any_field_of_either_output_format)
    misses this by one character: its planted URL puts `api_key` FIRST,
    where there is no preceding `&` to be escaped.
    """
    url = f"https://gw.corp/v1/chat?model=gpt-4&api_key={_SECRET}"
    escaped = htmlmod.escape(url)  # what render_html feeds to _final_scrub

    assert _SECRET not in scrub_values(escaped)


def test_final_scrub_redacts_a_double_quoted_assignment_inside_serialized_json():
    """json.dumps escapes `"` to `\\"`, so _ASSIGNED_SECRET_PATTERN's
    `(["'])` never matches the opening quote of a double-quoted
    assignment. Single-quoted assignments are caught; double-quoted
    ones - the more common form in JavaScript - are not.

    This is the layer whose stated purpose is catching "bespoke and
    internal credential formats the prefix list can't know about".
    """
    serialized = json.dumps({"note": f'var apiKey = "{_SECRET}";'})

    assert _SECRET not in scrub_values(serialized)


def test_final_scrub_redacts_an_assignment_inside_rendered_html():
    """html.escape turns both quote characters into entities, so
    _ASSIGNED_SECRET_PATTERN can never fire in the HTML report at all -
    zero coverage, not reduced coverage.
    """
    escaped = htmlmod.escape(f"var apiKey = '{_SECRET}';")

    assert _SECRET not in scrub_values(escaped)


def test_credential_query_params_are_redacted_in_relative_urls_too():
    """_redact_url_credentials only matches `https?://...`. A bare path
    with a query string - which is exactly what a ServiceNow
    `relative_path`, a `setEndpoint('/proxy?...')` fragment, or a
    property value holding a path is - is never examined at all.
    """
    assert _SECRET not in scrub_values(f"/v1/chat?model=gpt-4&api_key={_SECRET}")


def test_end_to_end_secret_in_relative_path_does_not_reach_the_html_report():
    """The live path for the two bugs above, using a real field.

    A Scripted REST API resource whose `relative_path` carries a
    credential query parameter. tier 3 embeds relative_path verbatim
    into the tool description (it is never pre-scrubbed), the
    description becomes the finding explanation, and the finding
    explanation is rendered into the HTML report a governance lead
    actually reads.
    """
    client = FakeClient({
        "sys_ws_operation": [{
            "sys_id": "w1",
            "name": "assistant bridge",
            "relative_path": f"/proxy?model=gpt-4&api_key={_SECRET}",
            "operation_script": "// anthropic",
            "sys_created_by": "admin",
        }],
    })
    agents, tools, creds, owners, notes = fetch_shadow(client, include_script_scan=True)
    inv = _inventory(agents=agents, tools=tools, credentials=creds,
                     owners=owners, scan_notes=notes)
    findings, graph = run_scan(inv)

    assert tools, "fixture must actually detect something, or the test is vacuous"
    assert _SECRET not in to_json(inv, findings, graph)
    assert _SECRET not in render_html(inv, findings, graph)


# ---------------------------------------------------------------------
# 2. sys_properties is an entity-attribute-value table: the semantic
#    field name lives in a row's `name` VALUE, not in a dict KEY. The
#    key-name redaction layer only ever inspects dict keys, so it is
#    structurally unable to protect this table - the one table the
#    module docstring itself calls out as "where a value field can
#    legitimately hold an API key".
# ---------------------------------------------------------------------


def test_a_plaintext_credential_in_a_string_typed_property_is_not_written_verbatim():
    """A property named `x_acme.anthropic.api_key`, typed `string`
    (which is the misconfiguration worth flagging in the first place),
    holding a bespoke internal token.

    It is detected - the name matches the `anthropic` keyword - and
    `raw=scrub(entry)` then stores the whole row. scrub() sees dict keys
    sys_id/name/type/value/description, none of which is secret-named,
    and a value with no recognised prefix shape. The credential is
    written to the report verbatim.

    config_surfaces.py's docstring claims guard 2 covers this: "a
    plaintext key sitting in a property typed `string` (which happens
    constantly, and is itself worth flagging) is redacted on the way
    into the report." It is not.
    """
    client = FakeClient({
        "sys_properties": [{
            "sys_id": "p1",
            "name": "x_acme.anthropic.api_key",
            "type": "string",
            "value": _SECRET,
            "description": "gateway credential",
        }],
    })
    tools, notes = fetch_config_surfaces(client, load_providers())
    inv = _inventory(tools=tools, scan_notes=notes)
    findings, graph = run_scan(inv)

    assert tools, "fixture must actually detect the property, or the test is vacuous"
    assert _SECRET not in to_json(inv, findings, graph)


def test_secret_property_skip_is_not_defeated_by_an_unexpected_type_value():
    """`_is_secret_property` is an exact-match lookup against a
    hand-written set of five lowercase strings, on a field whose real
    values were never confirmed against a live instance.

    Any type string outside that set - a numeric glide type id, a
    differently-cased label, a scoped variant - and the credential is
    read, keyword-matched, and stored. A guard on credential material
    should fail closed on an unrecognised type, not open.
    """
    client = FakeClient({
        "sys_properties": [{
            "sys_id": "p2",
            "name": "x_acme.anthropic.gateway_secret",
            "type": "glide_encrypted_2way",  # real-looking, not in the set
            "value": _SECRET,
            "description": "",
        }],
    })
    tools, notes = fetch_config_surfaces(client, load_providers())
    inv = _inventory(tools=tools, scan_notes=notes)
    findings, graph = run_scan(inv)

    assert _SECRET not in to_json(inv, findings, graph)


# ---------------------------------------------------------------------
# 3. Splunk pagination advances the cursor by a different number than it
#    asked for.
# ---------------------------------------------------------------------


def test_splunk_get_all_does_not_skip_rows_when_the_final_window_is_short():
    """`get_all` requests `min(count, remaining)` rows but advances
    `offset += count`. On every iteration where `remaining < count` -
    i.e. as the safety cap is approached - the cursor jumps further than
    the window that was actually requested, and the rows in between are
    never asked for.

    ServiceNow's `get_all`, which this docstring explicitly says it
    mirrors, gets this right: it advances by `page_size`, the same value
    it passed to the server.

    The failure is silent in the worst way: because rows are skipped,
    the result set can finish BELOW max_records, so `safe_get_all`
    reports a clean complete read with no truncation note.
    """
    total = 260
    requested: list[tuple[int, int]] = []

    class ShortPageClient(SplunkClient):
        def _get_page(self, endpoint, count, offset):
            requested.append((offset, count))
            rows = [{"name": f"row{i}"} for i in range(offset, min(offset + count, total))]
            # Splunk applies per-user ACL filtering to knowledge objects,
            # so a window can come back short without being the last -
            # this client's own docstring is built on that premise.
            return rows[:-1] if rows else rows

    client = ShortPageClient(base_url="https://splunk.example:8089", token="t", max_records=180)
    rows = client.get_all("/services/saved/searches", count=100)
    seen = {r["name"] for r in rows}

    covered = set()
    for offset, count in requested:
        covered.update(range(offset, offset + count))
    gaps = sorted(set(range(max(covered) + 1)) - covered)

    assert not gaps, (
        f"offsets never requested: {gaps[:10]}... "
        f"(windows requested: {requested})"
    )
    assert len(seen) >= 1


# ---------------------------------------------------------------------------
# Found while reviewing the review's own fixes.
# ---------------------------------------------------------------------------

def test_the_exclusion_escape_hatch_the_scan_note_advertises_actually_works():
    """D6a's filters emit a scan note telling the reader to pass
    `include_vendor_scope=True` to see what was dropped. When that fix
    first landed, the parameter existed only on the tier-4 helper — it
    was not on `fetch_shadow`, not threaded through the connector, and
    had no CLI flag. Findings were excluded by default with no reachable
    way to get them back short of editing source.

    Same failure shape the review was written to catch, one level
    further in: silently dropping findings is as bad as silently missing
    them, and an escape hatch that doesn't open is worse than none
    because the note claims otherwise. Asserts the whole chain, since
    each link was individually plausible and collectively broken.
    """
    from agentcensus.cli import build_parser
    from agentcensus.connectors.servicenow.shadow import fetch_shadow
    from tests.servicenow_fakes import FakeClient

    client = FakeClient({
        "sys_scope": [
            {"sys_id": "s1", "name": "Now Assist", "scope": "sn_nowassist"},
            {"sys_id": "s2", "name": "ACME", "scope": "x_acme"},
        ],
        "sys_script_include": [
            {"sys_id": "v1", "name": "VendorThing", "script": "// openai",
             "active": "true", "sys_scope": "s1", "sys_created_by": "admin"},
            {"sys_id": "c1", "name": "CustomerBot", "script": "// openai",
             "active": "true", "sys_scope": "s2", "sys_created_by": "admin"},
            {"sys_id": "i1", "name": "DisabledBot", "script": "// openai",
             "active": "false", "sys_scope": "s2", "sys_created_by": "admin"},
        ],
    })

    default, *_rest = fetch_shadow(client, include_script_scan=True)
    assert sorted(a.name for a in default) == ["CustomerBot"]

    with_vendor, *_rest = fetch_shadow(
        client, include_script_scan=True, include_vendor_scope=True)
    assert "VendorThing" in [a.name for a in with_vendor]

    with_inactive, *_rest = fetch_shadow(
        client, include_script_scan=True, include_inactive=True)
    assert "DisabledBot" in [a.name for a in with_inactive]

    # And the CLI exposes both, so the note's instruction is actionable.
    args = build_parser().parse_args(
        ["scan", "--connector", "servicenow", "--include-script-scan",
         "--include-vendor-scope", "--include-inactive"]
    )
    assert args.include_vendor_scope and args.include_inactive


def test_unrecognised_property_types_are_reported_as_a_coverage_gap_not_a_win():
    """`_is_secret_property` fails closed, which is right — but it means
    two very different things get skipped: properties that are genuinely
    encrypted (the guard working) and properties whose type nobody
    classified (a coverage gap, where an LLM endpoint may sit
    unexamined). Reporting both under one count hides the second behind
    the first — the 'looks complete, isn't' shape again.
    """
    from agentcensus.connectors.servicenow.config_surfaces import fetch_config_surfaces
    from agentcensus.connectors.servicenow.llm_providers import load_providers
    from tests.servicenow_fakes import FakeClient

    client = FakeClient({
        "sys_properties": [
            {"sys_id": "p1", "name": "a.key", "type": "password2", "value": "x"},
            {"sys_id": "p2", "name": "b.url", "type": "glide_url_unknown_type", "value": "y"},
        ]
    })
    _tools, notes = fetch_config_surfaces(client, load_providers())
    blob = " ".join(notes)

    assert "guard working as intended" in blob
    assert "COVERAGE GAP" in blob
