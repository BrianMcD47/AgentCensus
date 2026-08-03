"""The worst defect this project has had: eight wrong field names.

`sys_rest_message.endpoint` should have been `rest_endpoint`. Tier 2 —
the only CONFIRMED-grade outbound detection in the product, the thing the
tool exists for — requested a column that has never existed, on every
instance, for the whole life of the project. Every "0 outbound LLM REST
messages" it ever printed was that typo.

Seven more like it: `sys_rest_message_fn.endpoint`,
`sys_connection.connection_url` (real, but only on the `http_connection`
child), `sys_hub_action_instance.name` and `.active` (that table has five
columns and neither is one of them), both NASK `name` fields, and
`sn_build_agent_skill_resource.name`.

Why it survived four independent code reviews, two live scans, and a
suite of 190 tests:

  1. ServiceNow omits a nonexistent requested field EXACTLY as it omits a
     denied one — absent from the row, HTTP 200, no error anywhere.
  2. The v17 field-blindness machinery, built specifically to stop this
     tool mistaking "could not see" for "nothing there", had only ONE
     explanation available. So it reported FIELD-LEVEL ACL for both, and
     rendered a bug in this project's own tables.py as a permissions
     problem on the customer's instance — complete with advice to go ask
     their admin for access to a column that does not exist.
  3. The test fixtures used the same wrong names, so the suite agreed
     with the code while both disagreed with the platform.

The generalizable lesson, and the reason this file exists rather than
just a corrected constant: **a diagnostic that can name only one cause
will name that cause for every symptom.** A crash would have been found
in an hour. A fluent, plausible, wrong explanation survived indefinitely
and was actively believed.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from agentcensus.connectors.servicenow import tables
from agentcensus.connectors.servicenow.http import ServiceNowClient
from agentcensus.core.models import AccessGapKind


def _client():
    return ServiceNowClient(instance_url="https://x.service-now.com", username="u", password="p")


def _resp(rows):
    r = MagicMock()
    r.status_code = 200
    r.headers = {}
    r.json.return_value = {"result": rows}
    r.raise_for_status.side_effect = None
    return r


def _schema_aware(table_rows, columns, parent=None):
    """Mock that answers data reads, sys_dictionary and sys_db_object.

    The dictionary lookup is what makes the two causes distinguishable at
    all, so a fixture that can't answer it can't test the fix.
    """
    def handler(url, **kwargs):
        params = kwargs.get("params", {})
        query = params.get("sysparm_query", "")
        offset = int(params.get("sysparm_offset", 0) or 0)

        if "/sys_dictionary" in url:
            # Paginated like everything else: `get_all` stops on an EMPTY
            # page, not a short one (a deliberate fix for real
            # undercounting). A mock that returns the same page forever
            # therefore runs to the 10,000-row safety cap — which is what
            # this fixture did first, turning a 7-test file into 38
            # seconds of pointless looping.
            if "elementISNOTEMPTY" not in query or offset:
                return _resp([])
            owner = query.split("name=")[1].split("^")[0]
            return _resp([{"element": c} for c in columns.get(owner, [])])

        if "/sys_db_object" in url:
            # Models the TWO-READ parent lookup, not a dot-walk.
            #
            # This fixture previously returned `{"super_class.name": ...}`,
            # i.e. it asserted that the Table API honours a dot-walk in
            # `sysparm_fields` — while `tables.py`, two files away,
            # recorded a live measurement that it does not. A round-5
            # reviewer caught it, and correctly named it as the same
            # post-mortem as the `rest_endpoint` bug: a fixture encoding
            # the author's model of the platform rather than the
            # platform's measured behaviour, so the suite agreed with the
            # code while both were unmoored from reality.
            #
            # Parent sys_ids are synthesized as "id::<name>" so the second
            # read can resolve them without a lookup table.
            if "sys_id=" in query:
                pid = query.split("sys_id=")[1].split("^")[0]
                return _resp([{"name": pid.removeprefix("id::")}])
            owner = query.split("name=")[1].split("^")[0] if "name=" in query else ""
            parent_name = (parent or {}).get(owner)
            return _resp([{"super_class": f"id::{parent_name}"}] if parent_name else [{}])

        return _resp(table_rows if not offset else [])
    return handler


# ---------------------------------------------------------------------
# the distinction
# ---------------------------------------------------------------------

def test_a_nonexistent_field_is_reported_as_our_bug_not_their_acl():
    """The whole point. Asking for a column the platform doesn't have must
    NOT tell the customer to go get permissions — there is nothing to
    grant, and sending a security team to widen access on a production
    instance to fix a typo in this repo is worse than saying nothing."""
    client = _client()
    with patch("requests.get", side_effect=_schema_aware(
        [{"sys_id": "1", "name": "x"}],
        {"sys_rest_message": ["sys_id", "name", "rest_endpoint"]},
    )):
        _rows, note = client.safe_get_all("sys_rest_message", ["sys_id", "name", "endpoint"])

    assert "SCHEMA MISMATCH" in note
    assert "DO NOT EXIST" in note
    assert "defect in AgentCensus" in note
    # Must not send them to their admin.
    assert "FIELD-LEVEL ACL" not in note
    assert "Grant the scan account" not in note

    gap = client.access_gaps[0]
    assert gap.kind is AccessGapKind.SCHEMA_MISMATCH
    assert "no grant" in gap.grant


def test_a_genuinely_denied_field_still_reports_as_an_acl():
    """Control, and the case that must keep working. `gen_ai_service_secret`
    withheld `sys_created_by` on a live instance — a column that exists on
    every ServiceNow table, so that one is real. If the fix made everything
    read as a schema bug it would just be the same error mirrored."""
    client = _client()
    with patch("requests.get", side_effect=_schema_aware(
        [{"sys_id": "1", "name": "x"}],
        {"gen_ai_service_secret": ["sys_id", "name", "sys_created_by"]},
    )):
        _rows, note = client.safe_get_all(
            "gen_ai_service_secret", ["sys_id", "name", "sys_created_by"]
        )

    assert "FIELD-LEVEL ACL" in note
    assert "SCHEMA MISMATCH" not in note
    assert client.access_gaps[0].kind is AccessGapKind.FIELD_ACL


def test_both_causes_in_one_read_are_reported_separately():
    """They demand opposite actions from the reader — go ask for access
    vs. do not ask for anything — so collapsing them into one sentence
    would reintroduce the original defect at a smaller scale."""
    client = _client()
    with patch("requests.get", side_effect=_schema_aware(
        [{"sys_id": "1"}],
        {"t": ["sys_id", "real_but_denied"]},
    )):
        _rows, note = client.safe_get_all("t", ["sys_id", "real_but_denied", "not_a_column"])

    assert "SCHEMA MISMATCH" in note and "not_a_column" in note
    assert "FIELD-LEVEL ACL" in note and "real_but_denied" in note
    kinds = {g.kind for g in client.access_gaps}
    assert kinds == {AccessGapKind.SCHEMA_MISMATCH, AccessGapKind.FIELD_ACL}


def test_inherited_columns_are_not_reported_as_nonexistent():
    """`sys_dictionary` lists a table's OWN columns, so `sys_created_by` on
    `sys_rest_message` lives on an ancestor. Without walking `super_class`,
    every inherited field would be called a schema bug — a false positive
    on nearly every table, which would make the whole diagnostic
    untrustworthy and therefore ignored. That failure mode is how the
    original bug survived: a signal nobody believes is worse than none."""
    client = _client()
    with patch("requests.get", side_effect=_schema_aware(
        [{"sys_id": "1"}],
        {"child": ["sys_id"], "sys_metadata": ["sys_created_by"]},
        parent={"child": "sys_metadata"},
    )):
        _rows, note = client.safe_get_all("child", ["sys_id", "sys_created_by"])

    assert "SCHEMA MISMATCH" not in note
    assert "FIELD-LEVEL ACL" in note


def test_unknown_schema_fails_open_and_claims_neither_cause():
    """If the dictionary itself can't be read, the tool does not know which
    it is looking at — and must not guess. Guessing "your ACL" was the
    original bug; guessing "our bug" would be the same overconfidence
    pointed the other way."""
    client = _client()
    with patch("requests.get", side_effect=_schema_aware([{"sys_id": "1"}], {})):
        _rows, note = client.safe_get_all("t", ["sys_id", "whatever"])

    assert "FIELD-LEVEL ACL" in note
    assert "SCHEMA MISMATCH" not in note


# ---------------------------------------------------------------------
# the specific names, so they cannot silently revert
# ---------------------------------------------------------------------

def test_the_corrected_field_names_are_the_real_ones():
    """Verified against sys_dictionary on a live instance (2026-08). Named
    explicitly because a rename is a one-character revert away and the
    consequence is a tier that silently detects nothing."""
    assert tables.REST_ENDPOINT_FIELD == "rest_endpoint"
    assert "rest_endpoint" in tables.REST_MESSAGE_FIELDS
    assert "rest_endpoint" in tables.REST_MESSAGE_FN_FIELDS
    assert "endpoint" not in tables.REST_MESSAGE_FIELDS
    assert "endpoint" not in tables.REST_MESSAGE_FN_FIELDS

    # The base connection table has no URL column; the child does.
    assert "host" in tables.CONNECTION_FIELDS
    assert "connection_url" not in tables.CONNECTION_FIELDS
    assert "connection_url" in tables.HTTP_CONNECTION_FIELDS

    # Five real columns; `name`/`active` are not among them. And NO
    # dot-walk: measured live, the Table API does not honour
    # `action_type.name` in sysparm_fields — it silently returns neither
    # an error nor the key. The action type is joined client-side from its
    # own table instead, which is verifiable.
    assert "name" not in tables.HUB_ACTION_INSTANCE_FIELDS
    assert "active" not in tables.HUB_ACTION_INSTANCE_FIELDS
    assert tables.HUB_ACTION_TYPE_TABLE == "sys_hub_action_type_base"
    assert not any("." in f for f in tables.HUB_ACTION_INSTANCE_FIELDS)

    for field_list in (tables.NASK_PROVIDER_MAPPING_FIELDS, tables.NASK_MODEL_CONFIG_FIELDS):
        assert "name" not in field_list
    assert "provider" in tables.NASK_PROVIDER_MAPPING_FIELDS
    assert "model_display_name" in tables.NASK_MODEL_CONFIG_FIELDS

    assert "filename" in tables.BUILD_AGENT_SKILL_RESOURCE_FIELDS
    assert "name" not in tables.BUILD_AGENT_SKILL_RESOURCE_FIELDS


def test_the_secret_column_is_still_never_requested():
    """`gen_ai_service_secret` gained `name`/`purpose`/`state` in the same
    pass that corrected the other names. Widening a field list is exactly
    when a secret column gets added by accident."""
    for table, fields, _label in tables.GENAI_SECRET_TABLES:
        assert "secret" not in fields, table


# ---------------------------------------------------------------------
# ServiceNow `!=` does not match NULL
# ---------------------------------------------------------------------

def test_the_property_query_lets_empty_typed_rows_through():
    """Measured live (2026-08): `sys_properties` held 3,673 rows, the
    exclusion query returned 3,657, and the 16 missing were 12 genuinely
    encrypted (correct) plus 4 with an EMPTY `type` — dropped at the
    database because ServiceNow's `!=` does not match NULL.

    Why four records mattered: config_surfaces fails closed on an
    unrecognised type AND emits a COVERAGE GAP note naming it, so that a
    property this tier declines to read is still reported. Those rows
    never arrived, so the note could not fire. A guard and its own alarm,
    both bypassed by a NULL.

    The client-side check is where the guarantee lives; the server-side
    filter is defence in depth for keeping encrypted VALUES off the wire,
    not the thing that decides what gets examined."""
    assert "typeISEMPTY" in tables.SYS_PROPERTIES_QUERY
    assert "^OR" in tables.SYS_PROPERTIES_QUERY
    # The exclusions themselves must survive the addition.
    assert "type!=password" in tables.SYS_PROPERTIES_QUERY


def test_an_empty_typed_property_is_examined_not_refused():
    """Corrects an assumption made while fixing the query above.

    An empty `type` is an ALLOWED type here — `''` and `'none'` are both
    in NON_SECRET_PROPERTY_TYPES, added during the live-data widening
    because ServiceNow's own type picker offers "-- None --" as a real
    choice. So the four properties the `!=` filter was dropping are not
    "refused but now reported"; they are now EXAMINED, having never been
    looked at before. A detection gain, not a reporting one.

    The guard that still protects them is `_name_implies_credential`: a
    typeless property called `x_acme.api_key` has its value withheld on
    the strength of its name, which is the check that matters for an
    entity-attribute-value table.

    An unknown type — as opposed to an empty one — still fails closed."""
    from agentcensus.connectors.servicenow.config_surfaces import (
        _is_secret_property,
        _name_implies_credential,
    )

    assert not _is_secret_property({"type": ""})
    assert not _is_secret_property({})
    assert _is_secret_property({"type": "some_type_invented_in_2029"})
    # ...and the name-based guard is what covers the risky case.
    assert _name_implies_credential({"name": "x_acme.anthropic.api_key"})


def test_the_credential_reassurance_is_not_gated_on_a_count_that_is_always_zero():
    """The note explaining that encrypted properties are deliberately
    untouched fired only when a counter was non-zero — and that counter is
    always zero, because those rows are excluded server-side and never
    reach the loop that counts them. The reassurance never appeared in any
    report."""
    from agentcensus.connectors.servicenow.config_surfaces import _fetch_properties
    from tests.servicenow_fakes import FakeClient

    client = FakeClient({tables.SYS_PROPERTIES_TABLE: [
        {"sys_id": "p1", "name": "glide.ui.theme", "value": "blue", "type": "string"},
    ]})
    notes: list[str] = []
    _fetch_properties(client, [], notes)
    joined = " ".join(notes)
    assert "never reads credential material" in joined
    # And makes no claim about a number it cannot observe.
    assert "0 system propert" not in joined


def test_a_count_and_the_list_it_summarises_come_from_one_source():
    """A live run printed "2 provider/model configuration(s) found — VA
    Azure OpenAI, gpt-4o" while the inventory held three NASK tools.
    Counting one sequence and naming a filtered subset of it is two
    sources of truth for one sentence, and a reader cannot audit a count
    against a list built differently."""
    from agentcensus.connectors.servicenow import nask
    from tests.servicenow_fakes import FakeClient

    client = FakeClient({
        tables.NASK_PROVIDER_MAPPING_TABLE: [
            {"sys_id": "a", "provider": "VA Azure OpenAI", "active": "true"},
            {"sys_id": "b", "provider": "AmazonBedrockHandler", "active": "true"},
        ],
        tables.NASK_MODEL_CONFIG_TABLE: [
            {"sys_id": "c", "model_display_name": "gpt-4o", "active": "true"},
        ],
    })
    tools, notes = nask.fetch_nask(client)
    note = next(n for n in notes if "Now Assist Skill Kit" in n)

    assert f"{len(tools)} provider/model configuration(s)" in note
    for tool in tools:
        assert tool.name in note, f"counted but not named: {tool.name}"


def test_the_property_tier_reports_that_it_ran():
    """Connections say "no records matched"; properties said nothing at
    all when they found nothing, so a reader could not tell an empty
    result from a tier that never executed."""
    from agentcensus.connectors.servicenow.config_surfaces import _fetch_properties
    from tests.servicenow_fakes import FakeClient

    client = FakeClient({tables.SYS_PROPERTIES_TABLE: [
        {"sys_id": "p1", "name": "glide.ui.theme", "value": "blue", "type": "string"},
        {"sys_id": "p2", "name": "glide.foo", "value": "1", "type": "integer"},
    ]})
    notes: list[str] = []
    _fetch_properties(client, [], notes)
    assert any("2 examined" in n for n in notes)
