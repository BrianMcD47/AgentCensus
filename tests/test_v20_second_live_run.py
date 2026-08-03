"""Regression tests for the SECOND live run (v19 -> v20).

The first live run found defects in the code. This one found defects in
what the report SAYS, which is a harder class to see and a worse class to
ship, because a wrong note is read as a finding.

  - "MCP Server Console not detected" was printed on an instance with four
    MCP governance tables sitting right there, answering 403
  - "Native schema detected: Build Agent" was printed for two empty tables
  - NASK records whose name was withheld by an ACL were labelled
    "(unnamed)", asserting a property of the data to describe a property
    of the credential
  - the row cap truncated customer Business Rules on the smallest
    instance this will ever see

The through-line, and the reason these are grouped: every one is a place
where the tool could not distinguish ABSENCE from IGNORANCE, and resolved
the ambiguity in the reassuring direction. A scanner's whole product is
the difference between "there is nothing there" and "I could not see."
"""

from __future__ import annotations

from agentcensus.connectors.servicenow import mcp_server, nask, native, tables
from agentcensus.connectors.servicenow.http import DEFAULT_MAX_RECORDS_PER_TABLE
from tests.servicenow_fakes import FakeClient

_SATELLITES = [t for t, _f, _w in tables.MCP_SATELLITE_TABLES]


# ---------------------------------------------------------------------
# 1 — absence of the registry was reported as absence of MCP
# ---------------------------------------------------------------------

def test_denied_mcp_satellites_prove_presence_not_absence():
    """The 403 IS the finding. `mcp_auth_scopes` and the `aig_*` tables
    only exist where an MCP surface exists to govern, so read-denied on
    them means MCP is configured here and this account cannot enumerate
    it — the opposite of what the old single-table note concluded.

    Measured on a live PDI: registry name absent, all four satellites
    403. The report said the app probably wasn't installed."""
    client = FakeClient({}, deny=set(_SATELLITES))
    notes = mcp_server._satellite_notes(client)
    joined = " ".join(notes)

    assert "ARE present" in joined
    assert "DENIED" in joined
    for table in _SATELLITES:
        assert table in joined
    # The specific false reassurance that shipped. If any future edit
    # reintroduces this phrasing on an instance with live satellites, the
    # reader is misinformed in the direction that ends the investigation.
    assert "isn't installed" not in joined
    assert "not detected" not in joined


def test_readable_mcp_satellites_also_report_presence():
    """Presence should not depend on being denied. An account that CAN
    read them must reach the same conclusion by the easier route."""
    client = FakeClient({"mcp_auth_scopes": [{"sys_id": "1", "mcp_server": "srv", "tool_group": "g"}]})
    joined = " ".join(mcp_server._satellite_notes(client))
    assert "ARE present" in joined
    assert "mcp_auth_scopes" in joined


def test_all_absent_is_a_stronger_negative_but_still_hedged():
    """Control, and the case that must NOT become an all-clear. Five
    absent table names is real evidence and worth saying so, but the
    registry's true name is still unverified — so the note has to carry
    its own limit or it becomes the next false reassurance."""
    joined = " ".join(mcp_server._satellite_notes(FakeClient({})))
    assert "not detected" in joined
    assert "not proof" in joined
    # Names what was actually checked, so a reader can tell whether the
    # tables on THEIR instance were among them.
    for table in _SATELLITES:
        assert table in joined


# ---------------------------------------------------------------------
# 2 — an empty shipped table reported as a detected schema
# ---------------------------------------------------------------------

def test_empty_build_agent_tables_are_not_reported_as_a_detected_schema():
    """`table_exists` answers "does this table exist", and the platform
    ships these tables to everyone. Announcing "Native schema detected"
    on that basis tells a reader an agent framework is in use when the
    true statement is that nobody has opened it.

    This was untestable until the fake could model present-and-empty —
    see FakeClient.table_exists."""
    client = FakeClient({}, empty={"sn_build_agent_conversation", "sn_build_agent_skill"})
    agents, tools, _creds, _owners, notes = native.detect_and_fetch(client)
    joined = " ".join(notes)

    assert agents == [] and tools == []
    assert "EMPTY" in joined
    assert "Native schema detected" not in joined
    # Says the thing a reader actually needs: nothing here, and nothing
    # was skipped to reach that answer.
    assert "nothing was missed" in joined


def test_build_agent_skills_are_read_even_with_zero_conversations():
    """The skill registry was declared in tables.py and read by nobody,
    while the module docstring said in prose that it didn't exist. A
    configured-but-unexercised skill — skills present, conversations
    empty — is the state most worth reporting and the one the old early
    return discarded."""
    client = FakeClient(
        {"sn_build_agent_skill": [{"sys_id": "s1", "name": "summarize_ticket"}]},
        empty={"sn_build_agent_conversation"},
    )
    agents, tools, _creds, _owners, notes = native.detect_and_fetch(client)

    assert [t.name for t in tools] == ["summarize_ticket"]
    assert agents == []
    assert "1 registered skill(s)" in " ".join(notes)


# ---------------------------------------------------------------------
# 3 — an ACL boundary described as a property of the data
# ---------------------------------------------------------------------

_ACL_ROW = {"sys_id": "n1", "active": "true"}          # identifying column withheld
_BLANK_ROW = {"sys_id": "n2", "active": "true", "provider": "  "}   # genuinely blank


def test_withheld_name_is_labelled_as_unreadable_not_unnamed():
    """ServiceNow omits a field from the payload when read is denied, so
    a withheld name and an empty name are indistinguishable by `.get()`
    alone — and the label chosen decides which one the reader believes.
    "(unnamed)" asserts a fact about the record. The record has a name.

    This is the second time this project has answered a detection
    blindness with a cosmetic label; the first was caught in review, this
    one shipped and was found live."""
    client = FakeClient({tables.NASK_PROVIDER_MAPPING_TABLE: [_ACL_ROW]})
    tools, _notes = nask.fetch_nask(client)
    assert len(tools) == 1
    assert "<unreadable: field-level ACL>" in tools[0].name
    assert "(unnamed)" not in tools[0].name


def test_a_genuinely_blank_name_still_reads_as_unnamed():
    """Control. The fix must not relabel every blank field as an ACL
    problem — that would trade a false all-clear for a false alarm, which
    is the over-correction this codebase keeps making when it fixes an
    under-detection."""
    client = FakeClient({tables.NASK_PROVIDER_MAPPING_TABLE: [_BLANK_ROW]})
    tools, _notes = nask.fetch_nask(client)
    assert tools[0].name.endswith("(unidentified)")


# ---------------------------------------------------------------------
# 4 — generative-AI credential stores, enumerated but never read
# ---------------------------------------------------------------------

def test_genai_service_secrets_are_enumerated():
    """`gen_ai_service_secret` held a row on an instance where every
    other generative-AI table was empty. A credential can outlive the
    integration that used it — which is exactly when nobody is watching
    it — so its existence is the finding regardless of what else the
    scan explains."""
    client = FakeClient({"gen_ai_service_secret": [{"sys_id": "k1", "sys_created_by": "admin"}]})
    creds, notes = nask.fetch_genai_credentials(client)

    assert len(creds) == 1
    assert creds[0].source == "gen_ai_service_secret"
    assert "no secret value was requested" in " ".join(notes)


def test_genai_credential_field_lists_never_name_a_secret_column():
    """The guarantee is structural, not behavioural: the value is never
    requested, so there is no code path on which it could be held, logged
    or redacted-too-late. Enforced here as well as in
    test_no_secret_fields.py because this list is new and the temptation
    to add `name` or `value` later is obvious."""
    banned = ("secret", "value", "key", "token", "password", "credential")
    for _table, fields, _label in tables.GENAI_SECRET_TABLES:
        for field in fields:
            assert not any(b in field.lower() for b in banned), field


def test_empty_credential_tables_produce_no_note():
    """Silence is correct when there is nothing to say. Every surface
    that reports "0 found" adds a line the reader must dismiss, and this
    report already asks a lot of its reader."""
    creds, notes = nask.fetch_genai_credentials(FakeClient({}))
    assert creds == [] and notes == []


# ---------------------------------------------------------------------
# 5 — the cap truncated customer code on the smallest possible instance
# ---------------------------------------------------------------------

def test_default_cap_clears_the_measured_live_row_count():
    """5,085 non-vendor `sys_script` rows on an ordinary PDI, against a
    5,000 cap: ~85 customer-authored Business Rules never examined, on
    the smallest instance this will ever run against.

    Truncation is worse than it looks because the API returns rows
    ordered, so the same tail is dropped every run — a stable, confident,
    incomplete answer, which is indistinguishable from a complete one."""
    assert DEFAULT_MAX_RECORDS_PER_TABLE >= 5085


# ---------------------------------------------------------------------
# 5 — ServiceNow's own GenAI stack, which the provider list cannot see
# ---------------------------------------------------------------------

def test_platform_native_ai_actions_are_reported_as_context_not_findings():
    """Found by reading the Flow Designer action picker on a live PDI:
    the instance had no third-party LLM spoke at all, but shipped
    `OneExtend Invocation`, `One API - Feature Completion`,
    `GlobalToolExecutor` and `Semantic Search` as installed actions.

    A flow calling `OneExtend Invocation` IS invoking an LLM. Every scan
    before this reported nothing, because the provider list only knows
    third-party HOSTNAMES and this is internal plumbing with an ordinary
    name.

    Reported as a note and NOT as agents or tools, on purpose: findings
    are generated from inventory objects, so anything added there can
    reach the severity table through a rule. These ship with the platform
    and appear throughout OOB content — promoting them would bury the
    customer-built integrations this tool exists to find, which is the
    'ten shipped service accounts at HIGH' failure repeated.
    """
    from agentcensus.connectors.servicenow import flow_designer

    client = FakeClient({
        "sys_hub_flow": [
            {"sys_id": "f1", "name": "Ordinary looking flow", "description": "",
             "active": "true", "type": "flow", "sys_created_by": "admin"},
        ],
        "sys_hub_action_instance": [
            {"sys_id": "a1", "flow": "f1", "action_type": "at_oneextend",
             "order": "100", "sys_created_by": "admin"},
        ],
        "sys_hub_action_type_base": [
            {"sys_id": "at_oneextend", "name": "OneExtend Invocation"},
        ],
        "sys_user": [],
    })
    agents, tools, _owners, notes = flow_designer.fetch_flow_designer(client)

    joined = " ".join(notes)
    assert "PLATFORM-NATIVE AI" in joined
    assert "Ordinary looking flow" in joined
    assert "OneExtend Invocation" in joined
    # The point of the design: context, not inventory.
    assert agents == []
    assert tools == []


def test_platform_ai_markers_are_word_boundary_matched():
    """`genai`/`nowassist` are short enough to appear inside unrelated
    identifiers. A false positive here is cheap but corrosive: this note
    exists to be believed, and one obviously-wrong entry is enough for a
    reader to skip the whole section."""
    from agentcensus.connectors.servicenow import flow_designer

    client = FakeClient({
        "sys_hub_flow": [
            {"sys_id": "f1", "name": "Unrelated", "description": "",
             "active": "true", "type": "flow", "sys_created_by": "admin"},
        ],
        "sys_hub_action_instance": [
            {"sys_id": "a1", "flow": "f1", "action_type": "at_x",
             "order": "100", "sys_created_by": "admin"},
        ],
        "sys_hub_action_type_base": [
            {"sys_id": "at_x", "name": "Regenaissance Report Builder"},
        ],
        "sys_user": [],
    })
    _agents, _tools, _owners, notes = flow_designer.fetch_flow_designer(client)
    assert not any("PLATFORM-NATIVE AI" in n for n in notes)
