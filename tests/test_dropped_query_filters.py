"""A server-side filter on an unreadable field is silently discarded.

Measured live (2026-08) with a negative control, after an earlier
inference from the same instance turned out to be unfounded:

    endpointLIKE<impossible hostname>   -> every row in the table

`endpoint` was under a field-level ACL there. ServiceNow does not merely
omit an unreadable field from the response — it drops any query condition
naming it, returns HTTP 200, and says nothing. Confirmed by contrast on
the same instance: `sys_db_object.name=`, `sys_user.
web_service_access_only=`, `sys_properties.type!=` and `sys_script.
sys_scope.scope NOT LIKE` all filtered correctly, and all four name
READABLE fields.

So the rule is narrow and predictable — filter applies iff the field is
readable — which is why it can be guarded rather than merely documented.

Why this is worth a file of its own: a failed read is loud and a dropped
filter is silent, and the silent one is the one that produces a confident
wrong answer. Four filters in this connector are load-bearing, and the
account most likely to trip this is a least-privileged one — exactly what
this product tells customers to create.

The near-miss worth recording: this was almost built as a FEATURE. Tier 2
is blind wherever `endpoint` is unreadable, and the proposed fix was to
push host matching server-side and never read the value. That design
would have reported Firebase Cloud Messaging and Yahoo Finance as
confirmed LLM integrations, at the highest confidence grade in the
product, on precisely the instances where nobody could read `endpoint` to
check. The negative control is the only reason it wasn't written.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from agentcensus.connectors.servicenow import integration_accounts, tables
from agentcensus.connectors.servicenow.http import ServiceNowClient
from tests.servicenow_fakes import FakeClient


def _real_client() -> ServiceNowClient:
    """The two tests below exercise the client's own plumbing — which
    fields go on the wire, and how `table_exists` composes onto
    `safe_get_all`. FakeClient reimplements both rather than sharing them,
    so asserting against it would prove only that the fake agrees with
    itself."""
    return ServiceNowClient(instance_url="https://x.service-now.com", username="u", password="p")


def _resp(rows: list[dict]) -> MagicMock:
    r = MagicMock()
    r.status_code = 200
    r.headers = {}
    r.json.return_value = {"result": rows}
    r.raise_for_status.side_effect = None
    return r


def _pages(rows: list[dict]) -> list[MagicMock]:
    """One page of rows, then an empty page to end pagination.

    `get_all` deliberately does NOT stop on a short page — that was a real
    undercounting bug, since ServiceNow can return fewer rows than the
    page size while more remain. It stops on an EMPTY page. A mock that
    returns the same non-empty page forever therefore paginates to the
    safety cap and trips the truncation note, which is what happened when
    this file was first written: the assertion failed for a reason that
    had nothing to do with the behaviour under test."""
    return [_resp(rows), _resp([])]

# A row whose `web_service_access_only` column never came back — what a
# field-level ACL actually looks like on the wire. The field is absent,
# not empty; the rest of the row is intact.
_ACL_USER = {"sys_id": "u1", "user_name": "alice", "name": "Alice"}
_OK_USER = {
    "sys_id": "u2", "user_name": "svc_api", "name": "API Svc",
    "web_service_access_only": "true", "active": "true",
}


def test_a_dropped_filter_is_reported_not_trusted():
    """The failure this prevents: `web_service_access_only=true` is the
    entire integration-account tier, so a dropped filter turns every
    human user on the instance into a reported API-only machine identity
    — 639 of them on the instance tested — each carrying a severity that
    assumes nobody is watching it.

    Loud, and specifically NOT an exception: the rows are real and the
    rest of the scan should continue. What must not happen is treating
    them as matches."""
    client = FakeClient({tables.USER_TABLE: [_ACL_USER]})
    notes: list[str] = []
    integration_accounts.fetch_integration_accounts(client, notes)

    joined = " ".join(notes)
    assert "QUERY FILTER SILENTLY DROPPED" in joined
    assert "web_service_access_only" in joined
    # Names the consequence, not just the cause. A note that says only
    # "filter dropped" leaves the reader to work out that the rows are
    # now meaningless, and they won't.
    assert "UNFILTERED set" in joined


def test_a_readable_filter_field_produces_no_warning():
    """Control, and the case that must stay quiet. Every spurious warning
    costs the reader attention that the real ones need — and this report
    already asks a great deal of its reader."""
    client = FakeClient({tables.USER_TABLE: [_OK_USER]})
    notes: list[str] = []
    creds, _owners = integration_accounts.fetch_integration_accounts(client, notes)

    assert not any("SILENTLY DROPPED" in n for n in notes)
    assert len(creds) == 1


def test_the_filter_field_is_requested_so_it_can_be_checked():
    """The guard infers readability from whether the column came back, so
    a filter field that was never REQUESTED is indistinguishable from one
    that was refused. If `safe_get_all` didn't add it to the field list,
    the guard would fire on every filtered read in the connector — a
    false alarm on every scan, which is how a warning gets ignored."""
    client = _real_client()
    with patch("requests.get", side_effect=_pages([{"sys_id": "1", "flag": "x"}])) as get:
        client.safe_get_all("sys_thing", ["sys_id"], "flag=x", filter_fields=["flag"])

    requested = get.call_args_list[0].kwargs["params"]["sysparm_fields"]
    assert "flag" in requested
    assert "sys_id" in requested


def test_table_exists_fails_closed_when_its_filter_is_dropped():
    """The most consequential site in the connector. `table_exists`
    filters `sys_db_object` by `name=`, and that filter IS the check — if
    it were dropped, the query would return every table on the instance,
    `len(rows) > 0` would be true for every input, and every table would
    report as existing. Every honest "not detected" note in this
    connector would invert into a false positive, and modules would go on
    to read tables that aren't there.

    Fails closed: not-found plus the note, which degrades detection
    rather than inventing tables."""
    client = _real_client()
    # `name` withheld by a field-level ACL: the row arrives without it.
    with patch("requests.get", side_effect=_pages([{"sys_id": "t1"}])):
        exists, err = client.table_exists("anything_at_all")

    assert exists is False
    assert err and "SILENTLY DROPPED" in err

    # Control: with `name` readable, existence is asserted normally.
    with patch("requests.get", side_effect=_pages([{"sys_id": "t1", "name": "sys_user"}])):
        exists, err = client.table_exists("sys_user")
    assert exists is True and err is None


def test_every_filtered_read_in_the_connector_declares_its_filter_fields():
    """Mechanical, because this is the kind of guard that gets bypassed
    by the next person adding a filter — including the next version of
    me. Four sites use a server-side filter today; each must pass
    `filter_fields`, or it is unguarded and silently trusted.

    Greps the source rather than exercising behaviour on purpose: a
    behavioural test can only cover the call sites someone remembered to
    write a test for, which is exactly the set that isn't the problem."""
    import pathlib
    import re

    root = pathlib.Path(integration_accounts.__file__).parent
    offenders: list[str] = []

    for path in sorted(root.glob("*.py")):
        src = path.read_text()
        for match in re.finditer(r"safe_get_all\((.*?)\)\s*$", src, re.S | re.M):
            call = match.group(1)
            # A call with a query but no declared filter_fields.
            has_query = "query=" in call or call.count(",") >= 2
            if has_query and "filter_fields" not in call and "query=f\"name=" not in call:
                # Only flag calls that genuinely pass a non-empty query.
                if re.search(r"query\s*=\s*[\"']\w", call) or re.search(r",\s*query\b", call):
                    offenders.append(f"{path.name}: {call.strip()[:80]}")

    assert not offenders, "unguarded filtered read(s):\n" + "\n".join(offenders)
