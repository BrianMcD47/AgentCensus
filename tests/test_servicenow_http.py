"""Tests for the pieces of http.py that need real requests/time mocking:
retry/backoff, the pagination safety cap, and the OAuth token exchange.
Everything else (safe_get_all's error-wrapping) is exercised indirectly
through the FakeClient-based native/shadow tests.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from agentcensus.connectors.servicenow.http import (
    OAuthClientCredentials,
    ServiceNowClient,
    _with_stable_order,
)


def _fake_response(status_code=200, json_data=None, headers=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.json.return_value = json_data or {}
    if status_code >= 400:
        import requests

        resp.raise_for_status.side_effect = requests.HTTPError(response=resp)
    else:
        resp.raise_for_status.side_effect = None
    return resp


def test_get_all_stops_at_max_records_per_table():
    client = ServiceNowClient(
        instance_url="https://example.service-now.com",
        username="u",
        password="p",
        max_records_per_table=250,
    )
    full_page = [{"sys_id": str(i)} for i in range(100)]

    with patch("requests.get", return_value=_fake_response(200, {"result": full_page})):
        rows = client.get_all("sys_script_include", ["sys_id"])

    # would paginate forever against an infinite mock feed without the cap
    assert len(rows) == 250


def test_safe_get_all_reports_truncation():
    client = ServiceNowClient(
        instance_url="https://example.service-now.com",
        username="u",
        password="p",
        max_records_per_table=100,
    )
    full_page = [{"sys_id": str(i)} for i in range(100)]

    with patch("requests.get", return_value=_fake_response(200, {"result": full_page})):
        rows, note = client.safe_get_all("sys_script", ["sys_id"])

    assert len(rows) == 100
    assert note is not None
    assert "safety cap" in note


def test_retries_on_429_then_succeeds():
    client = ServiceNowClient(instance_url="https://example.service-now.com", username="u", password="p")
    responses = [
        _fake_response(429, headers={"Retry-After": "0"}),
        _fake_response(200, {"result": [{"sys_id": "1"}]}),
        # A single real row is a page shorter than DEFAULT_PAGE_SIZE, which
        # is no longer treated as "end of data" on its own (see the short-
        # page regression test below) — get_all correctly asks for a
        # second page, which must come back empty for pagination to stop.
        _fake_response(200, {"result": []}),
    ]

    with patch("requests.get", side_effect=responses), patch("time.sleep") as mock_sleep:
        rows = client.get_all("sys_rest_message", ["sys_id"])

    assert rows == [{"sys_id": "1"}]
    mock_sleep.assert_called_once()


def test_safe_get_all_reports_rate_limit_after_exhausting_retries():
    client = ServiceNowClient(instance_url="https://example.service-now.com", username="u", password="p")
    always_429 = _fake_response(429, headers={"Retry-After": "0"})

    with patch("requests.get", return_value=always_429), patch("time.sleep"):
        rows, note = client.safe_get_all("sys_rest_message", ["sys_id"])

    assert rows == []
    assert "rate limited" in note.lower()


def test_oauth_client_credentials_flow_used_instead_of_basic_auth():
    client = ServiceNowClient(
        instance_url="https://example.service-now.com",
        oauth=OAuthClientCredentials(client_id="cid", client_secret="secret"),
    )
    token_response = _fake_response(200, {"access_token": "tok_123"})
    # One real (short) page, then empty — a fixed return_value would make
    # every page look like the same single row forever, which no longer
    # signals "done" on its own (see the short-page regression test below).
    table_responses = [
        _fake_response(200, {"result": [{"sys_id": "1"}]}),
        _fake_response(200, {"result": []}),
    ]

    with patch("requests.post", return_value=token_response) as mock_post, \
         patch("requests.get", side_effect=table_responses) as mock_get:
        rows = client.get_all("sys_user", ["sys_id"])

    assert rows == [{"sys_id": "1"}]
    mock_post.assert_called_once()
    assert mock_post.call_args.kwargs["data"]["client_id"] == "cid"
    # bearer token, not basic auth, on the actual data call
    assert "auth" not in mock_get.call_args.kwargs
    assert mock_get.call_args.kwargs["headers"]["Authorization"] == "Bearer tok_123"


def test_requires_either_basic_or_oauth_credentials():
    import pytest

    with pytest.raises(ValueError):
        ServiceNowClient(instance_url="https://example.service-now.com")


def test_with_stable_order_adds_tiebreaker_to_empty_query():
    assert _with_stable_order("") == "ORDERBYsys_id"


def test_with_stable_order_appends_to_existing_query():
    assert _with_stable_order("active=true") == "active=true^ORDERBYsys_id"


def test_with_stable_order_does_not_duplicate_existing_order():
    assert _with_stable_order("active=true^ORDERBYname") == "active=true^ORDERBYname"
    assert _with_stable_order("active=true^ORDERBYDESCname") == "active=true^ORDERBYDESCname"


def test_get_all_continues_past_a_short_nonempty_page():
    """Live-confirmed against a real PDI, not a hypothetical: page 1
    (offset=0) returned exactly 100 rows, page 2 (offset=100) returned 99
    — one short — and page 3 (offset=200) returned a full 100 again,
    proving real data existed past the short page. The old logic
    (`if len(page) < page_size: break`) would have stopped at page 2,
    silently truncating everything after it — which is exactly what
    happened in production: an unfiltered scan returned 199 rows total
    (100 + 99) when the table actually had roughly 1992 accessible rows.
    A page is only "the end" when it's completely empty."""
    client = ServiceNowClient(instance_url="https://example.service-now.com", username="u", password="p")
    page1 = [{"sys_id": f"a{i}"} for i in range(100)]
    page2 = [{"sys_id": f"b{i}"} for i in range(99)]  # one short, NOT the end
    page3 = [{"sys_id": f"c{i}"} for i in range(100)]
    page4: list[dict] = []  # empty — but page3 was EXACTLY FULL, so one
    page5: list[dict] = []  # more window is probed before concluding.

    # Why the extra probe: a full page followed by an empty one is the
    # only shape an ACL-emptied pagination window can have (100
    # consecutive denied rows return nothing, mid-table, looking exactly
    # like the end). Verified: data at offsets 0 and 200 with an emptied
    # window at 100 returned 100 rows instead of 200, silently.
    #
    # The cost is one extra request per table whose row count happens to
    # be an exact multiple of the page size. A short final page — the
    # common case — still stops immediately, which is why this is not
    # three extra requests on every table.
    responses = [
        _fake_response(200, {"result": page1}),
        _fake_response(200, {"result": page2}),
        _fake_response(200, {"result": page3}),
        _fake_response(200, {"result": page4}),
        _fake_response(200, {"result": page5}),
    ]

    with patch("requests.get", side_effect=responses) as mock_get:
        rows = client.get_all("sys_script_include", ["sys_id"])

    assert len(rows) == 299  # 100 + 99 + 100 — not 199
    assert mock_get.call_count == 5


def test_get_all_always_sends_a_stable_order_even_with_no_filter():
    """Live-confirmed regression: the exact same unfiltered read against a
    real PDI's sys_script_include returned 199, 996, and 1992 rows purely
    depending on requested page size and whether an explicit ORDERBY was
    present — proving get_all's page-by-page pagination silently lost
    rows across page boundaries with no filter and no forced sort. Every
    request must carry a deterministic order, not just filtered ones."""
    client = ServiceNowClient(instance_url="https://example.service-now.com", username="u", password="p")

    with patch("requests.get", return_value=_fake_response(200, {"result": []})) as mock_get:
        client.get_all("sys_script_include", ["sys_id"])  # no query filter given

    assert mock_get.call_args.kwargs["params"]["sysparm_query"] == "ORDERBYsys_id"


def test_get_all_appends_stable_order_to_a_caller_supplied_query():
    client = ServiceNowClient(instance_url="https://example.service-now.com", username="u", password="p")

    with patch("requests.get", return_value=_fake_response(200, {"result": []})) as mock_get:
        client.get_all("sys_user", ["sys_id"], query="web_service_access_only=true")

    assert (
        mock_get.call_args.kwargs["params"]["sysparm_query"]
        == "web_service_access_only=true^ORDERBYsys_id"
    )


def test_get_all_requests_exclude_reference_link():
    """Confirmed live against a real ServiceNow instance: without this
    parameter, reference fields (sys_user.department, and by strong
    convention others like sys_script.collection) come back as
    {"link": "...", "value": "..."} dicts instead of plain sys_id
    strings — a real, observed bug, not a hypothetical one (see
    owners.py's department fix). This is the one place in the client
    that param gets set; every table read goes through get_all, so
    proving it here covers all of them."""
    client = ServiceNowClient(instance_url="https://example.service-now.com", username="u", password="p")

    with patch("requests.get", return_value=_fake_response(200, {"result": []})) as mock_get:
        client.get_all("sys_user", ["sys_id", "department"])

    assert mock_get.call_args.kwargs["params"]["sysparm_exclude_reference_link"] == "true"
