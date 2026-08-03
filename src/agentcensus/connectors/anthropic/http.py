"""Read-only client for Anthropic's Admin API.

GET-only, same discipline as ServiceNow's http.py: no method on this
class issues anything but a GET, and there must never be one added — a
connector that could modify organization members, roles, or API key
status is not a connector this project accepts (see core/connector.py).

Two credential types the real Admin API accepts, both supported here:
  - Admin API key (`sk-ant-admin...`) in the `x-api-key` header —
    covers organization members, invites, workspaces, workspace
    members, and API keys.
  - OAuth bearer token with `org:admin` scope in `Authorization: Bearer` —
    required specifically for the service-account/federation-issuer/
    federation-rule endpoints; Admin API keys are not accepted there
    (per Anthropic's own documented restriction, current as of this
    writing). `fetch_service_accounts` in connector.py is skipped with
    an explanatory scan note when only an Admin API key is configured.

VERIFICATION STATUS: endpoint paths, headers, and the pagination shape
(`data`/`has_more`/`last_id`) below are taken directly from Anthropic's
own current Admin API documentation (docs.anthropic.com /
platform.claude.com, manage-claude/admin-api). Individual row field
names for `/organizations/api_keys` beyond what the docs explicitly
show (`expires_at`) are inferred from the general shape Anthropic's
list endpoints use elsewhere, not confirmed against a live response —
`connector.py` reads every row defensively (`.get()`, never a bare
index) specifically because of that, so an unexpected or missing field
degrades to "not captured" rather than an exception.
"""

from __future__ import annotations

import os
import time

import requests

from agentcensus.core.redaction import scrub_values

BASE_URL = "https://api.anthropic.com/v1/organizations"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_PAGE_LIMIT = 100
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MAX_RETRIES = 3


class AnthropicAdminClient:
    def __init__(
        self,
        admin_api_key: str | None = None,
        oauth_token: str | None = None,
        timeout_seconds: int = 30,
    ):
        self.admin_api_key = admin_api_key or os.environ.get("AGENTCENSUS_ANTHROPIC_ADMIN_KEY", "")
        self.oauth_token = oauth_token or os.environ.get("AGENTCENSUS_ANTHROPIC_OAUTH_TOKEN", "")
        self.timeout_seconds = timeout_seconds

        if not self.admin_api_key and not self.oauth_token:
            raise ValueError(
                "Either an Admin API key (pass admin_api_key= or set "
                "AGENTCENSUS_ANTHROPIC_ADMIN_KEY) or an org:admin OAuth bearer token "
                "(pass oauth_token= or set AGENTCENSUS_ANTHROPIC_OAUTH_TOKEN) is required."
            )

    def _headers(self) -> dict:
        headers = {"anthropic-version": ANTHROPIC_VERSION, "Accept": "application/json"}
        if self.oauth_token:
            headers["authorization"] = f"Bearer {self.oauth_token}"
        else:
            headers["x-api-key"] = self.admin_api_key
        return headers

    def get(self, path: str, params: dict | None = None) -> dict:
        """Retries on 429/5xx with the same policy as the other two
        connectors. The Admin API is rate limited like any other
        Anthropic endpoint, and without this a single 429 mid-scan
        degraded an entire endpoint to an empty scan note — which in a
        report reads the same as "this organization has no API keys",
        the exact kind of silent under-report this project treats as a
        correctness bug rather than a nuisance."""
        url = f"{BASE_URL}{path}"
        last_exc: Exception | None = None

        for attempt in range(_MAX_RETRIES + 1):
            resp = requests.get(
                url, params=params or {}, headers=self._headers(), timeout=self.timeout_seconds
            )
            if resp.status_code not in _RETRYABLE_STATUS:
                resp.raise_for_status()
                return resp.json()

            last_exc = requests.HTTPError(f"{resp.status_code} from {path}", response=resp)
            if attempt == _MAX_RETRIES:
                break
            retry_after = resp.headers.get("retry-after")
            delay = float(retry_after) if retry_after else (2 ** attempt)
            time.sleep(delay)

        raise last_exc

    def get_all(self, path: str, params: dict | None = None) -> list[dict]:
        """Paginates using Anthropic's cursor shape (`data`, `has_more`,
        `last_id`) until exhausted."""
        results: list[dict] = []
        query = dict(params or {})
        query.setdefault("limit", DEFAULT_PAGE_LIMIT)
        after = None
        while True:
            if after:
                query["after_id"] = after
            page = self.get(path, query)
            rows = page.get("data", [])
            results.extend(rows)
            if not page.get("has_more") or not rows:
                break
            after = page.get("last_id") or rows[-1].get("id")
            if not after:
                break
        return results

    def safe_get_all(self, path: str, params: dict | None = None) -> tuple[list[dict], str | None]:
        """Never raises — same fault-isolation contract as ServiceNow's
        safe_get_all. A missing scope on the Admin key/token for one
        endpoint (e.g. an Admin API key hitting a service-account
        endpoint that requires OAuth) degrades to a scan note."""
        try:
            return self.get_all(path, params), None
        except requests.RequestException as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            if status == 403:
                return [], f"Access denied reading '{path}' — this credential lacks the required scope."
            if status == 404:
                return [], f"'{path}' not found — endpoint may not exist for this organization type."
            if status == 429:
                return [], (
                    f"Rate limited reading '{path}' after {_MAX_RETRIES} retries — "
                    "try again later."
                )
            return [], scrub_values(f"Failed to read '{path}': {e}")
