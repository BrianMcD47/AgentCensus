"""Read-only client for the Splunk REST API (management port, default
8089). GET-only — no method on this class issues anything but a GET,
matching every other connector's read-only guarantee (see
core/connector.py). Deliberately does NOT implement the
`/services/auth/login` session-key exchange some Splunk auth flows use;
that's one more moving part than this needs when a static auth token or
Basic Auth already covers it, and it keeps this client honestly
GET-only with zero exceptions (ServiceNow's OAuth client-credentials
handshake is the one documented exception to that shape in this project,
and this Splunk client doesn't add a second one).

Splunk's REST API returns Atom XML by default; every request here sets
`output_mode=json` to get JSON instead. Response shape is Splunk's
standard `{"entry": [{"name": ..., "content": {...fields...}}, ...],
"paging": {...}}` — well-established and stable, unlike some of the
ServiceNow table names elsewhere in this project that needed live
verification. Field names WITHIN `content` for saved-search alert
actions (`actions`, `action.webhook.param.url`, `action.script.filename`,
etc.) are real, documented Splunk fields, but this client and
connector.py still read them defensively (`.get()`, never a bare
index) — a Splunk instance's exact configured field set can vary by
version and by which alert actions are installed.
"""

from __future__ import annotations

import os
import time

import requests

from agentcensus.core.redaction import scrub_values

DEFAULT_PAGE_COUNT = 100
# Same safety cap and retry policy as the ServiceNow client — a large
# Splunk deployment can have tens of thousands of saved searches, and
# an unbounded read there is slow and noisy against a production
# search head.
DEFAULT_MAX_RECORDS = 5000
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MAX_RETRIES = 3


class SplunkClient:
    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        timeout_seconds: int = 30,
        verify_ssl: bool = True,
        max_records: int = DEFAULT_MAX_RECORDS,
    ):
        self.max_records = max_records
        self.base_url = (base_url or os.environ.get("AGENTCENSUS_SPLUNK_URL", "")).rstrip("/")
        self.token = token or os.environ.get("AGENTCENSUS_SPLUNK_TOKEN", "")
        self.username = username or os.environ.get("AGENTCENSUS_SPLUNK_USERNAME", "")
        self.password = password or os.environ.get("AGENTCENSUS_SPLUNK_PASSWORD", "")
        self.timeout_seconds = timeout_seconds
        self.verify_ssl = verify_ssl

        if not self.base_url:
            raise ValueError(
                "Splunk management URL is required (pass base_url= or set "
                "AGENTCENSUS_SPLUNK_URL, e.g. https://splunk.example.com:8089)"
            )
        if not self.token and not (self.username and self.password):
            raise ValueError(
                "Either a static auth token (AGENTCENSUS_SPLUNK_TOKEN) or username/password "
                "(AGENTCENSUS_SPLUNK_USERNAME/PASSWORD) is required."
            )

    def _request_kwargs(self) -> dict:
        if self.token:
            return {"headers": {"Authorization": f"Bearer {self.token}"}}
        return {"auth": (self.username, self.password)}

    def _get_page(self, endpoint: str, count: int, offset: int) -> list[dict]:
        """One page, with the same retry/backoff contract ServiceNow's
        client has. Splunk returns 503 while a search head is starting
        or under load, and 429 behind some reverse proxies; without
        this, a single transient blip silently degraded a whole
        endpoint to an empty scan note, which reads identically to
        'this instance has no saved searches.'"""
        url = f"{self.base_url}{endpoint}"
        last_exc: Exception | None = None

        for attempt in range(_MAX_RETRIES + 1):
            resp = requests.get(
                url,
                params={"output_mode": "json", "count": count, "offset": offset},
                timeout=self.timeout_seconds,
                verify=self.verify_ssl,
                **self._request_kwargs(),
            )
            if resp.status_code not in _RETRYABLE_STATUS:
                resp.raise_for_status()
                return resp.json().get("entry", [])

            last_exc = requests.HTTPError(f"{resp.status_code} from {endpoint}", response=resp)
            if attempt == _MAX_RETRIES:
                break
            retry_after = resp.headers.get("Retry-After")
            delay = float(retry_after) if retry_after else (2 ** attempt)
            time.sleep(delay)

        raise last_exc

    def get_all(
        self, endpoint: str, count: int = DEFAULT_PAGE_COUNT,
        max_records: int | None = None,
    ) -> list[dict]:
        """Paginates via Splunk's offset/count convention. `endpoint` is
        namespaced app-agnostic (`/services/...` rather than
        `/servicesNS/<user>/<app>/...`) so this sees saved searches/apps/
        users across every app on the instance, not just one, matching
        the "scan the whole platform" intent everywhere else in this
        project.

        Stops only on a genuinely EMPTY page, never on a merely short
        one. This mirrors a bug found and fixed in the ServiceNow client
        (see `servicenow/http.py`'s `get_all`), where a page one row
        short of the requested size was treated as end-of-data and
        silently truncated the rest of the table — an unfiltered read
        returned 199 rows against a table with ~1992 accessible ones.
        The same failure shape is available here: Splunk applies
        per-user ACL filtering to saved searches and other knowledge
        objects, so a page can legitimately come back short without
        being last. The bug was fixed here before it was ever observed
        on a live Splunk instance, because the ServiceNow case proved
        the reasoning ("short page means done") is unsound in general,
        not that one vendor implements it badly.
        """
        max_records = self.max_records if max_records is None else max_records
        results: list[dict] = []
        offset = 0
        while True:
            remaining = max_records - len(results)
            if remaining <= 0:
                break
            requested = min(count, remaining)
            page = self._get_page(endpoint, requested, offset)
            results.extend(page[:remaining])
            if len(page) == 0:
                break
            # Advance by what was REQUESTED, not by the nominal page
            # size. On the final window before the safety cap,
            # `requested` is smaller than `count`; advancing by `count`
            # there jumps the cursor past rows that were never asked
            # for. ServiceNow's get_all has always done this correctly
            # (`offset += page_size`); this file had drifted.
            offset += requested
        return results

    def safe_get_all(self, endpoint: str) -> tuple[list[dict], str | None]:
        """Never raises — same fault-isolation contract as every other
        connector's safe_get_all. Splunk's own role/capability model
        means a read-only role can easily have access to some endpoints
        (e.g. saved/searches) and not others (e.g. authentication/users
        requires admin_all_objects or similar on many instances) — one
        denied endpoint degrades the scan, not crashes it.

        Returns (rows, note): note is None on a clean complete read, an
        error string on failure, and a truncation warning when the
        safety cap was hit — same three-state contract as ServiceNow's.
        """
        try:
            rows = self.get_all(endpoint)
        except requests.RequestException as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            if status in (401, 403):
                return [], f"Access denied reading '{endpoint}' — the scan credential lacks access to this endpoint."
            if status == 404:
                return [], f"'{endpoint}' not found on this instance."
            if status == 429:
                return [], (
                    f"Rate limited reading '{endpoint}' after {_MAX_RETRIES} retries — "
                    "try again later or scan during a quieter window."
                )
            return [], scrub_values(f"Failed to read '{endpoint}': {e}")

        if len(rows) >= self.max_records:
            return rows, (
                f"'{endpoint}' returned at least {self.max_records} records — stopped at the "
                f"safety cap. Results from this endpoint are incomplete. Raise "
                f"max_records if you need the full set."
            )
        return rows, None
