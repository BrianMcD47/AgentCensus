"""Read-only Table API client, shared by native.py and shadow.py.

Only `get`/`get_all`/`safe_get_all`/`table_exists` exist here. There is
no `post`, `patch`, or `delete` against the Table API, and there must
never be one added — see core/connector.py and CONTRIBUTING.md.

The one POST this client can make is an OAuth2 client_credentials token
request, when configured for OAuth instead of Basic Auth (see
`OAuthClientCredentials` below). That's an authentication handshake,
not a write against anything this tool scans — it doesn't create,
modify, or delete a single ServiceNow record. Basic Auth needed no such
exception because credentials go straight in the request header; OAuth
needs one extra round trip to exchange client_id/secret for a bearer
token before the GETs can happen. Worth stating plainly given how much
of this project's trust pitch rests on "read-only" — this doesn't
weaken that claim, but it's the one place a POST happens at all, so it
should be obvious why.

Why OAuth matters enough to add: several enterprise ServiceNow
instances disable Basic Auth for API access by security policy. A
connector that only supports Basic Auth simply cannot connect there,
which is a real gap for a tool whose whole pitch is "run this at any
customer, no special access negotiation."
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

import requests

from agentcensus.connectors.servicenow.tables import impact_for
from agentcensus.core.models import AccessGap, AccessGapKind
from agentcensus.core.redaction import scrub_values

DEFAULT_PAGE_SIZE = 100
# Safety cap — see get_all's docstring. Raised from 5,000 after a live
# measurement: on an ordinary PDI, `sys_script` held 5,733 rows, of which
# 5,085 survived the vendor-scope filter. The cap truncated at 5,000, so
# roughly 85 customer-authored Business Rules were never examined on the
# smallest instance this will ever run against. A production instance
# will hold more, and the records past the cap are not random — the API
# returns them ordered, so truncation systematically drops the same tail
# every run, which reads as a stable, confident, incomplete answer.
#
# 10,000 is not a principled number either; it is one measurement plus
# headroom. It costs about 30 seconds on a scan that already takes two
# and a half minutes, which is the right trade for a tool whose entire
# value is not missing things. The truncation note still fires above it.
DEFAULT_MAX_RECORDS_PER_TABLE = 10000
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MAX_RETRIES = 3
# One extra window is probed past an empty page, and only when the last
# non-empty page was exactly full — the single shape an ACL-emptied
# pagination window can take. A longer run of denied rows (200+) would
# still truncate; that is a deliberate trade against paying extra
# requests on every table of every scan.


def _with_stable_order(query: str) -> str:
    """Appends a deterministic `ORDERBYsys_id` tiebreaker to any encoded
    query, unless the caller already specified an order.

    Confirmed live against a real PDI, not theoretical: the exact same
    unfiltered `sys_script_include` read returned 199, 996, and 1992
    rows depending only on the requested page size and whether an
    explicit ORDERBY was present — the Table API does not guarantee a
    stable row ordering across separate offset/limit requests on its
    own. Without a forced deterministic sort, get_all's page-by-page
    loop can silently skip (or duplicate) rows across page boundaries,
    with no error and no note — the scan just quietly returns less
    than the true accessible set. This was found because a single
    real record (a custom Script Include on that PDI) was completely
    absent from get_all's output despite being fully readable via a
    direct name-filtered query on the same table with the same
    credentials."""
    if "ORDERBY" in (query or "").upper():
        return query
    return f"{query}^ORDERBYsys_id" if query else "ORDERBYsys_id"


@dataclass
class OAuthClientCredentials:
    """client_credentials grant. ServiceNow issues the token from an
    OAuth application registry entry (`oauth_entity` — the same table
    shadow.py's tier 1 reads) configured for this grant type."""
    client_id: str
    client_secret: str
    token_url: str | None = None  # defaults to {instance}/oauth_token.do


class ServiceNowClient:
    def __init__(
        self,
        instance_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        oauth: OAuthClientCredentials | None = None,
        timeout_seconds: int = 30,
        max_records_per_table: int = DEFAULT_MAX_RECORDS_PER_TABLE,
    ):
        self.instance_url = (instance_url or os.environ.get("AGENTCENSUS_SN_INSTANCE", "")).rstrip("/")
        self.username = username or os.environ.get("AGENTCENSUS_SN_USERNAME", "")
        self.password = password or os.environ.get("AGENTCENSUS_SN_PASSWORD", "")
        self.timeout_seconds = timeout_seconds
        self.max_records_per_table = max_records_per_table

        self.oauth = oauth or self._oauth_from_env()
        self._bearer_token: str | None = None

        # Every read this account was refused, in the order encountered.
        # Lives on the client rather than being threaded through every
        # module's `notes` list because the client is the only place that
        # sees all of them, and because a module that forgets to forward
        # a gap would silently shrink the access section — the same
        # manifest-drift failure this connector has hit three times.
        self.access_gaps: list[AccessGap] = []
        self._gap_keys: set[tuple] = set()
        # Real column names per table, resolved lazily and only when a
        # requested field fails to come back. Costs nothing on a clean scan.
        self._columns_cache: dict[str, set[str]] = {}

        if not self.instance_url:
            raise ValueError(
                "ServiceNow instance URL is required "
                "(pass instance_url= or set AGENTCENSUS_SN_INSTANCE)"
            )
        if not self.oauth and not (self.username and self.password):
            raise ValueError(
                "Either username/password (AGENTCENSUS_SN_USERNAME/PASSWORD) or OAuth "
                "client credentials (AGENTCENSUS_SN_CLIENT_ID/SECRET) are required."
            )

    @staticmethod
    def _oauth_from_env() -> OAuthClientCredentials | None:
        client_id = os.environ.get("AGENTCENSUS_SN_CLIENT_ID")
        client_secret = os.environ.get("AGENTCENSUS_SN_CLIENT_SECRET")
        if client_id and client_secret:
            return OAuthClientCredentials(client_id=client_id, client_secret=client_secret)
        return None

    def _ensure_bearer_token(self) -> str:
        if self._bearer_token:
            return self._bearer_token
        token_url = self.oauth.token_url or f"{self.instance_url}/oauth_token.do"
        resp = requests.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.oauth.client_id,
                "client_secret": self.oauth.client_secret,
            },
            timeout=self.timeout_seconds,
        )
        resp.raise_for_status()
        self._bearer_token = resp.json()["access_token"]
        return self._bearer_token

    def _request_kwargs(self) -> dict:
        if self.oauth:
            return {"headers": {"Accept": "application/json", "Authorization": f"Bearer {self._ensure_bearer_token()}"}}
        return {"auth": (self.username, self.password), "headers": {"Accept": "application/json"}}

    def get(self, table: str, params: dict) -> list[dict]:
        url = f"{self.instance_url}/api/now/table/{table}"
        last_exc: Exception | None = None

        for attempt in range(_MAX_RETRIES + 1):
            resp = requests.get(url, params=params, timeout=self.timeout_seconds, **self._request_kwargs())

            if resp.status_code not in _RETRYABLE_STATUS:
                resp.raise_for_status()
                return resp.json().get("result", [])

            last_exc = requests.HTTPError(f"{resp.status_code} from {table}", response=resp)
            if attempt == _MAX_RETRIES:
                break
            retry_after = resp.headers.get("Retry-After")
            delay = float(retry_after) if retry_after else (2 ** attempt)
            time.sleep(delay)

        raise last_exc

    def get_all(self, table: str, fields: list[str], query: str = "") -> list[dict]:
        """Paginates until exhausted or `max_records_per_table` is hit.
        The cap exists because sys_script/sys_script_include on a mature
        instance can run into the tens of thousands of rows — an
        unbounded scan there is slow and can burn a meaningful chunk of
        the instance's API quota for a single table. Hitting the cap
        doesn't fail the read; it returns what was fetched. Use
        `safe_get_all` to get a note when that happens.

        Every request goes through `_with_stable_order`, which forces a
        deterministic sort — see its docstring for the live-confirmed
        bug this fixes: without it, offset-based pagination against the
        Table API can silently lose rows across page boundaries, with
        no error and no indication anything was missed."""
        results: list[dict] = []
        offset = 0
        consecutive_empty = 0
        last_nonempty_len = 0
        while True:
            remaining = self.max_records_per_table - len(results)
            if remaining <= 0:
                break
            page_size = min(DEFAULT_PAGE_SIZE, remaining)
            params = {
                "sysparm_fields": ",".join(fields),
                "sysparm_limit": page_size,
                "sysparm_offset": offset,
                # Without this, ServiceNow returns every reference-type field
                # (department on sys_user, run_as on sn_aia_agent/sysauto_script,
                # collection on sys_script, basic_auth_profile on sys_rest_message,
                # ...) as a {"link": "...", "value": "..."} dict instead of a
                # plain sys_id string — confirmed live against a real instance,
                # not theoretical: sys_user.department came back as exactly that
                # dict shape for any user with a department set. Every plain
                # `entry.get("some_reference_field")` read anywhere in this
                # connector that isn't already routed through `ref()` (department
                # in owners.py, for one — a real bug this fix closes) would
                # otherwise silently store a dict where a string was expected.
                # This normalizes every reference field to a bare sys_id string
                # across every table this client reads, at the one place all of
                # them go through, rather than patching each call site.
                "sysparm_exclude_reference_link": "true",
                # Always set, even with no caller-provided filter — see
                # _with_stable_order's docstring for the live-confirmed
                # data-loss bug this closes. Previously this key was only
                # added `if query:`, so an unfiltered scan (query="") had
                # no sort at all, which is exactly the case that lost rows.
                "sysparm_query": _with_stable_order(query),
            }
            page = self.get(table, params)
            # Defensively slice to what we asked for rather than trusting
            # the server honored sysparm_limit exactly — the cap above
            # only means something if this does too.
            results.extend(page[:remaining])
            # Only an EMPTY page means "no more data." A page shorter than
            # requested does NOT mean that — confirmed live against a real
            # PDI: offset=0 returned exactly 100 rows, offset=100 returned
            # 99 (one short), and offset=200 returned a full 100 again,
            # proving real data existed past the short page. Row-level ACL
            # evaluation can silently drop a single row from an otherwise-
            # full pagination window without the server signaling anything
            # unusual — the response looks exactly like "reached the end,"
            # just one row lighter. Treating `len(page) < page_size` as
            # end-of-data (the previous logic) truncated the entire rest of
            # the table the instant that happened once. offset still
            # advances by the requested page_size, not len(page) — offset
            # tracks position in the server's underlying ordered index,
            # which is unaffected by how many rows got filtered out of any
            # one response.
            # An empty page does NOT necessarily mean end-of-data either.
            #
            # The comment above establishes, from live measurement, that
            # row-level ACLs silently remove rows from a pagination window
            # with no server signal. Take that one step further: if 100
            # CONSECUTIVE rows are denied, the window comes back EMPTY —
            # mid-table, indistinguishable from the end.
            #
            # Verified: with data at offsets 0 and 200 and an ACL-emptied
            # window at 100, this returned 100 rows instead of 200,
            # silently. The same class as the short-page bug already fixed
            # here, one window wider, and MORE likely on exactly the
            # least-privileged accounts this tool tells customers to use.
            #
            # So tolerate a bounded run of empty pages (~300 rows) before
            # concluding the table is exhausted. The cost of being wrong in
            # the tolerant direction is three wasted requests; the cost of
            # being wrong in the strict direction is silently dropping the
            # rest of the table.
            if len(page) == 0:
                # Only keep going if the LAST NON-EMPTY page was exactly
                # full. That is the only shape an ACL-emptied window can
                # have — a partial page means the server had fewer rows to
                # give, which is a genuine end-of-data signal.
                #
                # Unconditional tolerance was the first version of this
                # fix, and it cost three extra requests per table on every
                # scan (~35s across the manifest) to defend against a case
                # that leaves a detectable fingerprint. Paying that on
                # every table to catch a rare one is the wrong trade for a
                # tool people already wait two minutes for.
                # Exactly ONE probe window, not a run of them. An empty
                # page does not update `last_nonempty_len`, so a loop that
                # allowed several would keep probing on the strength of a
                # full page seen several windows ago — an earlier version of this
                # loop did, and ran past the end of every fixture.
                if last_nonempty_len != page_size or consecutive_empty:
                    break
                consecutive_empty = 1
            else:
                consecutive_empty = 0
                last_nonempty_len = len(page)
            offset += page_size
        return results

    def probe(self, table: str, fields: list[str] | None = None) -> tuple[str, str | None]:
        """Single-row read-access probe. Returns (status, detail) where
        status is one of "ok" | "denied" | "absent" | "error".

        TWO things changed here after the first live run, both of which
        only a real instance could show:

        1. STATUS, NOT A BOOLEAN. `sn_aia_agent` (no Now Assist licence)
           and `sn_mcp_server_registry` (app not installed) both reported
           ERROR, because the old classification substring-matched the
           exception text for "not found" and ServiceNow says "Invalid
           table" instead. So the two most common real outcomes — an
           unlicensed feature and an uninstalled app — rendered as
           *something is broken*, and the summary counted them as
           failures. A security team reading that concludes the tool is
           half-broken when it is working correctly.

           A scanner cannot distinguish "this table name is wrong" from
           "this feature isn't licensed here" — both are absent. That is
           exactly why it must report the raw platform reason rather
           than collapsing it, so someone on a LICENSED instance can
           tell the difference the tool can't.

        2. REAL FIELDS, NOT `sys_id`. Probing `sysparm_fields=sys_id`
           proves the TABLE exists and says nothing about the FIELDS —
           but detection depends entirely on fields (`connection_url`,
           `sp_widget.script`, `sys_scope.scope`, `sys_properties.type`),
           every one read with `.get()`, so a wrong field name returns
           None and the surface silently detects nothing. Preflight —
           the feature whose whole job is telling a security team what
           will happen — was structurally unable to catch that. Probing
           with the real field list costs the same single row.
        """
        """Single-row read-access probe. Never raises.

        `preflight` previously probed with `safe_get_all(table,
        ["sys_id"])`, which paginates to the safety cap: 50 HTTP
        requests and 5,000 rows per table, on the one command that
        prints "one row probed per table, nothing written." This is
        that claim, implemented.
        """
        requested = fields or ["sys_id"]
        try:
            rows = self.get(
                table,
                {"sysparm_fields": ",".join(requested), "sysparm_limit": 1},
            )
        except requests.RequestException as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            if status in (401, 403):
                # Recorded here as well as in safe_get_all. Missing this
                # was not hypothetical: the first live run of the access
                # section reported 8 grants instead of 12, silently
                # omitting all four MCP governance tables — because
                # mcp_server.py discovers them by probing, and only
                # safe_get_all recorded gaps. The section named every
                # grant except the most valuable one, and looked complete
                # while doing it.
                #
                # The general shape, worth keeping in mind for the next
                # connector: a cross-cutting record has to be written at
                # EVERY point the condition occurs, and "every point" is
                # not the same as "every point considered when the code was
                # written."
                self._record_gap(table, AccessGapKind.TABLE_DENIED)
                return "denied", f"the scan credential lacks read access to '{table}'"
            if status == 404:
                return "absent", f"'{table}' does not exist on this instance"
            # ServiceNow answers an unknown table with 400 + "Invalid
            # table", not 404. Classified as ABSENT (with the platform's
            # own wording preserved) rather than ERROR, because on a real
            # instance that is overwhelmingly an unlicensed or
            # uninstalled feature — not a fault.
            detail = scrub_values(str(e))
            if "invalid table" in detail.lower() or status == 400:
                return "absent", f"'{table}' not present ({detail})"
            return "error", scrub_values(f"failed to read '{table}': {e}")

        # Table readable. Now: did the fields we actually depend on come
        # back? An empty table cannot answer that, so say so rather than
        # claiming verification we don't have.
        if not rows:
            return "ok", "table readable; empty, so field names unverified"
        missing = [f for f in requested if f not in rows[0]]
        if missing:
            # Same reasoning as the denied branch above. `preflight` is
            # the command whose entire job is telling a security team what
            # this scan will and won't see, so a field it finds withheld
            # must reach the access section — otherwise preflight knows
            # something the report doesn't.
            denied, unknown = self.classify_missing_fields(table, missing)
            if unknown:
                # preflight is the command a security team runs to decide
                # whether to grant anything. Telling them a nonexistent
                # column is "missing" sends them to widen access for a bug
                # in this tool — which is exactly what happened for months
                # with `sys_rest_message.endpoint`.
                self._record_gap(table, AccessGapKind.SCHEMA_MISMATCH, tuple(unknown))
            if denied:
                self._record_gap(table, AccessGapKind.FIELD_ACL, tuple(denied))
            parts = []
            if unknown:
                parts.append("NOT REAL COLUMNS (AgentCensus bug): " + ", ".join(unknown))
            if denied:
                parts.append("MISSING FIELDS: " + ", ".join(denied))
            return "ok", " | ".join(parts)
        return "ok", None

    def table_exists(self, table: str) -> tuple[bool, str | None]:
        """Cheap, read-only existence check via sys_db_object rather than
        querying the table itself and interpreting a 400 — an instance
        without the table returns a clean empty result here instead of
        an HTTP error to parse. Never raises — see safe_get_all.

        The `filter_fields` guard matters more here than anywhere else in
        the connector. This filter is the whole check: if an ACL on
        `sys_db_object.name` caused the condition to be dropped, the query
        would return every table on the instance, `len(rows) > 0` would be
        true for every input, and EVERY table would report as existing —
        including the ones whose names are still unverified guesses. Every
        honest "not detected" note in this connector would invert into a
        false positive, and the modules would then read tables that aren't
        there. Measured as filtering correctly on the instance tested
        (1 row for a real name, 0 for an invented one, 1,986 unfiltered).
        """
        rows, error = self.safe_get_all(
            "sys_db_object", ["sys_id"], query=f"name={table}", filter_fields=["name"]
        )
        if error:
            # Fails CLOSED: an unreadable filter field means the row count
            # is meaningless, so "exists" cannot be asserted from it. The
            # caller sees not-found plus the note explaining why, which
            # degrades detection rather than inventing tables.
            return False, error
        return len(rows) > 0, None

    def columns_of(self, table: str) -> set[str]:
        """Real column names for a table, including inherited ones.

        Cached per table per scan. Exists because of the worst defect this
        project has had: ServiceNow omits a requested field that DOESN'T
        EXIST exactly the same way it omits one you're DENIED — field
        missing from the row, HTTP 200, no error. `unreadable_fields` could
        see the symptom and had only one explanation available, so it
        reported "FIELD-LEVEL ACL" for both, and a wrong field name in this
        tool's own tables.py was reported to users as a permissions problem
        on their instance.

        That is how `sys_rest_message.endpoint` — which should have been
        `rest_endpoint` — survived four code reviews and two live runs.
        Tier 2 never worked, and the diagnostic explained its silence
        fluently enough that nobody looked further. A crash would have been
        found in an hour.

        Inheritance matters: `sys_dictionary` rows list a table's OWN
        columns, so `sys_created_by` on `sys_rest_message` lives on an
        ancestor. Walking the `super_class` chain is what stops this
        function from reporting real inherited fields as nonexistent — the
        exact false positive that would make the whole check untrustworthy
        and therefore ignored.

        Fails OPEN: on any error it returns an empty set, and callers treat
        "unknown schema" as "don't claim either cause". A diagnostic aid
        must never be able to break a scan.
        """
        if table in self._columns_cache:
            return self._columns_cache[table]

        columns: set[str] = set()
        try:
            seen: set[str] = set()
            current: str | None = table
            while current and current not in seen:
                seen.add(current)
                rows = self.get_all(
                    "sys_dictionary",
                    ["element"],
                    query=f"name={current}^elementISNOTEMPTY",
                )
                columns.update(r.get("element") for r in rows if r.get("element"))
                current = self._parent_table(current)
        except Exception:
            columns = set()

        self._columns_cache[table] = columns
        return columns

    def _parent_table(self, table: str) -> str | None:
        """The name of `table`'s parent, resolved WITHOUT a dot-walk.

        Two reads: `sys_db_object` by name for the bare `super_class`
        reference, then `sys_db_object` by that sys_id for its `name`.

        The single-read version used `sysparm_fields=super_class.name`,
        and an independent review found that `tables.py` — two files away —
        records a live measurement that the Table API DOES NOT honour
        dot-walks in `sysparm_fields`, concluding "no dot-walks anywhere
        in this connector".

        THE EVIDENCE IS ACTUALLY MIXED, and that is the reason for this
        rewrite rather than a shrug. The reviewer predicted `columns_of`
        would resolve own-columns only, which would make every inherited
        field — `sys_created_by` on nearly every table — read as a schema
        mismatch. That did NOT happen on the instance tested: a full
        manifest audit reported exactly 8 bad field names, all genuine,
        and did not flag `sys_created_by` on `sys_rest_message`, which is
        inherited and therefore provably resolved through the walk. So
        `super_class.name` worked where `action_type.name` did not.

        Why the difference is unknown. Plausibly the failing request also
        asked for the base field (`action_type` AND `action_type.name`)
        while this one asked only for the dotted form; plausibly it is a
        property of the reference or the table. Unknown is the operative
        word.

        So: depend on neither. Two plain reads cost one extra request per
        inheritance level, are verifiable from the response shape, and do
        not require knowing which of two contradictory observations about
        dot-walks is the general rule. A diagnostic whose correctness is
        contingent on an unexplained platform behaviour is not a
        diagnostic — and this one exists specifically to stop the tool
        blaming customers for its own bugs.
        """
        found = self.get(
            "sys_db_object",
            {
                "sysparm_query": f"name={table}",
                "sysparm_fields": "super_class",
                "sysparm_limit": 1,
                "sysparm_exclude_reference_link": "true",
            },
        )
        parent_id = ref(found[0].get("super_class")) if found else None
        if not parent_id:
            return None

        parent = self.get(
            "sys_db_object",
            {
                "sysparm_query": f"sys_id={parent_id}",
                "sysparm_fields": "name",
                "sysparm_limit": 1,
                "sysparm_exclude_reference_link": "true",
            },
        )
        return (parent[0].get("name") or None) if parent else None

    def classify_missing_fields(self, table: str, missing: list[str]) -> tuple[list[str], list[str]]:
        """Split withheld fields into (denied_by_acl, not_a_real_column).

        The second list is a bug in THIS TOOL, not a finding about the
        instance, and the report has to say so — otherwise it sends a
        customer to their security team to request access to a column that
        does not exist.
        """
        known = self.columns_of(table)
        if not known:
            return list(missing), []
        denied, unknown = [], []
        for field in missing:
            # Dot-walked requests are checked on their base field; the ACL
            # and the schema both apply there.
            (denied if field.split(".")[0] in known else unknown).append(field)
        return denied, unknown

    def _record_gap(
        self,
        table: str,
        kind: AccessGapKind,
        fields: tuple[str, ...] = (),
    ) -> None:
        """Capture a refused read as data, at the moment it happens.

        Deduplicated on (table, kind, fields) because the same table is
        read by several modules in one scan — `sys_user` alone is fetched
        by owners.py and integration_accounts.py — and a section that
        listed the same grant four times would be as unusable as the nine
        scattered notes it replaces.

        Never raises and never affects the return value of the caller.
        This is bookkeeping; a bug here must not be able to fail a scan
        that was otherwise succeeding.
        """
        gap = AccessGap(
            table=table,
            kind=kind,
            fields=tuple(fields),
            impact=impact_for(table, tuple(fields)),
        )
        key = (gap.table, gap.kind, gap.fields)
        if key not in self._gap_keys:
            self._gap_keys.add(key)
            self.access_gaps.append(gap)

    @staticmethod
    def unreadable_fields(rows: list[dict], requested: list[str]) -> list[str]:
        """Fields that were ASKED FOR and never came back.

        ServiceNow omits a field from the response entirely when a
        field-level ACL denies read on it — the row arrives with the
        other fields intact and no error anywhere. Combined with this
        connector's defensive `.get()` reads, that produces silence: the
        value is None, no exception is raised, no tier reports a
        problem, and the scan says "0 matched".

        Confirmed live, and it was not theoretical. On a real instance
        the scan credential could FILTER on `sys_rest_message.endpoint`
        (a server-side `endpointISNOTEMPTY` query returned rows) but not
        READ it — the response carried only `name`. Tier 2, the
        CONFIRMED-grade tier the whole confidence model rests on, had
        therefore never been able to fire, and every run reported "0
        outbound REST message(s) matched a known LLM provider host",
        which reads exactly like "there aren't any".

        This project has now met the same shape three times
        (`oauth_entity.client_id`, `sys_user.locked_out`, and this), so
        it is detected once, here, rather than in each tier.

        Checked across ALL returned rows, not just the first: a field
        that is merely EMPTY on one record is still present as a key, so
        sampling one row would raise false alarms on sparse data.
        """
        if not rows:
            return []
        present: set[str] = set()
        for row in rows:
            present.update(row.keys())
        return [f for f in requested if f not in present]

    def safe_get_all(
        self,
        table: str,
        fields: list[str],
        query: str = "",
        filter_fields: list[str] | None = None,
    ) -> tuple[list[dict], str | None]:
        """Same as get_all, but never raises. Real instances have
        inconsistent ACLs across tables — a read-only role that can see
        sys_rest_message may well be denied on sys_script. One denied
        table should degrade the scan, not crash it.

        Returns (rows, note). note is None on a clean, complete read;
        on failure rows is [] and note describes what happened; on a
        truncated-by-cap read, rows is non-empty and note explains the
        truncation. Meant to be appended straight into
        Inventory.scan_notes either way.
        """
        # A filter field must be REQUESTED to be checkable — readability is
        # inferred from whether the instance returned the column, so a
        # field that was never asked for is indistinguishable from one that
        # was refused. Requesting it is what makes the guard below mean
        # anything. Name the base field for a dot-walked condition
        # (`sys_scope`, not `sys_scope.scope`); the ACL applies to the
        # base field and that is what the response can be checked for.
        #
        # These extra columns stay in the returned rows rather than being
        # stripped: they are non-secret by construction (a field used in a
        # filter is one the query already names in plaintext) and they end
        # up in `raw` blobs where they are genuinely useful evidence.
        requested = list(fields)
        if filter_fields:
            requested += [f for f in filter_fields if f not in requested]

        try:
            rows = self.get_all(table, requested, query)
        except requests.RequestException as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            if status == 403:
                self._record_gap(table, AccessGapKind.TABLE_DENIED)
                return [], f"Access denied reading '{table}' — the scan credential lacks read access to this table."
            if status == 404:
                return [], f"'{table}' not found on this instance."
            if status == 429:
                return [], f"Rate limited reading '{table}' after {_MAX_RETRIES} retries — try again later or scan during a quieter window."
            # requests embeds the full request URL in its exception
            # text. ServiceNow keeps auth in headers so nothing leaks
            # today, but this string is written verbatim into the
            # report's scan_notes, and a scan note is not the place to
            # find out a future change put a token in a query string.
            return [], scrub_values(f"Failed to read '{table}': {e}")

        # Checked BEFORE the field-blindness note below, because it is the
        # more dangerous of the two and they can fire together.
        #
        # Measured live (2026-08), and the reason this exists: when the
        # account cannot READ a field, ServiceNow does not merely omit it
        # from the payload — it silently DISCARDS any query condition that
        # names it, and returns the full unfiltered result set with a 200
        # and no warning. Proven with a negative control: on a table with
        # `endpoint` under a field-level ACL, `endpointLIKE<impossible
        # hostname>` returned every row in the table. A filter that cannot
        # fail visibly is worse than no filter, because the caller sizes
        # its trust to a filter it believes ran.
        #
        # Why this is a correctness bug and not just a note: three of this
        # connector's server-side filters are load-bearing. `sys_db_object
        # name=` backs table_exists, so a dropped filter makes EVERY table
        # report as existing. `web_service_access_only=true` backs the
        # integration-account tier, so a dropped filter reports every user
        # on the instance as an API-only identity. `type!=<encrypted>`
        # keeps encrypted property values off the wire. All three were
        # measured as still filtering on the instance tested — those
        # fields were readable there — which is exactly why this needs a
        # guard rather than a one-time check: it is contingent on the
        # scan account's ACLs, and the product asks for least privilege.
        if filter_fields:
            unfiltered = self.unreadable_fields(rows, list(filter_fields))
            if unfiltered:
                self._record_gap(table, AccessGapKind.FILTER_DROPPED, tuple(unfiltered))
                return rows, (
                    f"QUERY FILTER SILENTLY DROPPED on '{table}': the server-side filter "
                    f"references field(s) {', '.join(unfiltered)}, which this account cannot "
                    f"read. ServiceNow discards conditions on unreadable fields WITHOUT an "
                    f"error, so the {len(rows)} row(s) returned are the UNFILTERED set, not "
                    f"the {len(rows)} that matched. Do not treat these rows as matches — "
                    f"they are every record in the table. Grant read access to "
                    f"{unfiltered[0]!r} to make this filter effective."
                )

        blind = self.unreadable_fields(rows, fields)
        if blind:
            denied, unknown = self.classify_missing_fields(table, blind)
            if unknown:
                # A field this tool asked for that the platform does not
                # have. Reported as OUR defect, loudly, and deliberately
                # not as an access gap — there is no permission to grant.
                self._record_gap(table, AccessGapKind.SCHEMA_MISMATCH, tuple(unknown))
            if denied:
                self._record_gap(table, AccessGapKind.FIELD_ACL, tuple(denied))
            # Deliberately loud, and deliberately NOT an error: the read
            # succeeded and the rest of the row is usable. But any tier
            # keying on one of these fields is now blind, and will report
            # "0 found" indistinguishably from "none exist". A governance
            # tool must not let that pass as a clean result.
            return rows, _missing_field_note(table, denied, unknown)

        if len(rows) >= self.max_records_per_table:
            return rows, (
                f"'{table}' has at least {self.max_records_per_table} matching records — "
                f"stopped at the safety cap. Results from this table are incomplete. "
                f"Raise max_records_per_table if you need the full set."
            )
        return rows, None


def _missing_field_note(table: str, denied: list[str], unknown: list[str]) -> str:
    """One note covering both reasons a requested field didn't come back.

    They demand opposite responses from the reader, which is the entire
    reason this function exists rather than one generic sentence:

      denied  -> go ask for read access; the data is there
      unknown -> do NOT ask for anything; this tool asked for a column the
                 platform doesn't have, and no grant will fix it

    The old note said the first for both. That is how a typo in this
    project's own tables.py reached users as an instruction to widen
    permissions on their production instance.
    """
    parts = []
    if unknown:
        parts.append(
            f"SCHEMA MISMATCH on '{table}': this tool requested field(s) "
            f"{', '.join(unknown)}, which DO NOT EXIST on that table. This is a defect "
            f"in AgentCensus, not a permissions problem on your instance — do not grant "
            f"anything for it. Any detection keying on {unknown[0]!r} has been silently "
            f"finding nothing. Please report this with your ServiceNow version."
        )
    if denied:
        parts.append(
            f"FIELD-LEVEL ACL on '{table}': requested field(s) "
            f"{', '.join(denied)} were not returned by the instance, though the "
            f"rest of each row was. Any detection keying on {denied[0]!r} is BLIND "
            f"here and will report zero matches whether or not any exist. Grant "
            f"the scan account read access to these fields, or treat this table's "
            f"results as unverified."
        )
    return " ".join(parts)


def ref(value) -> str | None:
    """Table API reference fields come back as either a raw sys_id
    string or a {"value": sys_id, "link": ...} dict depending on
    sysparm_exclude_reference_link / display value settings."""
    if not value:
        return None
    if isinstance(value, dict):
        return value.get("value")
    return value
