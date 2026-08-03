"""Fake ServiceNow Table API client shared by native/shadow tests. No
network, no live instance — mirrors the subset of ServiceNowClient's
interface (get_all, safe_get_all, table_exists) that native.py and
shadow.py actually call, including the same never-raises contract.
"""

from __future__ import annotations


class FakeClient:
    def __init__(
        self,
        tables: dict[str, list[dict]],
        deny: set[str] | None = None,
        empty: set[str] | None = None,
    ):
        self._tables = tables
        self._deny = deny or set()  # table names that simulate a 403
        # Real column names per table, for tests that need to distinguish
        # "denied" from "does not exist". Default {} means unknown schema,
        # which the real client treats as fail-open: it declines to claim
        # either cause. That keeps every pre-existing test's behaviour.
        self._columns: dict[str, set[str]] = {}
        # Gap recording, so module tests exercise the path from a refused
        # read to the rendered access section. A round-5 review pointed
        # out that no test did: every module test ran against a client
        # that structurally could not record a gap, so `test_access_gaps`
        # tested the dataclass and the renderer while the WIRING between
        # them was untested. Detections that read `client.access_gaps` —
        # tier 2's blindness guard now does — were untestable.
        self.access_gaps: list = []
        # Tables that EXIST but hold no rows — the ordinary state of any
        # shipped-but-unused feature table, and distinct from absent.
        self._empty = empty or set()

    def get_all(self, table, fields, query=""):
        if table in self._deny:
            raise RuntimeError(f"simulated failure reading {table}")
        return self._tables.get(table, [])

    def _record_gap(self, table, kind, fields=()):
        from agentcensus.core.models import AccessGap
        gap = AccessGap(table=table, kind=kind, fields=tuple(fields))
        if (gap.table, gap.kind, gap.fields) not in {
            (g.table, g.kind, g.fields) for g in self.access_gaps
        }:
            self.access_gaps.append(gap)

    def safe_get_all(self, table, fields, query="", filter_fields=None):
        from agentcensus.core.models import AccessGapKind
        if table in self._deny:
            self._record_gap(table, AccessGapKind.TABLE_DENIED)
            return [], f"Access denied reading '{table}' — the scan credential lacks read access to this table."
        rows = self._tables.get(table, [])
        # Mirrors the real client's guard. ServiceNow silently DISCARDS a
        # query condition naming a field the account cannot read and
        # returns the unfiltered set with a 200 — so a fake that always
        # honours the filter can never reproduce the failure, and the
        # guard would be untested against the only behaviour it exists for.
        if filter_fields and rows:
            unfiltered = self.unreadable_fields(rows, list(filter_fields))
            if unfiltered:
                self._record_gap(table, AccessGapKind.FILTER_DROPPED, unfiltered)
                return rows, (
                    f"QUERY FILTER SILENTLY DROPPED on '{table}': the server-side filter "
                    f"references field(s) {', '.join(unfiltered)}, which this account cannot "
                    f"read. ServiceNow discards conditions on unreadable fields WITHOUT an "
                    f"error, so the {len(rows)} row(s) returned are the UNFILTERED set."
                )
        return rows, None

    def table_exists(self, table):
        if "sys_db_object" in self._deny:
            return False, "Access denied reading 'sys_db_object' — the scan credential lacks read access to this table."
        # NOTE a real divergence from the platform, kept deliberately and
        # flagged rather than silently fixed: here a table with zero rows
        # reads as ABSENT, while ServiceNow reports it as present-and-empty.
        # That difference made an entire defect class untestable — native.py
        # announced "Native schema detected: Build Agent" on table existence
        # alone, so a shipped-but-empty table was reported as a live agent
        # schema, and no fixture could reproduce it because in the fake an
        # empty table simply didn't exist. Pass `empty=` below to model the
        # real behaviour for tests that need it.
        exists = table in self._tables and len(self._tables[table]) > 0
        exists = exists or table in self._empty
        return exists, None

    def record_field_gap(self, table, fields):
        """Explicitly record a field-level gap, for tests that simulate a
        withheld column by monkeypatching `safe_get_all` rather than by
        supplying rows that lack it."""
        from agentcensus.core.models import AccessGapKind
        self._record_gap(table, AccessGapKind.FIELD_ACL, fields)

    def probe(self, table, fields):
        """Mirrors ServiceNowClient.probe's 4-state contract.

        `denied` is the state that matters and the one a fake most easily
        omits: it means the table EXISTS and this account cannot read it,
        which for governance tables is an affirmative finding rather than
        a degraded read. mcp_server.py depends on telling it apart from
        `absent`, so the fake has to be able to express it.
        """
        if table in self._deny:
            return "denied", f"Access denied reading '{table}'."
        if table not in self._tables and table not in self._empty:
            return "absent", f"Table '{table}' does not exist on this instance."
        rows = self._tables.get(table, [])
        missing = self.unreadable_fields(rows, fields)
        if missing:
            return "ok", f"field(s) not returned: {', '.join(missing)}"
        return "ok", f"{len(rows)} row(s)"

    def columns_of(self, table):
        return self._columns.get(table, set())

    def classify_missing_fields(self, table, missing):
        """Mirrors the real client: (denied_by_acl, not_a_real_column).

        Fails open on unknown schema — everything reads as denied — which
        is deliberate. A diagnostic that guesses "this is your bug" without
        evidence would be the same overconfidence, pointed the other way.
        """
        known = self.columns_of(table)
        if not known:
            return list(missing), []
        denied, unknown = [], []
        for f in missing:
            (denied if f.split(".")[0] in known else unknown).append(f)
        return denied, unknown

    @staticmethod
    def unreadable_fields(rows: list[dict], requested: list[str]) -> list[str]:
        if not rows:
            return []
        present: set[str] = set()
        for row in rows:
            present.update(row.keys())
        return [f for f in requested if f not in present]
