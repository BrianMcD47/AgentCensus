"""Output generation — JSON (machine) and HTML (shareable).

Both formats are implemented. `--format html` renders a
self-contained report with findings ranked by severity and coverage
caveats first; `--format json` is the machine format. The dependency
graph is present in the JSON but NOT yet rendered in the HTML — see
`render_html`'s `graph` parameter, which is accepted and deliberately
unused pending a rendering that's worth reading. That gap is named
here because README calls the graph the differentiating capability,
so a reader of the HTML alone should know it isn't shown yet.

SECRET HANDLING IS FORMAT-DEPENDENT, WHICH IS WHY IT HAPPENS TWICE.
An earlier version scrubbed only the fully assembled document and
claimed in its own docstring that there was "no path around it."
There was: `json.dumps` and `html.escape` rewrite the exact delimiter
characters (`"`, `'`, `&`) the redaction patterns key on, so a scrub
applied after escaping is a scrub applied to text the patterns can no
longer parse. Verified leaks at the time: a credential as the second
query parameter survived into HTML, and a double-quoted assignment
survived into JSON.

Now: values are scrubbed BEFORE escaping (`_esc`, the single funnel
every HTML field passes through), and `_final_scrub` still runs over
the assembled document as a backstop using patterns hardened to match
post-escape forms. Neither layer is trusted alone.
"""

from __future__ import annotations

import dataclasses
import html
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

import networkx as nx

from agentcensus.core import graph as graph_module
from agentcensus.core.models import Finding, Inventory
from agentcensus.core.redaction import scrub_values


def _default(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "value"):  # Enum
        return obj.value
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def to_json(
    inventory: Inventory, findings: list[Finding], graph: nx.DiGraph | None = None
) -> str:
    """`graph` is optional so existing callers (and tests) that only
    have findings, not a scan.run_scan() graph, keep working — the
    dependency_graph section is simply omitted rather than built fresh
    here, so the report always reflects whatever graph the findings
    were actually escalated against, not a silently-rebuilt duplicate.
    """
    payload = {
        "schema_version": "0.2",
        "platform": inventory.platform,
        "scanned_at": inventory.scanned_at,
        "counts": {
            "agents": len(inventory.agents),
            "tools": len(inventory.tools),
            "credentials": len(inventory.credentials),
            "owners": len(inventory.owners),
            "findings": len(findings),
        },
        # What was NOT scanned belongs in the report, not just on the
        # terminal. These notes carry the denied tables, the skipped
        # opt-in tiers, and any safety-cap truncation — i.e. every
        # reason the counts above might understate reality. They used
        # to exist only as CLI stdout, which meant anyone reading the
        # report file (the auditor, the person who receives it three
        # weeks later) had no way to know coverage was partial. A tool
        # whose credibility rests on saying what it can't see has to
        # put that in the artifact it hands over.
        "scan_notes": inventory.scan_notes,
        # Machine-readable twin of the report's access section, so a
        # pipeline can gate on coverage — "fail the build if any filter
        # was dropped" is a check worth being able to write, and reading
        # it out of prose notes would be miserable.
        "access_gaps": [
            {
                "table": g.table,
                "kind": g.kind.value,
                "fields": list(g.fields),
                "grant": g.grant,
                "impact": g.impact,
            }
            for g in inventory.access_gaps
        ],
        "inventory": {
            "agents": inventory.agents,
            "tools": inventory.tools,
            "credentials": inventory.credentials,
            "owners": inventory.owners,
        },
        "findings": findings,
    }
    if graph is not None:
        payload["dependency_graph"] = graph_module.to_dict(graph)
    return _final_scrub(json.dumps(payload, default=_default, indent=2))


def _final_scrub(serialized: str) -> str:
    """Last-line secret scrub over the fully serialized report.

    Connectors already scrub what they put in `raw`, and that's the
    right place to do it — it preserves structure and keeps the fast
    path cheap. But it relies on every connector remembering, at every
    call site, forever. That assumption broke in testing: tier 2's
    `raw` blob was correctly scrubbed while the human-readable
    `description` built from the same endpoint was not, so a
    `?api_key=` sailed into both output formats through a field nobody
    thought of as sensitive.

    A per-connector guard can only protect the fields its author
    remembered. This runs over everything, including fields added by
    connectors written years from now.

    WHAT THIS IS NOT. An earlier version of this docstring claimed
    "there is no path around it, no field it doesn't cover." That was
    false, and the way it was false is the point: by the time this runs,
    `json.dumps` / `html.escape` have already rewritten the delimiters
    the patterns key on, so `?a=1&api_key=X` arrives as
    `?a=1&amp;api_key=X` and a double-quoted assignment arrives with
    escaped quotes. FORMAT was the path around it. The patterns were
    subsequently hardened to match post-escape forms, and `_esc` now
    scrubs before escaping — but the honest description of this
    function is "a backstop that catches what the per-field scrub
    missed", not "a guarantee". Do not restore the stronger claim.

    Safe on JSON: the replacement marker contains no quotes or
    backslashes, so substituting it can't produce invalid JSON. That
    much was true and is verified by test.
    """
    return scrub_values(serialized)


def write_json(
    inventory: Inventory,
    findings: list[Finding],
    path: str | Path,
    graph: nx.DiGraph | None = None,
) -> None:
    """Writes owner-readable only (0600).

    This file is an inventory of every ungoverned integration, its
    owner, and its blast radius — a map of where to attack, if you're
    so inclined. Scans routinely run on a shared jump host or admin
    workstation, where the default 0644 would make it readable by
    every local account. Created with O_CREAT|O_EXCL-less O_TRUNC but
    an explicit mode, and chmod'ed afterwards too so an existing file
    from a previous run (created before this change, or with a
    different umask) gets tightened rather than silently inheriting
    loose permissions.
    """
    path = Path(path)
    payload = to_json(inventory, findings, graph)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(payload)
    try:
        os.chmod(path, 0o600)
    except OSError:
        # Non-POSIX filesystem (a Windows share, some container mounts)
        # — the write already succeeded, and failing the whole scan
        # over a permission-tightening step that the filesystem doesn't
        # support would be worse than proceeding.
        pass


_SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
_SEVERITY_COLOR = {
    "critical": "#7f1d1d", "high": "#b45309", "medium": "#a16207",
    "low": "#3f6212", "informational": "#334155",
}


def _esc(value: Any) -> str:
    """Scrub, THEN escape — never the other way round.

    `html.escape` rewrites `&`, `"` and `'`, which are the delimiters
    `redaction`'s URL-query and quoted-assignment patterns match on.
    Scrubbing the escaped text means matching against a form the
    patterns were not written for, and it fails silently: the report
    renders normally with the credential intact. Doing it here, at the
    one funnel every rendered field passes through, means no HTML
    field can bypass it by being added later.
    """
    return html.escape(scrub_values("" if value is None else str(value)))


_GAP_LABEL = {
    "table_denied": "Table denied",
    "field_acl": "Field withheld",
    "filter_dropped": "Filter dropped",
}


def _owner_label(owner_id: str | None, owners_by_id: dict) -> str:
    """A person's name, not their sys_id.

    Every agent in the first rendered report showed its owner as
    `6816f79cc0a8016401c5a33be04be441`. The owner WAS resolved — the
    Owner record with a real name sat in the same inventory — and the
    table printed the foreign key instead.

    Ownership is the single most consequential column in this report: a
    governance team's first question about any ungoverned agent is who
    is accountable for it. Answering with 32 hex characters is the same
    defect as NASK's "(unnamed)": a value that is technically present and
    humanly useless.
    """
    if not owner_id:
        return "unresolved"
    owner = owners_by_id.get(owner_id)
    if not owner:
        # Deliberately not a bare sys_id. If the reference can't be
        # resolved, say so — the id alone reads like an answer.
        return f"<unresolved owner ref {owner_id[:8]}…>"
    # `display_name`, not `name` — the first draft of this function read
    # `.name`, which does not exist on Owner, so `getattr(..., "")`
    # silently returned empty and every owner would have rendered as their
    # email or a placeholder. Caught only because the test asserted the
    # actual name appears, rather than asserting the sys_id does not.
    #
    # A negative assertion alone ("no sys_id in the output") would have
    # passed against a completely broken implementation. Worth remembering
    # when writing the next one.
    name = (getattr(owner, "display_name", "") or "").strip()
    email = (getattr(owner, "email", "") or "").strip()
    if name and email:
        return f"{name} ({email})"
    return name or email or f"<owner {owner_id[:8]}… has no name or email>"


# Connectors that can report their own blindness.
#
# Membership is EARNED, not assumed: a connector belongs here once it
# records AccessGap entries for the reads it was refused. Everything else
# gets "coverage unknown" rather than a green banner, because an empty gap
# list from a connector that cannot produce gaps is not evidence of
# coverage — it is absence of evidence, which is the one thing this
# project exists to keep the report from confusing.
#
# ServiceNow is the only member today. Splunk and Anthropic are
# implemented but have none of the gap-recording machinery, and a
# review put it plainly: they are not yet peers of the ServiceNow
# connector, and the report was actively lying about them.
GAP_RECORDING_PLATFORMS = frozenset({"servicenow"})


# Where a detected thing actually lives, so a finding can be acted on.
#
# A report that says "ClaudeAgentService is an ungoverned agent" and then
# leaves the reader to work out WHERE that is has done the hard half and
# skipped the easy one. Keyed on the `_kind` this connector already
# records; unknown kinds produce no path rather than a guessed one.
_KIND_TO_TABLE = {
    "script_include": "sys_script_include",
    "business_rule": "sys_script",
    "scheduled_job": "sysauto_script",
    "scripted_rest_api": "sys_ws_operation",
    "widget": "sp_widget",
    "sp_widget": "sp_widget",
    "ui_action": "sys_ui_action",
    "inbound_email_action": "sysevent_in_email_action",
    "fix_script": "sys_script_fix",
    "processor": "sys_processor",
    "flow": "sys_hub_flow",
    "rest_message": "sys_rest_message",
    "oauth_entity": "oauth_entity",
    "user": "sys_user",
    "credential": "sys_user",
}


def _where_to_find(subject_id: str | None, raw: dict | None, signal: str = "") -> str:
    """A paste-able ServiceNow navigation target for one record.

    `<table>.do?sys_id=<id>` goes straight to the record when typed into
    the filter navigator, and works on every UI version — unlike a menu
    path, which moves between releases and differs by role.

    Deliberately not a hyperlink: the report has no reliable instance URL
    (OAuth scans authenticate against a host the reader may reach under a
    different name), and a link that 404s is worse than a string that
    obviously needs pasting.
    """
    if not subject_id:
        return ""

    # `_kind` first — set by shadow.py tier 4 — then the DETECTION SIGNAL,
    # which every detector sets and which encodes the source table.
    #
    # An independent review found this column was dead in the findings table
    # (it read `evidence["raw"]`, a key no rule has ever written) and
    # mostly dead in the agent inventory, because `_kind` is set by tier 4
    # alone. Every Flow Designer, AI Agent Studio and Build Agent row
    # rendered "—". On the reference instance, where tier 4 was
    # ACL-denied, the column was empty everywhere — a feature whose
    # docstring described doing "the easy half" of the job while doing
    # none of it.
    #
    # Signals look like `shadow:script_keyword:script_include:openai`,
    # `flow_designer:name_match`, `native:sn_aia_agent`. Reading the
    # segments is more robust than adding `_kind` to five producers and
    # relying on the sixth to remember.
    kind = (raw or {}).get("_kind") or (raw or {}).get("_source_table")
    table = _KIND_TO_TABLE.get(str(kind or "").lower())

    if not table and signal:
        for segment in str(signal).replace("(", ":").split(":"):
            segment = segment.strip().lower()
            if segment in _KIND_TO_TABLE:
                table = _KIND_TO_TABLE[segment]
                break
            # `native:sn_aia_agent` names the table outright.
            if segment.startswith(("sn_", "sys_")):
                table = segment
                break
        else:
            if str(signal).startswith("flow_designer"):
                table = "sys_hub_flow"

    if not table:
        return ""
    return f"{table}.do?sys_id={subject_id}"


def _subject_location(finding: Finding, subject_index: dict) -> str:
    """Navigation target for a finding, resolved via its subject.

    The old call read `finding.evidence["raw"]`. No rule anywhere writes
    that key, so the lookup was always None and the most action-oriented
    column in the report was an unconditional blank stripe.
    """
    subject = subject_index.get((finding.subject_type, finding.subject_id))
    return _where_to_find(
        finding.subject_id,
        getattr(subject, "raw", None),
        getattr(subject, "detection_signal", "") or (finding.evidence or {}).get("detection_signal", ""),
    )


def _coverage_banner(gaps: list, platform: str = "") -> str:
    """One line above the findings; the detail goes at the bottom.

    Reordered after a reader's reaction to the first rendered report:
    twelve rows of access requirements and nineteen coverage notes ran
    BEFORE any finding. Every line was accurate, and the effect was to
    make the tool look like it hadn't worked — trust dropped before the
    results were reached.

    The honesty is the product, so it is not being cut. It is being put
    where a reader arrives at it having already seen what was found,
    behind one line that says how much was covered and what to grant.
    A scanner that leads with its own caveats reads as a scanner that
    failed.
    """
    if not gaps:
        # An empty list means one of TWO things, and they are opposite.
        #
        # Only the ServiceNow connector records gaps. Anthropic and Splunk
        # have no `_record_gap`, no schema validation, no field-blindness
        # machinery. So a Splunk scan in which every single endpoint
        # returned 403 produced this banner: "Full coverage — every table
        # and field this scan needs was readable." Both halves false.
        #
        # The banner was reading absence of evidence as evidence of
        # coverage — the precise distinction this entire project is
        # organised around, made by the component that summarises it.
        #
        # Allowlisted rather than inferred: a connector earns the green
        # banner by being able to report its own blindness, and a new
        # connector defaults to "unknown" until it can. That is the
        # fail-closed direction.
        if platform and not all(p in GAP_RECORDING_PLATFORMS for p in platform.split("+")):
            return (
                '<div class="banner warn">Coverage unknown. This scan included a '
                f"connector ({_esc(platform)}) that cannot yet report what it was refused, "
                "so an empty gap list here means <em>nothing was recorded</em> — not that "
                "nothing was denied. Treat every count in this report as a lower bound.</div>"
            )
        return (
            '<div class="banner ok">Full coverage — every table and field this scan '
            "needs was readable.</div>"
        )

    tables_denied = sorted({g.table for g in gaps if g.kind.value == "table_denied"})
    fields_denied = sorted({g.table for g in gaps if g.kind.value == "field_acl"})
    bugs = sorted({g.table for g in gaps if g.kind.value == "schema_mismatch"})
    dropped = [g for g in gaps if g.kind.value == "filter_dropped"]

    bits = []
    if tables_denied:
        bits.append(f"{len(tables_denied)} table(s) unreadable")
    if fields_denied:
        bits.append(f"{len(fields_denied)} table(s) with fields withheld")
    if bugs:
        bits.append(f"{len(bugs)} schema mismatch(es) — an AgentCensus bug, not a permission")
    if dropped:
        bits.append(f"{len(dropped)} SILENTLY DROPPED FILTER(S) — some findings may be wrong")

    return (
        '<div class="banner warn">Partial coverage: ' + "; ".join(bits) + ". "
        'Findings below are real; the gaps mean there may be MORE. '
        '<a href="#access">Exact grants needed →</a></div>'
    )


def _render_access_gaps(gaps: list) -> str:
    """The grants that would make this scan complete, as one list.

    Everything here was already in the report — as nine separate notes on
    one live run, each naming a table, each stating a consequence,
    ordered by whenever that table happened to be read. All the
    information and none of the usability: a reader who wants to fix it
    has to collate it by hand, and won't.

    Ordered by whether an impact is known rather than by table name or
    severity. A gap with a measured consequence is one somebody can take
    to a change request; a gap without one is a line item. Sorting by the
    thing that makes the list actionable is the whole point of building
    the section.

    `filter_dropped` is listed FIRST within its group and worded hardest,
    because it is the only kind here that makes the report actively wrong
    rather than incomplete — the rows came back, they just aren't what
    the scan asked for.
    """
    if not gaps:
        return (
            "<p class='muted'>No access gaps — every table and field this scan needs "
            "was readable. Coverage is limited only by what this tool knows to look "
            "for, not by permissions.</p>"
        )

    # Schema mismatches are removed from this section ENTIRELY.
    #
    # They were rendering inside a block headed "Access needed to complete
    # this scan", under the sentence "Each row is one grant to give the
    # scan account", above a five-step "How to grant these" walkthrough
    # ending in "editing ACLs requires security_admin" — for the one kind
    # models.py explicitly defines as NOT an access problem, where there
    # is nothing to grant and no admin to ask.
    #
    # `_coverage_banner` already handled this kind correctly. Both switch
    # on `kind.value`; only one was updated. That is the shape of every
    # coherence defect in this project: a new case added to one consumer
    # of an enum and not the other.
    bugs = [g for g in gaps if g.kind.value == "schema_mismatch"]
    gaps = [g for g in gaps if g.kind.value != "schema_mismatch"]

    dropped = [g for g in gaps if g.kind.value == "filter_dropped"]
    with_impact = [g for g in gaps if g.kind.value != "filter_dropped" and g.impact]
    without = [g for g in gaps if g.kind.value != "filter_dropped" and not g.impact]

    rows = []
    for gap in [*dropped, *with_impact, *without]:
        impact = gap.impact or (
            "Not separately documented — this table is read by the scan but nothing was "
            "measured going blind without it."
        )
        rows.append(
            "<tr>"
            f"<td>{_esc(_GAP_LABEL.get(gap.kind.value, gap.kind.value))}</td>"
            f'<td class="mono">{_esc(gap.grant)}</td>'
            f'<td class="expl">{_esc(impact)}</td>'
            "</tr>"
        )

    bug_block = ""
    if bugs:
        rows_b = "".join(
            f'<li class="mono">{_esc(g.table)}.{{{_esc(", ".join(g.fields))}}}</li>'
            for g in bugs
        )
        bug_block = (
            '<div class="banner warn"><strong>Defects in AgentCensus found during this '
            "scan.</strong> The columns below were requested by this tool and do not exist "
            "on those tables. <strong>There is nothing to grant and no permission that "
            "would help</strong> — any detection keying on them has been silently finding "
            f"nothing. Please report this with your ServiceNow version.<ul>{rows_b}</ul>"
            "</div>"
        )

    if not gaps:
        return bug_block or (
            '<div class="banner ok">No access gaps — every table and field this scan '
            "needs was readable.</div>"
        )

    warning = ""
    if dropped:
        warning = (
            "<p><strong>At least one server-side filter was silently discarded.</strong> "
            "ServiceNow drops a query condition naming a field the account cannot read, "
            "returns HTTP 200, and gives back the UNFILTERED set. Findings derived from "
            "those reads are not merely incomplete — they may be wrong. Treat them as "
            "unusable until the grant below is in place.</p>"
        )

    # HOW to grant it, not just what. The first version of this section
    # named tables and stopped, which leaves a reader who is not a
    # ServiceNow admin — the likely reader of a governance report — with
    # a list they cannot act on. These are the actual steps.
    how = (
        "<details><summary><strong>How to grant these</strong></summary>"
        "<ol>"
        "<li><strong>Create a dedicated read-only role</strong> — in the filter navigator, "
        "<code>sys_user_role.list</code> → New. Name it something like "
        "<code>u_agentcensus_read</code>. Do not use <code>admin</code>: this tool is "
        "designed to run least-privileged, and an admin scan tells you nothing about what "
        "a least-privileged one would see.</li>"
        "<li><strong>Grant table read</strong> — <code>sys_security_acl.list</code> → New, "
        "Type <code>record</code>, Operation <code>read</code>, Name = the table below. "
        "Add your new role under <em>Requires role</em>.</li>"
        "<li><strong>Grant field read</strong> — same form, but Name = "
        "<code>table.field</code> for each field listed. Field ACLs are separate from "
        "table ACLs; granting the table does not grant a restricted column.</li>"
        "<li><strong>Assign the role</strong> to the account the scan authenticates as "
        "(<code>sys_user.list</code> → the user → Roles → Edit).</li>"
        "<li><strong>Re-run <code>agentcensus preflight</code></strong> to confirm before "
        "a full scan.</li>"
        "</ol>"
        "<p class='small'>Editing ACLs requires the elevated <code>security_admin</code> "
        "role — in the ServiceNow UI, use the profile menu → <em>Elevate role</em>. Note "
        "that some tables are restricted by their owning application's cross-scope access "
        "settings rather than by roles; where that's the case, no grant will open them and "
        "they must be read in the UI by hand.</p>"
        "</details>"
    )

    return (
        bug_block
        + warning
        + "<p>Each row is one grant to give the scan account, and what it buys back. "
        "Nothing here is a finding about your instance — it is the boundary of what "
        "this scan was able to see.</p>"
        + how
        + "<table><thead><tr><th>Kind</th><th>Grant needed</th><th>What it unblinds</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def render_html(
    inventory: Inventory, findings: list[Finding], graph: nx.DiGraph | None = None
) -> str:
    """A single self-contained HTML file — no server, no external fetch
    at render time (see the project plan's no-egress constraint).

    This exists because JSON is not a deliverable. The person who has
    to act on this report is a governance or security lead, not the
    person who ran the scan, and handing them a 60KB nested blob makes
    the work of understanding it their problem. Everything below is
    ordered by what that reader needs first: what was found, what's
    worst, what the scan couldn't see, then the detail.

    Scan notes are given top billing rather than being buried at the
    bottom, because a partial scan that looks complete is the most
    dangerous output this tool can produce.
    """
    by_severity: dict[str, list[Finding]] = {s: [] for s in _SEVERITY_ORDER}
    for finding in findings:
        by_severity.setdefault(_sev(finding), []).append(finding)

    counts_row = "".join(
        f'<div class="stat"><span class="n" style="color:{_SEVERITY_COLOR[s]}">'
        f'{len(by_severity.get(s, []))}</span><span class="l">{s}</span></div>'
        for s in _SEVERITY_ORDER
    )

    notes_html = (
        "<ul>" + "".join(f"<li>{_esc(n)}</li>" for n in inventory.scan_notes) + "</ul>"
        if inventory.scan_notes
        else "<p class='muted'>No coverage caveats recorded.</p>"
    )

    access_html = _render_access_gaps(inventory.access_gaps)
    coverage_banner = _coverage_banner(inventory.access_gaps, inventory.platform)
    owners_by_id = {o.id: o for o in inventory.owners}
    # Subjects by (type, id), so a finding can resolve back to the record
    # it describes. The renderer already built exactly this map for
    # owners; the findings table just never used the idea.
    subject_index = {}
    for kind, items in (("agent", inventory.agents), ("tool", inventory.tools),
                        ("credential", inventory.credentials)):
        for item in items:
            subject_index[(kind, item.id)] = item

    # Collapse runs of identical findings before rendering. A real
    # instance has dozens of ordinary API-only service accounts; each is
    # a legitimate finding, and 62 byte-identical HIGH rows above two
    # CONFIRMED `api.anthropic.com` matches is still a failed report —
    # the reader scrolls past the answer to reach the noise. Severity
    # ordering alone cannot fix this, because the ordinary rows really
    # are higher severity; the problem is that they are the SAME row 62
    # times. Grouping is a presentation change that distorts nothing:
    # every subject id is still listed, and the JSON is untouched.
    rows = []
    for severity in _SEVERITY_ORDER:
        grouped: dict[tuple, list[Finding]] = {}
        for finding in by_severity.get(severity, []):
            grouped.setdefault((finding.rule_id, finding.title.split("'")[0]), []).append(finding)

        # Within a severity band, show the smallest groups first: a
        # one-off finding is a specific thing that happened, a group of
        # 62 is a population. The specific thing is what the reader can
        # act on today.
        for _key, group in sorted(grouped.items(), key=lambda kv: len(kv[1])):
            if len(group) > _GROUP_THRESHOLD:
                rows.append(_grouped_row(severity, group))
                continue
            for finding in group:
                evidence = ", ".join(f"{k}={v}" for k, v in (finding.evidence or {}).items())
                rows.append(
                    "<tr>"
                    f'<td><span class="pill" style="background:{_SEVERITY_COLOR[severity]}">'
                    f"{_esc(severity)}</span></td>"
                    f"<td>{_esc(_conf(finding))}</td>"
                    f"<td><strong>{_esc(finding.title)}</strong>"
                    f'<div class="expl">{_esc(finding.explanation)}</div>'
                    f'<div class="action">→ {_esc(finding.recommended_action)}</div></td>'
                    f'<td class="mono">{_esc(finding.subject_type)}<br>{_esc(finding.subject_id)}'
                    + (
                        f'<div class="where">{_esc(_subject_location(finding, subject_index))}</div>'
                        if _subject_location(finding, subject_index)
                        else ""
                    )
                    + "</td>"
                    f'<td class="mono small">{_esc(evidence)}</td>'
                    "</tr>"
                )
    findings_table = (
        "<table><thead><tr><th>Severity</th><th>Confidence</th><th>Finding</th>"
        "<th>Subject</th><th>Evidence</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
        if rows
        else "<p class='muted'>No findings.</p>"
    )

    agent_rows = "".join(
        "<tr>"
        f"<td><strong>{_esc(a.name)}</strong></td>"
        f"<td>{_esc(getattr(a.provenance, 'value', a.provenance))}</td>"
        f"<td>{_esc(getattr(a.confidence, 'value', a.confidence))}</td>"
        f'<td class="mono small">{_esc(a.detection_signal or "—")}</td>'
        f'<td class="mono small">{_esc(_owner_label(a.owner_id, owners_by_id))}</td>'
        f'<td class="where">{_esc(_where_to_find(a.id, a.raw, a.detection_signal or "") or "—")}</td>'
        "</tr>"
        for a in inventory.agents
    )
    agents_table = (
        "<table><thead><tr><th>Agent</th><th>Provenance</th><th>Confidence</th>"
        "<th>Why we think it's an agent</th><th>Owner</th>"
        "<th>Where to find it</th></tr></thead><tbody>"
        + agent_rows
        + "</tbody></table>"
        if agent_rows
        else "<p class='muted'>No agents detected.</p>"
    )

    scanned = inventory.scanned_at
    scanned_str = scanned.isoformat() if hasattr(scanned, "isoformat") else str(scanned)

    return _final_scrub(f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>AgentCensus — {_esc(inventory.platform)}</title>
<style>
 body{{font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
      margin:0;padding:2rem;color:#0f172a;background:#f8fafc;max-width:1200px}}
 h1{{margin:0 0 .25rem;font-size:1.6rem}}
 h2{{margin:2.2rem 0 .6rem;font-size:1.1rem;text-transform:uppercase;
     letter-spacing:.06em;color:#475569}}
 .meta{{color:#64748b;font-size:.9rem;margin-bottom:1.5rem}}
 .stats{{display:flex;gap:1.5rem;flex-wrap:wrap;background:#fff;padding:1rem 1.25rem;
        border:1px solid #e2e8f0;border-radius:8px}}
 .stat{{display:flex;flex-direction:column}}
 .stat .n{{font-size:1.7rem;font-weight:600;line-height:1}}
 .stat .l{{font-size:.75rem;text-transform:uppercase;color:#64748b;letter-spacing:.05em}}
 .notes{{background:#fffbeb;border:1px solid #fcd34d;border-radius:8px;padding:.75rem 1.25rem}}
 .notes ul{{margin:.4rem 0;padding-left:1.1rem}} .notes li{{margin:.3rem 0}}
 table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e2e8f0;
        border-radius:8px;overflow:hidden}}
 th{{text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;
     color:#64748b;background:#f1f5f9;padding:.6rem .8rem}}
 td{{padding:.7rem .8rem;border-top:1px solid #e2e8f0;vertical-align:top}}
 .pill{{color:#fff;padding:.15rem .5rem;border-radius:99px;font-size:.7rem;
        text-transform:uppercase;letter-spacing:.04em;white-space:nowrap}}
 .expl{{color:#475569;font-size:.88rem;margin-top:.25rem}}
 .action{{color:#0369a1;font-size:.85rem;margin-top:.3rem}}
 .mono{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem}}
 .small{{font-size:.75rem;color:#64748b}} .muted{{color:#64748b}}
 footer{{margin-top:3rem;color:#64748b;font-size:.8rem;border-top:1px solid #e2e8f0;
         padding-top:1rem}}
 .banner{{padding:.7rem .9rem;border-radius:8px;margin:1rem 0;font-size:.85rem}}
 .banner.ok{{background:#f0fdf4;border:1px solid #bbf7d0;color:#166534}}
 .banner.warn{{background:#fffbeb;border:1px solid #fde68a;color:#92400e}}
 .where{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.72rem;
         color:#0f766e;margin-top:.3rem}}
</style></head><body>
<h1>AgentCensus</h1>
<div class="meta">{_esc(inventory.platform)} · scanned {_esc(scanned_str)} ·
 {len(inventory.agents)} agents · {len(inventory.tools)} tools ·
 {len(inventory.credentials)} credentials</div>
<div class="stats">{counts_row}</div>
{coverage_banner}

<h2>Findings</h2>
{findings_table}

<h2>Agent inventory</h2>
{agents_table}

<h2 id="access">Access needed to complete this scan</h2>
<div class="notes">{access_html}</div>

<h2>What this scan could not see</h2>
<div class="notes">{notes_html}</div>

<footer>Generated by AgentCensus — read-only, deterministic, no data left this machine.
Script source is never included in reports; findings carry a fingerprint instead.
<code>needs_review</code> findings are heuristic leads, capped at MEDIUM severity including after blast-radius escalation — not verdicts. Where the cap held a finding down, <code>severity_if_confirmed</code> in its evidence says what it would have been.</footer>
</body></html>""")


# Above this many identical findings, render one collapsed row instead.
_GROUP_THRESHOLD = 3


def _group_title(first: Finding) -> str:
    """A label for a collapsed group of findings.

    The title is the shared prefix of the members' titles, taken as
    everything before the first quote — which works for
    "Scripted REST API resource at '/start' ..." and produces EMPTY
    STRING for "'OneExtendGlideUtil' is an agentic integration ...",
    because that one opens with the quote.

    Rendered live, that gave a row reading "11×" followed by nothing: a
    count with no subject. Two of the five finding groups in the first
    real report were unlabelled.

    Falls back to the rule id, which is always present and is what the
    JSON keys on anyway — a reader who sees `ungoverned.shadow_agent` can
    at least look it up, which is more than a bare number offers.
    """
    prefix = first.title.split(chr(39))[0].strip()
    if prefix:
        return prefix
    return str(getattr(first, "rule_id", "") or "finding")


def _grouped_row(severity: str, group: list[Finding]) -> str:
    """One row standing in for N findings, with every subject id still
    listed inside a <details> so nothing is hidden — only un-scrolled.

    The explanation shown belongs to ONE member of the group, and the
    grouping key is (rule_id, title-prefix) — which does not guarantee the
    others say the same thing. Seen live: eleven tool findings collapsed
    under a description naming one specific endpoint and one specific
    provider, which reads as eleven findings about that endpoint. They
    were eleven different subjects.

    Rather than un-group (the noise problem grouping exists to solve) or
    invent a synthetic summary (a new opportunity to state something no
    finding actually says), the row now labels the description as coming
    from a named representative. The reader can see it's a sample.
    """
    first = group[0]
    ids = ", ".join(_esc(f.subject_id) for f in group)
    sample = (
        f'<div class="small">Description below is from one representative record '
        f"({_esc(first.subject_id)}); the other {len(group) - 1} differ in subject and "
        "may differ in detail.</div>"
        if len(group) > 1
        else ""
    )
    return (
        "<tr>"
        f'<td><span class="pill" style="background:{_SEVERITY_COLOR[severity]}">'
        f"{_esc(severity)}</span></td>"
        f"<td>{_esc(_conf(first))}</td>"
        f"<td><strong>{len(group)}× {_esc(_group_title(first))}</strong>"
        f"{sample}"
        f'<div class="expl">{_esc(first.explanation)}</div>'
        f'<div class="action">→ {_esc(first.recommended_action)}</div>'
        f'<details><summary class="small">show all {len(group)} subjects</summary>'
        f'<div class="mono small">{ids}</div></details></td>'
        f'<td class="mono">{_esc(first.subject_type)}<br><span class="small">'
        f"{len(group)} records</span></td>"
        f'<td class="mono small">grouped — see subjects</td>'
        "</tr>"
    )


def _sev(finding: Finding) -> str:
    return getattr(finding.severity, "value", str(finding.severity))


def _conf(finding: Finding) -> str:
    return getattr(finding.confidence, "value", str(finding.confidence))


def write_html(
    inventory: Inventory,
    findings: list[Finding],
    path: str | Path,
    graph: nx.DiGraph | None = None,
) -> None:
    """Same 0600 discipline as write_json — an HTML report is no less
    sensitive for being readable."""
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(render_html(inventory, findings, graph))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
