"""Command-line entry point.

    # recommended: shareable HTML report, script-derived detections
    # included, opens in your browser when done:
    agentcensus scan --connector servicenow --include-script-scan --format html -o report.json

    # cross-platform merged scan — an agent connected to both shows up
    # as one connected component in the graph, not two disjoint ones:
    agentcensus scan --connector servicenow --connector splunk --output report.json

    # check what will be read, and whether this account can read it,
    # before running anything or writing a file:
    agentcensus preflight --connector servicenow --include-script-scan

    # exit 2 if anything is high+, e.g. for a CI job:
    agentcensus scan --connector servicenow --format html --fail-on high

Everything this CLI does is local: connect (read-only) to the target
platform(s), run deterministic rules against what it finds, write the
report locally (mode 0600). Nothing here makes an outbound call to
anything other than the platform(s) being scanned.

Exit codes: 0 success; 1 the scan could not run (bad args, no
connection, unknown connector); 2 the scan ran fine and found findings
at or above --fail-on. 1 and 2 are deliberately distinct — a CI job
needs to respond differently to "couldn't connect" than to "connected
and found something bad."
"""

from __future__ import annotations

import argparse
import sys
import webbrowser
from pathlib import Path

from agentcensus.core import registry
from agentcensus.core.correlate import merge_and_correlate
from agentcensus.core.report import write_html, write_json
from agentcensus.core.rules import default_engine
from agentcensus.core.scan import escalate_findings, run_scan
from agentcensus.core.severity import SeverityConfig


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentcensus")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a platform and write a findings report")
    scan.add_argument(
        "--connector",
        dest="connectors",
        action="append",
        required=True,
        metavar="PLATFORM",
        help=(
            "Which connector to run, e.g. 'servicenow'. Repeatable for a cross-platform "
            "merged scan (e.g. --connector servicenow --connector splunk) — findings run "
            "against one merged inventory and the report's dependency graph links agents/"
            "credentials that correlate across platforms (same OAuth client, same owner "
            "email) into one connected graph. See core/correlate.py. See `agentcensus "
            "connectors` for the full list of available platforms."
        ),
    )
    scan.add_argument("--output", "-o", default="agentcensus-report.json")
    scan.add_argument(
        "--format",
        choices=("json", "html", "both"),
        default="json",
        help=(
            "Output format. 'html' renders a single self-contained, shareable report — "
            "findings ranked by severity, coverage caveats up top. JSON is the machine "
            "format; HTML is the one you hand to whoever has to act on it. 'both' writes "
            "the JSON at --output and an .html alongside it."
        ),
    )
    scan.add_argument(
        "--no-open",
        action="store_true",
        help=(
            "Don't open the HTML report in a browser after writing it. HTML opens "
            "automatically otherwise (ignored for --format json, and silently skipped "
            "if no browser is available)."
        ),
    )
    scan.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "informational"),
        default=None,
        metavar="SEVERITY",
        help=(
            "Exit non-zero (2) if any finding at or above this severity is present. For "
            "scheduled/CI use, so a scan that surfaces something new fails the job instead "
            "of writing a file nobody opens."
        ),
    )
    scan.add_argument(
        "--include-script-scan",
        action="store_true",
        help=(
            "ServiceNow only: enable shadow-detection tiers that read script source "
            "(Script Includes, Business Rules, Scheduled Jobs, Scripted REST APIs). "
            "Off by default — requires a broader read grant than the rest of the scan. "
            "Ignored by connectors that don't support it."
        ),
    )
    scan.add_argument(
        "--include-script-excerpts",
        action="store_true",
        help=(
            "ServiceNow only: include a short, secret-scrubbed excerpt of each matching "
            "script in the report. Script bodies are NEVER stored in full — findings carry "
            "a sha256 fingerprint and length instead — because the scripts this tool flags "
            "are the ungoverned ones most likely to contain a hardcoded credential, and the "
            "report is meant to be shared. Requires --include-script-scan."
        ),
    )
    scan.add_argument(
        "--include-vendor-scope",
        action="store_true",
        help=(
            "ServiceNow only: include script-derived findings from vendor scopes (sn_*, "
            "com.snc/com.glide). Excluded by default because ServiceNow's own shipped code "
            "legitimately mentions LLM providers and would otherwise bury real customer "
            "findings. Turn this on if you suspect the exclusion is hiding something — the "
            "scan note reports how many records it dropped. Note that `global` scope holds "
            "both vendor and customer code and is never excluded."
        ),
    )
    scan.add_argument(
        "--include-inactive",
        action="store_true",
        help=(
            "ServiceNow only: include records marked inactive. Excluded by default (a "
            "disabled business rule isn't a running agent), but an inactive record can "
            "still hold a live credential and can be re-enabled by anyone with write access."
        ),
    )
    scan.add_argument(
        "--llm-providers-extra",
        default=None,
        help=(
            "Path to a YAML file (same shape as llm_providers.yaml) adding to or "
            "overriding individual entries in the bundled LLM provider list — use this "
            "to add an internal/self-hosted LLM gateway hostname. Same as setting "
            "AGENTCENSUS_LLM_PROVIDERS_EXTRA."
        ),
    )
    scan.add_argument(
        "--llm-providers-config",
        default=None,
        help="Path to a YAML file that replaces the bundled provider list entirely, rather than extending it.",
    )
    scan.add_argument(
        "--sensitive-table",
        action="append",
        default=[],
        metavar="TABLE",
        help=(
            "Mark a table/collection as sensitive for Impact scoring (see core/severity.py's "
            "SeverityConfig). Repeatable, e.g. --sensitive-table incident --sensitive-table "
            "sys_user. Currently consumed by rules/access.py's SensitiveTableAccessRule, which "
            "fires when a detected agent's target_table (populated where determinable — today "
            "that's Business Rule-sourced shadow agents, via the rule's `collection` field) is "
            "in this set."
        ),
    )
    scan.add_argument(
        "--sensitive-role",
        action="append",
        default=[],
        metavar="ROLE",
        help=(
            "Mark a role as sensitive for Impact scoring (see core/severity.py's "
            "SeverityConfig). Repeatable. Reserved for role-aware rules; no built-in rule "
            "consumes this yet."
        ),
    )

    sub.add_parser("connectors", help="List available connectors")

    preflight = sub.add_parser(
        "preflight",
        help="Check credentials and per-table read access WITHOUT running a full scan",
    )
    preflight.add_argument("--connector", dest="connectors", action="append", required=True,
                           metavar="PLATFORM")
    preflight.add_argument(
        "--include-script-scan", action="store_true",
        help="Also check the higher-privilege script-source tables.",
    )

    return parser


_SEVERITY_RANK = {
    "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


def _preflight(args) -> int:
    """Answers the first question every enterprise security team asks:
    'what exactly will this read, and does the account I'm about to
    give you actually have access?'

    Without this, the only way to find out was to run a full scan
    against production and read the scan notes afterwards — which is
    precisely the thing they want to approve *before* it happens. It
    reads one row per table (the cheapest possible probe) and reports
    reachable / denied / absent per table, changing nothing.

    Deliberately reports "absent" as neutral rather than as a failure:
    a table that doesn't exist on an instance usually means an
    unlicensed or uninstalled feature, which is information, not a
    problem to fix.
    """
    from agentcensus.connectors.servicenow import tables as sn_tables

    if args.connectors != ["servicenow"]:
        print(
            "preflight currently supports --connector servicenow only. Other connectors "
            "expose access differently and would need their own probe list to report "
            "anything honest.",
            file=sys.stderr,
        )
        return 1

    try:
        connector = registry.get("servicenow")()
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 1

    if not connector.test_connection():
        print("Could not connect to servicenow. Check credentials/env vars.", file=sys.stderr)
        return 1

    probes = list(sn_tables.DEFAULT_READ_MANIFEST) + (
        list(sn_tables.SCRIPT_READ_MANIFEST) if args.include_script_scan else []
    )

    print("Read access preflight — one row probed per table, nothing written.")
    print("Probed with the real field list, so a missing FIELD shows up too.\n")

    counts = {"ok": 0, "denied": 0, "absent": 0, "error": 0}
    caveats: dict[str, list[str]] = {}
    schema_bugs: list[str] = []
    for table, fields, purpose in probes:
        status, detail = connector.client.probe(table, fields)
        counts[status] += 1
        inline = f"   <-- {detail}" if (detail and status == "ok") else ""
        print(f"  {status.upper():<7} {table:<34} {purpose}{inline}")
        if detail and status != "ok":
            # Bucketed by status, not lumped together. The flat list was
            # printed under the "DENIED tables" heading, so `sn_aia_agent`
            # and `domain` — both ABSENT, both entirely expected on an
            # unlicensed instance — read as permission failures. A reader
            # counting problems counted two that weren't.
            caveats.setdefault(status, []).append(f"{table}: {detail}")
        if detail and "NOT REAL COLUMNS" in detail:
            schema_bugs.append(f"{table}: {detail.split('NOT REAL COLUMNS (AgentCensus bug): ')[-1]}")

    if not args.include_script_scan:
        print(
            "\n  (script-source tables not probed — re-run with --include-script-scan "
            "to check the higher-privilege grant those tiers need)"
        )

    print(
        f"\n{counts['ok']} readable, {counts['denied']} denied, "
        f"{counts['absent']} not present on this instance, {counts['error']} errored."
    )
    if counts["absent"]:
        # Spelled out because the tool CANNOT distinguish these two, and a
        # reader who assumes "absent = the tool guessed the table name
        # wrong" reaches the opposite conclusion from one who assumes
        # "absent = feature not licensed here". Both are common. Only a
        # human on a licensed instance can settle it, so give them the
        # platform's own wording instead of a verdict we can't support.
        print(
            "  ABSENT means the table does not exist on THIS instance. That is the "
            "expected result for an unlicensed feature (AI Agent Studio without Now "
            "Assist) or an uninstalled app, and is indistinguishable from outside from "
            "a table name this tool has wrong. Not a failure by itself."
        )
    if counts["denied"]:
        print(
            "  DENIED tables degrade to scan notes rather than failing the scan, so a "
            "partial grant still produces a usable — but explicitly incomplete — report."
        )
    if schema_bugs:
        # Deliberately the loudest thing preflight prints, and deliberately
        # NOT counted alongside denied/absent. Those describe the instance;
        # this describes AgentCensus. Requesting a column the platform does
        # not have is how tier 2 — the only CONFIRMED-grade outbound
        # detection — silently found nothing on every instance for months,
        # while reporting it as the customer's ACL problem.
        #
        # There is nothing here for an admin to grant. Anyone who reads
        # this as a permissions issue has been misled, which is precisely
        # what the old wording did.
        print(
            "\n  !! SCHEMA MISMATCH — a defect in AgentCensus, not in your instance:"
        )
        for bug in schema_bugs:
            print(f"       {bug}")
        print(
            "     These columns do not exist on those tables. Any detection keying on "
            "them is silently finding nothing, and NO permission grant will change that. "
            "Please report this with your ServiceNow version — the schema differs from "
            "the one this build was verified against."
        )
    _CAVEAT_HEADING = {
        "denied": "Denied — a grant would fix these:",
        "absent": "Not present on this instance — expected for unlicensed or "
                  "uninstalled features, and NOT something to grant:",
        "error": "Errored — worth investigating:",
    }
    for status in ("denied", "absent", "error"):
        entries = caveats.get(status)
        if not entries:
            continue
        print(f"\n  {_CAVEAT_HEADING[status]}")
        for caveat in entries:
            print(f"    - {caveat}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "connectors":
        for platform_id in registry.available():
            print(platform_id)
        return 0

    if args.command == "scan":
        if len(args.connectors) != len(set(args.connectors)):
            print(
                f"--connector was given more than once for the same platform: "
                f"{args.connectors}. Each platform should appear once.",
                file=sys.stderr,
            )
            return 1

        if args.include_script_excerpts and not args.include_script_scan:
            print(
                "--include-script-excerpts has no effect without --include-script-scan "
                "(there is no script content to excerpt unless the script tiers run).",
                file=sys.stderr,
            )
            return 1

        if args.sensitive_role:
            # An accepted flag that quietly does nothing is worse than
            # no flag: the user reasonably assumes their input affected
            # the scoring. Say so out loud until a rule consumes it.
            print(
                "warning: --sensitive-role is accepted but no rule consumes it yet, so it "
                "will not affect any finding's severity. --sensitive-table does work.",
                file=sys.stderr,
            )

        inventories = []
        for platform_id in args.connectors:
            try:
                connector_cls = registry.get(platform_id)
            except ValueError as e:
                print(str(e), file=sys.stderr)
                return 1

            connector = connector_cls()
            if not connector.test_connection():
                print(
                    f"Could not connect to {platform_id}. Check credentials/env vars.",
                    file=sys.stderr,
                )
                return 1

            inventories.append(
                connector.fetch_inventory(
                    include_script_scan=args.include_script_scan,
                    include_script_excerpts=args.include_script_excerpts,
                    include_vendor_scope=args.include_vendor_scope,
                    include_inactive=args.include_inactive,
                    llm_providers_extra=args.llm_providers_extra,
                    llm_providers_config=args.llm_providers_config,
                )
            )

        config = SeverityConfig(
            sensitive_tables=set(args.sensitive_table),
            sensitive_roles=set(args.sensitive_role),
        )

        if len(inventories) == 1:
            # Single connector: exactly the pre-multi-connector code path,
            # unnamespaced ids, no correlation step — nothing about this
            # case changes just because --connector is now repeatable.
            inventory = inventories[0]
            findings, graph = run_scan(inventory, config)
        else:
            inventory, graph = merge_and_correlate(inventories)
            findings = default_engine().run(inventory, config)
            escalate_findings(findings, graph)

        written = []
        if args.format in ("json", "both"):
            write_json(inventory, findings, args.output, graph=graph)
            written.append(str(args.output))
        if args.format in ("html", "both"):
            html_path = (
                args.output
                if args.format == "html" and str(args.output).endswith(".html")
                else str(Path(args.output).with_suffix(".html"))
            )
            write_html(inventory, findings, html_path, graph=graph)
            written.append(html_path)
            if not args.no_open:
                try:
                    webbrowser.open(f"file://{Path(html_path).resolve()}")
                except Exception:
                    pass  # no browser available (headless/CI) — the file is still written

        print(
            f"Scanned {len(inventory.agents)} agents across {len(inventories)} platform(s), "
            f"found {len(findings)} findings. Wrote {', '.join(written)}"
        )
        for note in inventory.scan_notes:
            print(f"  note: {note}")

        if args.fail_on:
            threshold = _SEVERITY_RANK[args.fail_on]
            breaching = [
                f for f in findings
                if _SEVERITY_RANK[getattr(f.severity, "value", str(f.severity))] >= threshold
            ]
            if breaching:
                print(
                    f"\n{len(breaching)} finding(s) at or above '{args.fail_on}' — "
                    f"failing as requested by --fail-on.",
                    file=sys.stderr,
                )
                # 2, not 1: exit 1 already means "the scan itself could
                # not run" everywhere else in this CLI. A CI job needs to
                # tell "couldn't connect" apart from "connected fine and
                # found something bad" — those call for opposite responses.
                return 2
        return 0

    if args.command == "preflight":
        return _preflight(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
