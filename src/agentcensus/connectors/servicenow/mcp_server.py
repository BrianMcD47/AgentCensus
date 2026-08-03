"""ServiceNow MCP Server Console detection — the native OOB MCP surface.

VERIFICATION STATUS: lower confidence than any other module in this
connector, stated plainly rather than glossed over. Public reporting
(ServiceNow Community articles, the Zurich/Australia release notes, and
the MCP Server Console FAQ, current as of mid-2026) confirms:

  - MCP Server Console is a real, GA, scoped ServiceNow application
    (`sn_mcp_server`), shipping in every Now Assist / AI Native SKU,
    minimum platform version Zurich Patch 9 / Australia Patch 2.
  - It is BOTH an MCP provider (packages ServiceNow capabilities — Now
    Assist Skills, Knowledge Graph, Subflows/Actions, Scripted REST
    APIs — and exposes them to external MCP clients: Claude, Copilot,
    or a customer's own homegrown agent, per ServiceNow's own framing)
    and an MCP client (connects out to external MCP servers).
  - Admins register servers, package tools, and register clients (no
    Dynamic Client Registration — every client is manually admin-added)
    from "MCP Server Console" in the platform UI.

What is NOT independently confirmed here: the exact table schema.
`sn_mcp_server_registry` turned up as a named table for MCP server
configuration in general web reporting, but that is not the same
confidence level as native.py's tables, which were confirmed directly
against a live PDI. Treat this module the way native.py's own docstring
asked to be treated before that verification pass happened: structurally
plausible, not yet proven. `table_exists` is used specifically so a
wrong guess degrades to an honest "not found" note instead of a crash
or, worse, a silent false negative that looks like a clean scan.

UPDATE (2026-08), and the reason this module now probes five tables
instead of one: on a live instance the guessed registry name was absent
while FOUR real MCP governance tables (`mcp_auth_scopes`,
`aig_scope_tool_mapping`, `aig_access_policy`,
`aig_access_policy_scope_mapping`) answered 403 — denied, meaning they
exist. The module printed "MCP Server Console not detected... either the
app isn't installed, the instance is below Zurich Patch 9, or the guessed
table name is wrong." All three branches were offered; only the third was
true; nothing in the scan could tell the reader which. That note reads as
"no MCP here," and it was wrong on the first real instance to test it.

The lesson is narrower than "verify table names" and worth stating: a
single probe cannot distinguish *absence of a feature* from *ignorance of
its schema*, yet the note it produces has to assert one or the other.
Probing the feature's satellites breaks the tie, because a governance
table only exists where the thing it governs exists. `denied` is not a
degraded read here — it is the affirmative finding.

Why this module exists anyway rather than waiting for verification: MCP
Server Console is the single most direct answer to "does this platform
have an out-of-the-box MCP server," which is exactly what was asked for
by name. Every row this module finds — regardless of which exact field
means what — represents *an admin-registered MCP exposure point*, which
is itself the finding: it's a capability surface offered to any external
AI agent, confirmed or not by name. That's worth surfacing at
NEEDS_REVIEW even before the field-level schema is nailed down, the same
way shadow.py's tier 4 surfaces a keyword hit before a human confirms it.
"""

from __future__ import annotations

from agentcensus.connectors.servicenow import tables
from agentcensus.connectors.servicenow.http import ServiceNowClient
from agentcensus.connectors.servicenow.owners import fetch_owners
from agentcensus.core.models import Confidence, Provenance, Tool

# Table/field constants live in tables.py, same as every other detection
from agentcensus.core.redaction import scrub

# module in this connector (single source of truth — see
# tests/test_no_secret_fields.py, which mechanically scans every
# `tables.py` *_FIELDS list, not per-module ones, for anything
# secret-shaped). Broad, low-risk field set — sys_id/name/active/
# sys_created_by/sys_updated_on exist on virtually every ServiceNow
# table, chosen specifically so this still returns something useful even
# if the more specific field names (direction, tool_type, target_flow,
# etc.) turn out to differ from what's guessed here once run against a
# real Zurich+ instance.
_MCP_REGISTRY_TABLE = tables.MCP_REGISTRY_TABLE
_MCP_REGISTRY_FIELDS = tables.MCP_REGISTRY_FIELDS


def _registration_label(row: dict) -> str:
    """Identifying label for one MCP server registration.

    `connection_alias` first, then `resource` — the two columns observed
    on `auth_server_connection` in the UI. Falls back to naming the
    record type rather than printing a sys_id, which is an identifier and
    not a name.
    """
    for field in ("connection_alias", "resource", "authorization_type"):
        value = row.get(field)
        if isinstance(value, dict):
            value = value.get("display_value") or value.get("value")
        if value and str(value).strip():
            return str(value).strip()
    return "MCP server registration <no readable identifying field>"


def _satellite_notes(client: ServiceNowClient, registry_found: bool = False) -> list[str]:
    """What to say when the registry table isn't there under the guessed name.

    The old note listed three possible causes and left the reader to pick.
    In practice a reader picks "not installed" and moves on, because that
    is the reassuring one. Measured on a live instance where the reassuring
    one was the wrong one: the registry name was wrong, and four MCP
    governance tables were sitting right there answering 403.

    So don't guess between the branches — ask. Each satellite is probed and
    the answer separates them:

      denied  -> the table EXISTS. MCP governance is configured on this
                 instance and the scan account simply can't read it. This
                 is the case the single-table check reported as absence,
                 and it is the opposite of absence.
      ok      -> readable, and the row count says whether anything is
                 configured.
      absent  -> genuinely not present.

    `denied` is deliberately the loudest outcome. It is the one where the
    customer can act (grant read) and the one where silence is most
    expensive, since a denied MCP table means an MCP surface nobody in this
    report can see.
    """
    denied: list[str] = []
    present: list[str] = []
    missing: list[str] = []

    for table, fields, _why in tables.MCP_SATELLITE_TABLES:
        status, _detail = client.probe(table, fields)
        if status == "denied":
            denied.append(table)
        elif status == "ok":
            present.append(table)
        elif status == "absent":
            missing.append(table)

    if denied or present:
        found = ", ".join(sorted(denied + present))
        if registry_found:
            # The registry WAS found; the caller has already said so. Saying
            # "not found under X" here as well produced two contradictory
            # sentences in one report — seen live, and exactly the kind of
            # thing that costs a reader's trust faster than a wrong number,
            # because it proves the tool isn't reading itself.
            note = (
                f"Supporting MCP governance tables are also present ({found}), consistent "
                "with the registry finding above."
            )
        else:
            note = (
                f"MCP governance tables ARE present on this instance ({found}) even though the "
                f"MCP server registry was not found under '{_MCP_REGISTRY_TABLE}'. Read that as "
                "'this scan does not know the registry's table name on this instance', NOT as "
                "'this instance has no MCP server'. The two are not the same claim and the "
                "difference matters: MCP auth scopes and AI Gateway access policies only exist "
                "where an MCP surface exists to govern."
            )
        if denied:
            note += (
                f" Read access was DENIED on: {', '.join(sorted(denied))}. Those tables hold "
                "the names of the MCP servers and tool groups this instance exposes — grant "
                "the scan account read access to enumerate them, or inspect them by hand."
            )
        return [note]

    return [
        f"MCP Server Console not detected: neither '{_MCP_REGISTRY_TABLE}' nor any of the "
        f"MCP governance tables ({', '.join(t for t, _f, _w in tables.MCP_SATELLITE_TABLES)}) "
        "exist on this instance. This is a stronger negative than previous versions reported "
        "— five independent table names, all absent — but still not proof: the registry's "
        "real table name is unverified (see module docstring), so a differently-named MCP "
        "surface would not be seen here."
    ]


def fetch_mcp_server_console(client: ServiceNowClient, include_inactive: bool = False):
    """Returns (tools, owners, notes)."""
    notes: list[str] = []

    exists, err = client.table_exists(_MCP_REGISTRY_TABLE)
    if err:
        notes.append(f"Could not check for MCP Server Console ({_MCP_REGISTRY_TABLE}): {err}")
        return [], [], notes
    if not exists:
        # The previously-guessed name, checked second. It was wrong on the
        # instance that produced the real one, but a name that public
        # reporting associated with this feature is worth one probe rather
        # than being deleted on the strength of a single instance.
        fallback, _err = client.table_exists(tables.MCP_REGISTRY_FALLBACK_TABLE)
        if fallback:
            notes.append(
                f"MCP registry found under the legacy name "
                f"'{tables.MCP_REGISTRY_FALLBACK_TABLE}' rather than "
                f"'{_MCP_REGISTRY_TABLE}'. Please report this with your ServiceNow "
                "version — it means the table name varies by release and this tool "
                "should check both by default."
            )
        notes.extend(_satellite_notes(client))
        return [], [], notes

    raw, err = client.safe_get_all(_MCP_REGISTRY_TABLE, _MCP_REGISTRY_FIELDS)
    if err:
        # A DENIED registry is the strongest possible statement this module
        # can make, and the bare "access denied" note buried it.
        #
        # Measured live (2026-08): once the registry's real name was found,
        # the table existed and returned 403 — so the previous release's
        # careful "MCP governance tables ARE present" reasoning silently
        # stopped running, because the code now took the registry path and
        # bailed on the error. The report went from explaining that an MCP
        # surface exists here to a one-line permissions complaint. A fix
        # that improves detection while degrading what the report SAYS is
        # not a net improvement.
        if "denied" in err.lower():
            notes.append(
                f"MCP Server Console IS PRESENT on this instance: the registry table "
                f"'{_MCP_REGISTRY_TABLE}' exists but read access was denied. That is a "
                "stronger finding than anything this module can report when the table is "
                "readable-and-empty — the registry exists, so an MCP surface is "
                "configured here, and this scan cannot say what it exposes. Grant read on "
                "that table to enumerate it."
            )
        else:
            notes.append(err)
        notes.extend(_satellite_notes(client, registry_found=True))
    # A note is NOT always fatal. `safe_get_all` returns rows AND a
    # note for a PARTIAL read — safety-cap truncation, or a
    # field-level ACL hiding one column. Bailing on the note threw
    # away every row that did arrive, turning "incomplete" into
    # "nothing found" with only a note to hint at it. Measured live:
    # sys_script hit the 5,000-row cap and all 5,000 Business Rules
    # were discarded. Bail only when there is nothing to work with.
    if not raw:
        return [], [], notes

    creator_usernames = {r.get("sys_created_by") for r in raw if r.get("sys_created_by")}
    owners_by_username, owner_notes = fetch_owners(client, creator_usernames)
    notes.extend(owner_notes)

    tools = [
        Tool(
            id=r["sys_id"],
            # `auth_server_connection` has NO `name` column — its
            # identifying field is `connection_alias`. Every MCP
            # registration therefore rendered as a bare 32-char sys_id.
            #
            # Byte-for-byte the defect nask.py fixed with `_LABEL_FIELDS`
            # in the same session, with the reasoning written out at
            # length ("a sys_id is an identifier, not a name"), left live
            # in the sibling module. The MCP surface is the one tables.py
            # calls the highest-value grant in the connector.
            name=_registration_label(r),
            description=(
                "MCP Server Console registration — an admin-configured MCP exposure point. "
                "Direction (provider vs. client) and which underlying capability it wraps "
                "(Now Assist Skill, Subflow, Scripted REST API, Knowledge Graph) are not "
                "distinguishable from this field set — see module docstring. Treat every row "
                "here as 'this instance offers or consumes an MCP surface,' confirm specifics "
                "manually via MCP Server Console in the platform UI."
            ),
            credential_id=None,
            provenance=Provenance.SYNTHESIZED,
            confidence=Confidence.NEEDS_REVIEW,
            direction=None,  # genuinely unknown from this field set — see docstring
            raw=scrub(r),
        )
        # `active` is requested by this field list and was never
        # consulted, so an inactive registration was reported as a live
        # MCP surface and --include-inactive could not suppress it.
        for r in raw
    ]
    # NO inactive filter. `active` is not a column on
    # `auth_server_connection`, so `is_inactive` always returned False,
    # the counter was structurally always zero, and the note it guarded
    # could never print. The comment above it still claimed "`active` is
    # requested by this field list" — true of the old guessed table,
    # false since the registry was renamed.
    #
    # Deleted rather than repaired: adding `active` to the field list
    # would be inventing a column, which is the exact class of bug this
    # module has already produced once.

    notes.append(
        f"MCP Server Console: {len(tools)} registration(s) found in '{_MCP_REGISTRY_TABLE}'. "
        "This is the native OOB MCP server surface — every registration is a capability "
        "exposed to, or a connection made out to, an external AI agent by design, whether "
        "that agent is Claude, Copilot, another ServiceNow instance, or a customer's own."
    )
    return tools, list(owners_by_username.values()), notes
