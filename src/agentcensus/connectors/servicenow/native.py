"""Native agent-registry detection.

Tries each known native schema in turn and uses whichever is actually
present — see the module docstring in tables.py for why there isn't
just one. Returns agents/tools/credentials plus scan_notes explaining
what was found (or wasn't), so an instance with neither schema present
produces a clean, explained empty result instead of looking broken.

Every table read goes through `safe_get_all`/`table_exists`, neither of
which raises — a single ACL-denied table degrades to an empty result
plus a note, not a crashed scan. Real instances have inconsistent ACLs
across tables; a scanner that can't tolerate that isn't usable on them.
"""

from __future__ import annotations

from datetime import datetime, timezone

from agentcensus.connectors.servicenow import tables
from agentcensus.connectors.servicenow.http import ServiceNowClient, ref
from agentcensus.connectors.servicenow.owners import fetch_owners
from agentcensus.core.models import (
    AccountType,
    Agent,
    Credential,
    Provenance,
    Tool,
)
from agentcensus.core.redaction import scrub


def _classify_account(run_as: str) -> AccountType:
    if not run_as:
        return AccountType.UNKNOWN
    lowered = run_as.lower()
    if lowered.startswith(("svc_", "api_")) or "integration" in lowered:
        return AccountType.SCOPED_SERVICE_ACCOUNT
    return AccountType.SHARED_HUMAN_ACCOUNT


def _parse_ts(value: str | None):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _fetch_aia(client: ServiceNowClient, notes: list[str]):
    """AI Agent Studio — enterprise, Now Assist-licensed."""
    raw_agents, err = client.safe_get_all(tables.AIA_AGENT_TABLE, tables.AIA_AGENT_FIELDS)
    if err:
        notes.append(err)
    # A note is NOT always fatal. `safe_get_all` returns rows AND a
    # note for a PARTIAL read — safety-cap truncation, or a
    # field-level ACL hiding one column. Bailing on the note threw
    # away every row that did arrive, turning "incomplete" into
    # "nothing found" with only a note to hint at it. Measured live:
    # sys_script hit the 5,000-row cap and all 5,000 Business Rules
    # were discarded. Bail only when there is nothing to work with.
    if not raw_agents:
        return [], [], [], []

    raw_links, err = client.safe_get_all(tables.AIA_AGENT_TOOL_M2M_TABLE, tables.AIA_AGENT_TOOL_M2M_FIELDS)
    if err:
        notes.append(err + " (agent-tool relationships will be incomplete)")
        raw_links = []

    creator_usernames = {a.get("sys_created_by") for a in raw_agents if a.get("sys_created_by")}
    owners_by_username, owner_notes = fetch_owners(client, creator_usernames)
    notes.extend(owner_notes)

    links_by_agent: dict[str, list[dict]] = {}
    for link in raw_links:
        agent_ref = ref(link.get("agent"))
        if agent_ref:
            links_by_agent.setdefault(agent_ref, []).append(link)

    agents: list[Agent] = []
    tools: list[Tool] = []
    credentials: dict[str, Credential] = {}

    for raw in raw_agents:
        sys_id = raw["sys_id"]
        creator = raw.get("sys_created_by")
        owner = owners_by_username.get(creator)
        # run_as is unverified as a plain string vs. a reference field on
        # sn_aia_agent specifically (the table doesn't exist on the one live
        # instance checked so far — no Now Assist license — so this couldn't
        # be confirmed either way). sys_hub_flow's own "run_as" is a plain
        # choice string ("user"/etc.), not a reference, so it's genuinely
        # unclear which shape sn_aia_agent's uses. ref() is a no-op on a
        # plain string and unwraps a {"link","value"} dict if it turns out
        # to be one — cheap insurance either way, same reasoning as
        # owners.py's department fix, just without live confirmation for
        # this specific field.
        run_as = ref(raw.get("run_as")) or ""
        account_type = _classify_account(run_as)

        tool_ids: list[str] = []
        for link in links_by_agent.get(sys_id, []):
            tool_ref = ref(link.get("tool"))
            if not tool_ref:
                continue
            tool_ids.append(tool_ref)
            if tool_ref not in {t.id for t in tools}:
                cred_id = ref(link.get("run_as")) or run_as or None
                if cred_id and cred_id not in credentials:
                    credentials[cred_id] = Credential(
                        id=cred_id,
                        name=cred_id,
                        account_type=_classify_account(cred_id),
                        # cred_id is the run_as identity, not a sys_user record this
                        # module reads directly — there's no independent way to
                        # resolve who owns it. Best-effort proxy: attribute it to
                        # the agent's own resolved owner (already looked up above
                        # from sys_created_by), same "closest available signal"
                        # reasoning shadow.py's tier-2 REST message credential uses
                        # for its own best-effort attribution. Was left owner_id=None
                        # unconditionally before this fix — a real accuracy gap of
                        # the same shape fixed in shadow.py's tier 1/2 credentials.
                        owner_id=owner.id if owner else None,
                    )
                tools.append(
                    Tool(id=tool_ref, name=tool_ref, description=None, credential_id=cred_id, raw=scrub(link))
                )

        agents.append(
            Agent(
                id=sys_id,
                name=raw.get("name", sys_id),
                description=raw.get("description") or None,
                owner_id=owner.id if owner else None,
                tool_ids=tool_ids,
                account_type=account_type,
                provenance=Provenance.NATIVE,
                detection_signal="native:sn_aia_agent",
                last_active_at=_parse_ts(raw.get("sys_updated_on")),
                raw=scrub(raw),
            )
        )

    return agents, tools, list(credentials.values()), list(owners_by_username.values())


def _fetch_build_agent_skills(client: ServiceNowClient, notes: list[str]) -> list[Tool]:
    """Build Agent's skill registry — the tool table this module used to
    say did not exist.

    `sn_build_agent_skill` and `sn_build_agent_skill_resource` were
    declared in tables.py and read by nobody, while this module's own
    docstring asserted in prose that Build Agent has no registry beyond
    conversations. Confirmed live (2026-08): both tables are real.

    They were empty on that instance, which is exactly why the gap
    survived two releases — an unread table and an empty table produce an
    identical report, so the only thing that could have caught this was
    reading the constants and noticing nothing referenced them. Recorded
    because the same trap is open wherever else a constant is defined
    ahead of its consumer.
    """
    skills, err = client.safe_get_all(
        tables.BUILD_AGENT_SKILL_TABLE, tables.BUILD_AGENT_SKILL_FIELDS
    )
    if err:
        notes.append(err + " (Build Agent skill registry)")
    if not skills:
        return []
    return [
        Tool(
            id=s["sys_id"],
            name=s.get("name", s["sys_id"]),
            description="Build Agent skill — a capability registered to the Build Agent schema.",
            credential_id=None,
            provenance=Provenance.NATIVE,
            raw=scrub(s),
        )
        for s in skills
    ]


def _fetch_build_agent(client: ServiceNowClient, notes: list[str]):
    """Build Agent — trial-tier. Agents are synthesized from the
    application_id/application_name referenced by conversation records;
    tools come from the skill registry (see `_fetch_build_agent_skills`).
    First draft — see tables.py caveat."""
    raw_conversations, err = client.safe_get_all(
        tables.BUILD_AGENT_CONVERSATION_TABLE, tables.BUILD_AGENT_CONVERSATION_FIELDS
    )
    if err:
        notes.append(err)
    # A note is NOT always fatal. `safe_get_all` returns rows AND a
    # note for a PARTIAL read — safety-cap truncation, or a
    # field-level ACL hiding one column. Bailing on the note threw
    # away every row that did arrive, turning "incomplete" into
    # "nothing found" with only a note to hint at it. Measured live:
    # sys_script hit the 5,000-row cap and all 5,000 Business Rules
    # were discarded. Bail only when there is nothing to work with.
    # Fetched BEFORE the conversation early-return, not after. Skills and
    # conversations are independent tables: an instance can have registered
    # skills and zero conversations (nobody has used them yet), which is the
    # state that most warrants reporting — a capability configured and
    # unexercised. Bailing on empty conversations would have hidden it.
    skill_tools = _fetch_build_agent_skills(client, notes)

    if not raw_conversations:
        return [], skill_tools, [], []

    creator_usernames = {c.get("sys_created_by") for c in raw_conversations if c.get("sys_created_by")}
    owners_by_username, owner_notes = fetch_owners(client, creator_usernames)
    notes.extend(owner_notes)

    apps: dict[str, dict] = {}
    for c in raw_conversations:
        app_id = c.get("application_id") or c.get("application_name")
        if not app_id:
            continue
        entry = apps.setdefault(
            app_id,
            {"name": c.get("application_name") or app_id, "creators": set(), "last_active": None},
        )
        if c.get("sys_created_by"):
            entry["creators"].add(c["sys_created_by"])
        ts = _parse_ts(c.get("last_message_at"))
        if ts and (entry["last_active"] is None or ts > entry["last_active"]):
            entry["last_active"] = ts

    agents: list[Agent] = []
    for app_id, entry in apps.items():
        owner = None
        # sorted(), so the choice is deterministic. It is also
        # ARBITRARY — alphabetically-first resolvable creator wins — and
        # that matters more than it looks: this picks which user a
        # multi-creator Build Agent app is attributed to, which decides
        # whether `orphaned.creator_inactive` fires at all. Iterating the
        # set directly, the same byte-identical instance produced that
        # finding on roughly one run in three, because CPython randomises
        # str hashing per process. A governance lead re-running a scan to
        # check a finding could fail to reproduce it.
        #
        # The tiebreak rule is named in detection_signal below rather
        # than left implicit, so a reader knows the owner was chosen
        # alphabetically and not because it means something.
        for creator in sorted(entry["creators"]):
            owner = owners_by_username.get(creator)
            if owner:
                break
        agents.append(
            Agent(
                id=app_id,
                name=entry["name"],
                description=None,
                owner_id=owner.id if owner else None,
                provenance=Provenance.NATIVE,
                detection_signal=(
                    "native:sn_build_agent_conversation "
                    "(owner = alphabetically-first resolvable conversation creator)"
                ),
                last_active_at=entry["last_active"],
                raw={},
            )
        )

    return agents, skill_tools, [], list(owners_by_username.values())


def detect_and_fetch(client: ServiceNowClient):
    """Returns (agents, tools, credentials, owners, scan_notes)."""
    notes: list[str] = []

    exists, err = client.table_exists(tables.AIA_AGENT_TABLE)
    if err:
        notes.append(f"Could not check for AI Agent Studio schema: {err}")
    elif exists:
        notes.append("Native schema detected: AI Agent Studio (sn_aia_agent) — enterprise, Now Assist-licensed.")
        agents, tools, creds, owners = _fetch_aia(client, notes)
        return agents, tools, creds, owners, notes

    exists, err = client.table_exists(tables.BUILD_AGENT_CONVERSATION_TABLE)
    if err:
        notes.append(f"Could not check for Build Agent schema: {err}")
    elif exists:
        agents, tools, creds, owners = _fetch_build_agent(client, notes)
        # Phrased from what was actually READ, not from what exists. The
        # previous wording announced "Native schema detected: Build Agent"
        # on the strength of `table_exists` alone, so a shipped-but-empty
        # table — the normal state on any instance where nobody has opened
        # the feature — was reported as a live agent schema. Detected and
        # populated are different claims and the reader is owed the second.
        if agents or tools:
            notes.append(
                "Native schema detected: Build Agent (sn_build_agent_conversation) — trial "
                f"tier, {len(agents)} agent(s) synthesized from distinct application_id values "
                f"in conversation records and {len(tools)} registered skill(s). Treat as a "
                "first draft."
            )
        else:
            notes.append(
                "Build Agent tables are present but EMPTY (no conversations, no registered "
                "skills). The schema ships with the platform, so its presence alone is not "
                "evidence anyone is using it — this is a licensing/installation fact, not a "
                "detection. Nothing was found here and nothing was missed."
            )
        return agents, tools, creds, owners, notes

    notes.append(
        "No native AI agent schema found (checked sn_aia_agent, sn_build_agent_conversation). "
        "This does not mean there are no agents on this instance — see shadow detection results."
    )
    return [], [], [], [], notes
