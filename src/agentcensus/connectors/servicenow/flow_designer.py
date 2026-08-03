"""Flow Designer / IntegrationHub detection — the no-code surface.

Added after a fresh-eyes review of the first version of shadow.py,
which only caught hand-coded integrations (Script Include + Scripted
REST API) and completely missed the no-code path. That's backwards
relative to the project's own thesis: section 1 of the project plan is
explicitly about *non-technical* employees building agents in minutes,
and that's Flow Designer, not someone writing a Script Include.

Three signals, all default-on (unlike shadow.py's tiers 3-4) because
they read structured metadata — flow names, descriptions, action step
names, installed app names — not raw script source. That's a
meaningfully lower-sensitivity read than script bodies, so it doesn't
need the same opt-in gate.

  - Installed IntegrationHub spokes/apps whose name or description
    matches a known LLM provider (sys_store_app). Doesn't mean a flow
    is actively using it, just that the capability exists on the
    instance — NEEDS_REVIEW, emitted as a Tool, not an Agent.
  - Flows (sys_hub_flow) whose name/description matches a provider
    keyword. NEEDS_REVIEW — a name/description match is still a
    heuristic, same as shadow.py's tier 4.
  - Action steps (sys_hub_action_instance) whose name matches a
    provider keyword, correlated back to their parent flow via the
    `flow` reference field. This is what actually produces a properly
    graph-connected Agent: the flow becomes the Agent, each matching
    action step becomes a synthesized Tool the Agent's tool_ids point
    to — learned directly from the tier-4 bug in shadow.py, where
    skipping this correlation step the first time left agents
    disconnected from the graph. Not repeating that here.

KNOWN LIMITATION: this only looks at flow/action *names* and
*descriptions*, not the JSON-blob action input values where the actual
configured endpoint/prompt/model would live. A flow whose LLM call is
only visible in its action's input configuration, with nothing
suggestive in any name, won't be caught. Closing that gap requires
verifying the input-value table/field shape against a live instance —
flagged as a follow-up, not silently skipped.
"""

from __future__ import annotations

import re

from agentcensus.connectors.servicenow import is_inactive, tables
from agentcensus.connectors.servicenow.http import ServiceNowClient, ref
from agentcensus.connectors.servicenow.llm_providers import (
    Provider,
    load_providers,
    match_keywords,
)
from agentcensus.connectors.servicenow.owners import fetch_owners
from agentcensus.core.models import Agent, Confidence, Provenance, Tool
from agentcensus.core.redaction import scrub


def _installed_llm_spokes(client: ServiceNowClient, providers: list[Provider], notes: list[str]) -> list[Tool]:
    raw, err = client.safe_get_all(tables.STORE_APP_TABLE, tables.STORE_APP_FIELDS)
    if err:
        notes.append(err)
    # A note is NOT always fatal. `safe_get_all` returns rows AND a
    # note for a PARTIAL read — safety-cap truncation, or a
    # field-level ACL hiding one column. Bailing on the note threw
    # away every row that did arrive, turning "incomplete" into
    # "nothing found" with only a note to hint at it. Measured live:
    # sys_script hit the 5,000-row cap and all 5,000 Business Rules
    # were discarded. Bail only when there is nothing to work with.
    if not raw:
        return []

    tools = []
    for entry in raw:
        haystack = f"{entry.get('name', '')} {entry.get('short_description', '')}"
        hit_providers = match_keywords(haystack, providers)
        if not hit_providers:
            continue
        tools.append(
            Tool(
                id=entry["sys_id"],
                name=entry.get("name", entry["sys_id"]),
                description=(
                    f"Installed app/spoke matching {', '.join(p.label for p in hit_providers)} "
                    f"— available to Flow Designer flows on this instance, whether or not any "
                    f"flow currently uses it."
                ),
                credential_id=None,
                provenance=Provenance.SYNTHESIZED,
                confidence=Confidence.NEEDS_REVIEW,
                direction="outbound",
                raw=scrub(entry),
            )
        )
    return tools


def _flows_and_actions(
    client: ServiceNowClient,
    providers: list[Provider],
    notes: list[str],
    include_inactive: bool = False,
):
    """Returns (agents, tools, owners) — one Agent per flow that has a
    name/description match or at least one matching action step, with
    tool_ids pointing at synthesized Tools for each matching action so
    the pair shows up connected in the dependency graph."""
    flows, err = client.safe_get_all(tables.HUB_FLOW_TABLE, tables.HUB_FLOW_FIELDS)
    if err:
        notes.append(err)
    # A note is NOT always fatal. `safe_get_all` returns rows AND a
    # note for a PARTIAL read — safety-cap truncation, or a
    # field-level ACL hiding one column. Bailing on the note threw
    # away every row that did arrive, turning "incomplete" into
    # "nothing found" with only a note to hint at it. Measured live:
    # sys_script hit the 5,000-row cap and all 5,000 Business Rules
    # were discarded. Bail only when there is nothing to work with.
    if not flows:
        return [], [], []

    actions, err = client.safe_get_all(
        tables.HUB_ACTION_INSTANCE_TABLE, tables.HUB_ACTION_INSTANCE_FIELDS
    )
    if err:
        notes.append(err + " (flow-level name/description matches will still be found, action-level ones won't)")
        actions = []

    # Action steps carry no name of their own. What identifies a step is
    # the ACTION TYPE it instantiates ("Look Up Records", "Send
    # Notification", and — the ones this tier exists for — any LLM/agent
    # spoke action), reached by dot-walking `action_type`. Requesting
    # `action_type.name` returns it as a flat key on the row.
    #
    # This is why every scan so far reported zero action-level matches: the
    # tier was matching keywords against `name`, a column that does not
    # exist on this table, so it compared against the empty string every
    # time and could never hit.
    action_type_names = _fetch_action_type_names(client, notes)

    actions_by_flow: dict[str, list[dict]] = {}
    for action in actions:
        flow_ref = ref(action.get("flow"))
        if flow_ref:
            actions_by_flow.setdefault(flow_ref, []).append(action)

    creator_usernames = {f.get("sys_created_by") for f in flows if f.get("sys_created_by")}
    owners_by_username, owner_notes = fetch_owners(client, creator_usernames)
    notes.extend(owner_notes)

    # Computed over ALL flows before the keyword loop below, deliberately:
    # a flow using ServiceNow's own GenAI stack usually has an entirely
    # ordinary name, so it will never appear in the provider-matched set.
    # That is the whole reason this surface was invisible.
    platform_note = _platform_ai_note(
        {f["sys_id"]: f for f in flows if f.get("sys_id")},
        actions_by_flow,
        action_type_names,
    )
    if platform_note:
        notes.append(platform_note)

    agents: list[Agent] = []
    synthesized_tools: list[Tool] = []
    excluded_inactive = 0

    for flow in flows:
        # An inactive flow is not a running agent. Filtered here as well
        # as in shadow.py's tier 4 because `--include-inactive` promised
        # "records marked inactive" without qualification while reaching
        # only tier 4 — so an inactive Flow was reported as live and the
        # flag could not suppress it. Flow Designer is the surface
        # tables.py itself calls "genuinely the more important one to get
        # right", since the project's thesis is about non-technical
        # employees building agents in minutes.
        if not include_inactive and is_inactive(flow):
            excluded_inactive += 1
            continue
        flow_id = flow["sys_id"]
        flow_haystack = f"{flow.get('name', '')} {flow.get('description', '')}"
        flow_level_hit = bool(match_keywords(flow_haystack, providers))

        matching_actions = []
        for action in actions_by_flow.get(flow_id, []):
            # NO is_inactive() here any more. `sys_hub_action_instance` has
            # no `active` column at all — verified live (2026-08); the table
            # has five own columns and that is not one of them. This filter
            # was evaluating a field that never existed, `.get()` returned
            # None, and the code counted the step as active. It reported
            # excluding inactive action steps; there is no such concept at
            # this level. Activity belongs to the parent flow, which is
            # already filtered above.
            #
            # Removing a filter that never filtered changes no behaviour.
            # It removes a claim the report was making and could not keep.
            name = _action_name(action, action_type_names)
            hit = match_keywords(name, providers)
            if not hit:
                continue
            tool = Tool(
                id=action["sys_id"],
                name=name or action["sys_id"],
                description=(
                    f"Flow Designer action step in '{flow.get('name', flow_id)}' — keyword "
                    f"match suggests it calls {', '.join(p.label for p in hit)}."
                ),
                credential_id=None,
                provenance=Provenance.SYNTHESIZED,
                confidence=Confidence.NEEDS_REVIEW,
                direction="outbound",
                raw=scrub(action),
            )
            synthesized_tools.append(tool)
            matching_actions.append(tool)

        if not flow_level_hit and not matching_actions:
            continue

        owner = owners_by_username.get(flow.get("sys_created_by"))
        agents.append(
            Agent(
                id=flow_id,
                name=flow.get("name", flow_id),
                description=flow.get("description") or None,
                owner_id=owner.id if owner else None,
                tool_ids=[t.id for t in matching_actions],
                provenance=Provenance.SYNTHESIZED,
                confidence=Confidence.NEEDS_REVIEW,
                detection_signal=(
                    "flow_designer:name_match" if flow_level_hit else "flow_designer:action_step_match"
                ),
                raw={**scrub(flow), "_creator": flow.get("sys_created_by")},
            )
        )

    if excluded_inactive:
        notes.append(
            f"{excluded_inactive} inactive Flow Designer record(s) were excluded. "
            "Pass --include-inactive to include them."
        )

    return agents, synthesized_tools, list(owners_by_username.values())


def _platform_ai_note(
    flows_by_id: dict[str, dict],
    actions_by_flow: dict[str, list[dict]],
    type_names: dict[str, str],
) -> str | None:
    """Flows using ServiceNow's OWN generative-AI actions.

    Reported as a note, never as agents or tools. These actions ship with
    the platform and appear throughout out-of-the-box content, so
    promoting them to findings would bury the customer-built integrations
    this tool exists to surface — the same mistake as ranking ten
    ServiceNow-shipped service accounts at HIGH.

    But silence was wrong too: a flow calling `OneExtend Invocation` is
    invoking an LLM, and every scan before this one reported nothing at
    all, because the provider list only knows third-party hostnames and
    these are internal.

    Word-boundary matched, so `nowassist` doesn't match inside an
    unrelated identifier.
    """
    hits: dict[str, set[str]] = {}
    for flow_id, actions in actions_by_flow.items():
        for action in actions:
            name = _action_name(action, type_names)
            if not name:
                continue
            lowered = name.lower()
            for marker in tables.PLATFORM_AI_ACTION_MARKERS:
                if re.search(r"\b" + re.escape(marker), lowered):
                    hits.setdefault(flow_id, set()).add(name)
                    break

    if not hits:
        return None

    lines = []
    for flow_id, names in sorted(hits.items()):
        # A sys_id is an identifier, not a name, and printing one where a
        # reader expects a name is the same defect NASK had. Measured live:
        # 2 of 4 hits fell through to a bare GUID, because an action can
        # reference a flow that isn't in the scanned set — a subflow, or a
        # flow filtered out as inactive. Say which, rather than printing
        # 32 hex characters and hoping.
        flow = flows_by_id.get(flow_id)
        if flow and (flow.get("name") or "").strip():
            label = flow["name"].strip()
        else:
            label = f"<flow {flow_id} — not in the scanned set (subflow, or excluded as inactive)>"
        lines.append(f"{label} [{', '.join(sorted(names))}]")

    return (
        f"PLATFORM-NATIVE AI: {len(hits)} flow(s) use ServiceNow's own generative-AI "
        f"actions — {'; '.join(lines[:12])}"
        + (f" (+{len(lines) - 12} more)" if len(lines) > 12 else "")
        + ". These are platform-shipped capabilities, not third-party integrations, so "
        "they are reported here rather than as findings. They still mean this instance "
        "sends data to a model: worth knowing which flows, and under whose governance."
    )


def _fetch_action_type_names(client: ServiceNowClient, notes: list[str]) -> dict[str, str]:
    """sys_id -> action type name, read as its own table.

    Replaces a `action_type.name` dot-walk that DID NOT WORK. Measured
    live: the Table API returned `action_type` as a bare sys_id and no
    dot-walked key at all, so the previous fix — which looked correct,
    passed its tests, and shipped — left this tier exactly as dead as the
    `name` column it replaced.

    Two silent failures in a row on the same tier is the argument for
    doing it the boring way. A separate read of a few hundred action types
    is cheap, and a client-side join either finds the name or visibly
    doesn't.
    """
    rows, err = client.safe_get_all(
        tables.HUB_ACTION_TYPE_TABLE, tables.HUB_ACTION_TYPE_FIELDS
    )
    if err:
        notes.append(
            err + " (action-step matching will be limited to flow-level "
            "name/description hits)"
        )
    return {
        r["sys_id"]: (r.get("name") or "")
        for r in rows
        if r.get("sys_id") and r.get("name")
    }


def _action_name(action: dict, type_names: dict[str, str]) -> str:
    """The label of a flow action step, via the joined action-type map.

    Returns "" when the type can't be resolved, and the caller treats that
    as NO MATCH rather than matching against an empty string — which is
    what `action.get("name", "")` did on every row of a table that has no
    `name` column.
    """
    type_ref = ref(action.get("action_type"))
    return type_names.get(type_ref, "") if type_ref else ""


def fetch_flow_designer(
    client: ServiceNowClient,
    providers: list[Provider] | None = None,
    include_inactive: bool = False,
):
    """Returns (agents, tools, owners, notes)."""
    providers = providers or load_providers()
    notes: list[str] = []

    spoke_tools = _installed_llm_spokes(client, providers, notes)
    flow_agents, action_tools, owners = _flows_and_actions(
        client, providers, notes, include_inactive=include_inactive
    )

    notes.append(
        f"Flow Designer detection: {len(spoke_tools)} installed app/spoke(s) matched a known "
        f"LLM provider, {len(flow_agents)} flow(s) flagged via name/description or action-step "
        f"keyword match (all needs review — see module limitations on action input values)."
    )

    return flow_agents, spoke_tools + action_tools, owners, notes
