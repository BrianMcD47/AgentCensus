"""Shared owner resolution — both native.py and shadow.py need to turn a
`sys_created_by` (or similar) username into an Owner, and both should
treat "no matching sys_user record at all" as its own signal rather
than silently dropping the agent's ownership info.
"""

from __future__ import annotations

from agentcensus.connectors.servicenow import tables
from agentcensus.connectors.servicenow.http import ServiceNowClient, ref
from agentcensus.core.models import UNRESOLVED_OWNER_PREFIX, Owner, OwnerStatus
from agentcensus.core.redaction import scrub

_BATCH_SIZE = 100  # sys_user IN-clause chunk size — keeps the encoded
                    # query URL well under typical server URL-length
                    # limits on instances with many distinct creators


def _valid_username(u: str) -> bool:
    """ServiceNow usernames don't contain query-language operator
    characters in normal use. Reject anything that does rather than
    interpolate it into an encoded query string unescaped — a stray
    '^' or ',' in a value we didn't expect could otherwise change the
    query's meaning, not just its match set."""
    return bool(u) and not any(c in u for c in "^,=!<>'\"")


def _owner_from_row(u: dict) -> Owner:
    status = OwnerStatus.ACTIVE if u.get("active") == "true" else OwnerStatus.INACTIVE
    return Owner(
        id=u["sys_id"],
        display_name=u.get("name") or u.get("user_name", "unknown"),
        status=status,
        # department is a reference field (sys_user -> cmn_department) —
        # confirmed live against a real instance to come back as
        # {"link": "...", "value": "..."} whenever it's set, not a plain
        # string. http.py now sends sysparm_exclude_reference_link=true so
        # this shouldn't happen anymore, but ref() here costs nothing and
        # is a second line of defense against storing a dict in a field
        # typed str | None — this was a real, live-observed bug, not a
        # hypothetical one.
        department=ref(u.get("department")) or None,
        email=u.get("email") or None,
        raw=scrub(u),
    )


def fetch_owners(client: ServiceNowClient, usernames: set[str]) -> tuple[dict[str, Owner], list[str]]:
    """Returns (owners_by_username, scan_notes). Never raises — a failed
    or ACL-denied sys_user read degrades to "all unresolved" plus a note,
    not a crash."""
    notes: list[str] = []
    usernames = {u for u in usernames if u}

    valid = {u for u in usernames if _valid_username(u)}
    skipped = usernames - valid
    if skipped:
        notes.append(
            f"Skipped owner lookup for {len(skipped)} username(s) containing characters "
            "not expected in a ServiceNow username — treated as unresolved rather than "
            "risking query injection."
        )

    by_username: dict[str, Owner] = {}
    batch = sorted(valid)
    for i in range(0, len(batch), _BATCH_SIZE):
        chunk = batch[i : i + _BATCH_SIZE]
        rows, error = client.safe_get_all(
            tables.USER_TABLE,
            tables.USER_FIELDS,
            query=f"user_nameIN{','.join(chunk)}",
            # A dropped filter here returns every user on the instance,
            # and this function's caller matches them back by username —
            # so the failure is quiet: owners simply stop resolving, or
            # resolve to whoever happens to be in the returned page. Worth
            # a note rather than silent misattribution of who owns an
            # agent, which is the single most consequential field in the
            # report for a governance team.
            filter_fields=["user_name"],
        )
        if error:
            notes.append(f"Owner lookup: {error}")
            continue
        for row in rows:
            username = row.get("user_name")
            if username:
                by_username[username] = _owner_from_row(row)

    # sorted(), not raw set iteration: this order flows into
    # Inventory.owners and the JSON report's inventory.owners array and
    # dependency_graph.nodes. CPython randomises str hashing per
    # process, so an unsorted set reorders the report between runs on
    # byte-identical input — breaking the README's "same input, same
    # findings, every run" guarantee and making scan-to-scan diffing
    # useless. Worst exactly when it matters most: if sys_user is
    # ACL-denied, every owner is unresolved and the whole section
    # reshuffles. Not visible to a single-process test loop.
    for username in sorted(usernames):
        if username not in by_username:
            by_username[username] = Owner(
                id=f"{UNRESOLVED_OWNER_PREFIX}{username}", display_name=username, status=OwnerStatus.UNKNOWN
            )

    return by_username, notes
