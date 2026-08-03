"""Shared helpers for the ServiceNow connector's detection modules."""


def is_inactive(entry: dict) -> bool:
    """One definition of "inactive", used by every detection surface.

    `active` ABSENT is treated as ACTIVE. A field-level ACL can hide it
    — confirmed live for `locked_out` on sys_user, where the field came
    back silently absent for an account that could read the table — and
    defaulting an unknown state to "inactive" would silently drop
    findings. Unknown must never suppress.

    Exists because `--include-inactive` originally reached exactly one
    of the surfaces its help text promised. `active` is requested by 16
    field lists in tables.py; only shadow.py's tier 4 changed behaviour
    when it flipped, so an inactive Flow, MCP registry row or NASK
    mapping was reported as live and the flag could not suppress any of
    them. A predicate copied into five modules would have drifted the
    same way, so it lives here once.
    """
    return str(entry.get("active", "true")).lower() == "false"
