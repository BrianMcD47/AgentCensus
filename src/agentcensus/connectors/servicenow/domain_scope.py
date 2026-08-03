"""Domain-separation awareness.

THE PROBLEM THIS SOLVES IS SILENT UNDER-REPORTING, NOT A CRASH.

On a domain-separated ServiceNow instance, domain filtering is applied
at query time to every read. A scan credential that sits in a child
domain sees only that domain's records — no error, no warning, no
indication in the response that anything was filtered out. The scan
completes cleanly and reports fewer agents than exist.

That is the same failure shape as the pagination bug this project
already found and fixed the hard way (see COVERAGE.md's live
verification section): a read that quietly returns less than the truth
is worse than one that fails loudly, because nothing prompts anyone to
look. The pagination version of this cost a full round of live
debugging to notice at all.

It matters disproportionately here because of WHO uses domain
separation: managed service providers and large multi-brand
enterprises — precisely the organizations with the most ungoverned
agents and the most reason to buy a tool that finds them. The customer
most likely to run this is the customer most likely to be silently
under-served by it.

WHAT THIS MODULE DOES, AND WHAT IT DELIBERATELY DOESN'T

It does not try to defeat domain filtering. Reading across domains
requires elevated privilege (a domain-spanning role, or the `sys_domain`
query trick that only works with one), and quietly escalating scope
would violate the least-privilege promise this project makes on the
front page of its README.

Instead it detects whether domain separation is in play at all, and
says so in the report. The customer then knows whether the numbers are
instance-wide or one domain's slice, which is the actual decision they
need to make. An honest "this is a partial view, here's why" beats
both a false total and a privilege grab.
"""

from __future__ import annotations

DOMAIN_TABLE = "domain"
DOMAIN_FIELDS = ["sys_id", "name", "active"]

# 'global' is present on every instance, separated or not — it's the
# root of the domain hierarchy, not evidence of separation.
_GLOBAL_DOMAIN_NAMES = {"global", "top/global", ""}


def check_domain_scope(client, notes: list[str]) -> None:
    """Appends a scan note when the instance appears domain-separated.

    Never raises and never fails a scan: an instance without the domain
    plugin returns no table (or denies it), which is itself the answer
    "not domain separated / can't tell", not an error worth surfacing
    as a failure.
    """
    exists, exists_err = client.table_exists(DOMAIN_TABLE)
    if exists_err or not exists:
        # No domain plugin, or no visibility into it. Either way there's
        # nothing useful to tell the user — an absent domain table on a
        # non-separated instance is the normal case, not a finding.
        return

    rows, err = client.safe_get_all(DOMAIN_TABLE, DOMAIN_FIELDS)
    if err:
        notes.append(
            f"{err} Domain separation could not be checked — if this instance IS "
            "domain-separated, this scan may only cover the scan account's own domain."
        )
        return

    real_domains = [
        r for r in rows
        if str(r.get("name", "")).strip().lower() not in _GLOBAL_DOMAIN_NAMES
    ]
    if not real_domains:
        return

    names = ", ".join(sorted(str(r.get("name", "?")) for r in real_domains)[:8])
    more = f" (+{len(real_domains) - 8} more)" if len(real_domains) > 8 else ""
    notes.append(
        f"DOMAIN SEPARATION IS ACTIVE on this instance ({len(real_domains)} non-global "
        f"domain(s): {names}{more}). ServiceNow filters every read by the scan account's "
        "domain, silently and without error, so these results cover ONLY what that account's "
        "domain can see — not the whole instance. To inventory the full instance, re-run "
        "with a credential in the global domain or one holding a domain-spanning role. "
        "AgentCensus deliberately does not attempt to escalate past this on its own."
    )
