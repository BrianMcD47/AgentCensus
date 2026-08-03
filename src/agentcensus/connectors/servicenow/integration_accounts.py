"""Generic integration/service-account detection — the provider-agnostic
catch-all tier.

Every other ServiceNow detection path (native.py, shadow.py, flow_designer.py,
mcp_server.py, nask.py) only fires when there's a *positive* signal tying an
artifact to a known LLM provider or a recognized agent-building surface. That
leaves a real gap: an external agent, on ANY platform — Splunk, a homegrown
script, something built on Anthropic's own infrastructure, a vendor product
nobody's heard of — that authenticates into this ServiceNow instance through
a plain integration user or OAuth application leaves no trace any of those
tiers would catch, because none of them look for "an LLM," they look for a
*specific list* of LLM providers or a *specific* agent-building surface. The
caller could be anything.

What every one of those callers DOES need, regardless of what it is or which
platform it lives on, is *an identity to authenticate as*. ServiceNow's own
mechanism for marking an identity as "this is for API access, not a human
logging in" is the `web_service_access_only` flag on `sys_user` — a real,
structural field, not a heuristic. This module reads every account with that
flag set and treats each one as a Credential regardless of whether anything
else in this scan recognized it, then rules/ungoverned.py's
UnattributedIntegrationAccountRule flags the ones nothing else in the
inventory can explain (no tool/agent references the credential, no owner
resolves) — that combination is "something is authenticating here and no
governance record anywhere in this scan says why," which is the closest a
single-platform connector can get to seeing an agent that lives entirely on
someone else's platform: it can't tell you what's on the other end, but it
can tell you the door exists and nobody's claimed it.

Deliberately conservative about confidence: `web_service_access_only=true`
alone doesn't mean "ungoverned" — plenty of legitimate, well-documented
integrations use exactly this flag correctly. CONFIRMED here means "this
account is structurally set up for API-only access," not "this is a
problem" — whether it's a problem is what the rule (not this module)
decides, based on whether anything else in the scan can explain it.
"""

from __future__ import annotations

from agentcensus.connectors.servicenow import tables
from agentcensus.connectors.servicenow.http import ServiceNowClient
from agentcensus.connectors.servicenow.owners import fetch_owners
from agentcensus.core.models import AccountType, Confidence, Credential, Provenance
from agentcensus.core.redaction import scrub

# Declared identity of this module's output. Rules match on this rather
# than on any field the Table API may or may not return for a given row.
SOURCE = "servicenow.integration_accounts"

# API-only accounts ServiceNow itself ships on every instance. Observed
# live: a scan of a stock PDI reported TEN of these as HIGH-severity
# "active with no scan-visible consumer" — which is literally true and
# completely useless, because they came with the platform and the
# customer neither created nor can meaningfully remove them. They are a
# FIXED cost: the same set appears on every instance regardless of size,
# so they dominate a small estate's report and are pure noise on a
# large one.
#
# Annotated, NOT suppressed. They are still reported (a shipped account
# can still be abused, and a customer may have repurposed one), just not
# at the severity reserved for something nobody can explain. Kept as
# data rather than logic so a customer can extend it — same reasoning as
# llm_providers.yaml.
PLATFORM_SHIPPED_ACCOUNTS = frozenset({
    "soap.guest", "virtual.agent", "securitycenter.user", "mic.administrator",
    "guest", "system", "admin", "glide.maint", "sn_esm.guest",
    "employee.experience", "sn_hr_core.guest", "survey.user",
})


def is_platform_shipped(username: str) -> bool:
    """Best-effort: does this look like an account ServiceNow shipped?

    Deliberately conservative — a false positive here LOWERS a finding's
    severity, so the list stays short and exact-match rather than
    pattern-based. Unknown accounts keep full severity."""
    return (username or "").strip().lower() in PLATFORM_SHIPPED_ACCOUNTS


def fetch_integration_accounts(client: ServiceNowClient, notes: list[str]):
    """Returns (credentials, owners). Every sys_user row with
    web_service_access_only=true becomes a Credential; owner is best-effort
    resolved from sys_created_by (who provisioned the account), same
    convention as every other synthesized-agent owner lookup in this
    connector — ServiceNow doesn't track "who administers this service
    account" as a distinct field, so the provisioner is the closest
    available proxy."""
    raw, err = client.safe_get_all(
        tables.USER_TABLE,
        tables.USER_FIELDS,
        query="web_service_access_only=true",
        # This filter is the entire tier. Unguarded, an ACL on
        # `web_service_access_only` would silently drop the condition and
        # return every user on the instance — 639 people reported as
        # API-only integration identities, at a severity that assumes each
        # one is an unattended machine account. Measured as still
        # filtering on the instance tested; the guard exists because that
        # is a fact about that account's roles, not about the platform.
        filter_fields=["web_service_access_only"],
    )
    if err:
        notes.append(err + " (generic integration-account detection skipped)")
        return [], []

    creator_usernames = {u.get("sys_created_by") for u in raw if u.get("sys_created_by")}
    owners_by_username, owner_notes = fetch_owners(client, creator_usernames)
    notes.extend(owner_notes)

    credentials = []
    for u in raw:
        creator = u.get("sys_created_by")
        owner = owners_by_username.get(creator) if creator else None
        # Confirmed live: `locked_out` can be silently absent from the
        # response even when explicitly requested via sysparm_fields and
        # even when other fields on the same row (user_name, active,
        # department, email) come back fine — a field-level ACL
        # restriction independent of table-level read access, not a
        # naming issue (locked_out is real, standard sys_user field).
        # `.get()` already treats "absent" the same as "false" here,
        # which is the conservative choice for this module's purpose:
        # UnattributedIntegrationAccountRule is about surfacing accounts
        # nothing else explains, so defaulting an unknown lock state to
        # "not locked" errs toward surfacing a lead for review rather
        # than silently suppressing one — consistent with this project's
        # general bias (see shadow.py tier 2's template-var fallback).
        locked_out = u.get("locked_out") == "true"
        credentials.append(
            Credential(
                id=u["sys_id"],
                name=u.get("user_name") or u.get("name") or u["sys_id"],
                account_type=AccountType.SCOPED_SERVICE_ACCOUNT,
                owner_id=owner.id if owner else None,
                provenance=Provenance.SYNTHESIZED,
                confidence=Confidence.CONFIRMED,  # web_service_access_only is structural,
                                                   # not a keyword guess — see module docstring
                provider=None,  # deliberately unset — this tier doesn't know or claim to
                                 # know what's on the other end, only that this identity
                                 # exists for API access
                has_audit_logging=None,
                last_used_at=None,  # last_login_time isn't meaningful for API-only accounts
                                     # on most instances (interactive login tracking, not API
                                     # call tracking) — left None rather than mapped to a field
                                     # that would misrepresent actual usage
                # Deliberately None. models.py requires correlation_key be set
                # "only when a connector genuinely knows one (an OAuth
                # client_id, an API key id, an HEC token id)" — an email is
                # not a credential identity. Two service accounts sharing a
                # team mailbox (integrations@corp.com, which is the ordinary
                # way a service account gets an email at all) were being
                # joined by same_identity_as edges, so one inherited the
                # other's downstream agents and therefore its blast radius
                # and severity. correlate.py argues at length that a false
                # merge is worse than a missed one; this was the only
                # producer of the key, and it was inventing it.
                #
                # The email is still carried as Owner.email, which is the
                # field designed for PERSON-level correlation and which
                # correctly does not imply "same credential".
                correlation_key=None,
                source=SOURCE,
                is_platform_shipped=is_platform_shipped(u.get("user_name", "")),
                is_disabled=locked_out,
                raw={**scrub(u), "_locked_out": locked_out},
            )
        )

    notes.append(
        f"Generic integration-account scan: {len(credentials)} account(s) found with "
        "web_service_access_only=true (API-only identities, regardless of what calls them). "
        "See ungoverned.unattributed_integration_account for which ones nothing else in this "
        "scan can explain."
    )
    return credentials, list(owners_by_username.values())
