"""Platform-agnostic data model.

Every connector translates its platform's native objects into these
shapes. Nothing downstream of a connector (rules, severity, graph,
report) knows or cares whether the data came from ServiceNow, Splunk,
or Microsoft 365 — that's the point of the pluggable connector interface
in `core.connector`. Do not add ServiceNow-specific fields here; put
platform-specific detail in `raw` and normalize the rest.

PROVENANCE AND CONFIDENCE

Not every agent a connector finds comes from a clean, platform-native
"here is the list of agents" table. Verified against a live ServiceNow
PDI (2026-07): the native AI Agent Studio tables (`sn_aia_*`) require
paid Now Assist licensing and don't exist at all on a free instance —
and separately, real agentic integrations get hand-built directly on
the platform (Script Include + Scripted REST API + Business Rule)
without ever touching whatever native agent-registry table *does*
exist. A tool that only reads native tables misses exactly the thing
this project exists to find — see section 1 of the project plan,
"27% of APIs connecting these agents are ungoverned."

So every Agent and Credential carries:
  - `provenance`: was this read from a platform's own agent registry,
    or synthesized by AgentCensus from lower-level platform artifacts
    (REST message definitions, OAuth entities, script source)?
  - `confidence`: for synthesized findings, how sure is the detection
    logic? CONFIRMED means the signal is structural (a REST message
    endpoint literally matches a known LLM API host). NEEDS_REVIEW
    means the signal is a heuristic (a keyword turned up in a script
    body) and a human should look before treating it as fact.

`severity.score` reads `confidence` and caps NEEDS_REVIEW findings at
MEDIUM regardless of impact/exposure — an unconfirmed heuristic match
should never scream CRITICAL. See core/severity.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class OwnerStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"          # deactivated/terminated in the platform
    ROLE_CHANGED = "role_changed"  # still active, but moved off the owning team
    UNKNOWN = "unknown"            # platform has no resolvable owner record


class AccountType(str, Enum):
    SCOPED_SERVICE_ACCOUNT = "scoped_service_account"
    SHARED_HUMAN_ACCOUNT = "shared_human_account"
    UNKNOWN = "unknown"


class Provenance(str, Enum):
    NATIVE = "native"        # read from the platform's own agent/tool registry
    SYNTHESIZED = "synthesized"  # inferred by AgentCensus from lower-level artifacts


class Confidence(str, Enum):
    CONFIRMED = "confirmed"        # structural signal (config/registry match)
    NEEDS_REVIEW = "needs_review"  # heuristic signal (keyword/pattern match)


@dataclass
class Owner:
    id: str
    display_name: str
    status: OwnerStatus
    department: str | None = None
    email: str | None = None   # the other cross-platform correlation key, alongside
                                # Credential.correlation_key — the same person's email is
                                # usually the only identity signal two independently-run
                                # connectors (e.g. ServiceNow and Splunk) actually share.
                                # Populated only when the platform's own user record exposes
                                # it structurally; never guessed/constructed.
    raw: dict = field(default_factory=dict)


# Prefix used by connectors that synthesize a placeholder Owner for a
# creator username they could not resolve to a real user record (e.g.
# sys_user was ACL-denied, or the account has since been deleted).
# Exported here rather than living in one connector because RULES have
# to be able to tell a placeholder from a real owner: `owner_id is not
# None` is true for both, which meant an account whose creator was
# genuinely unresolvable was reported as owned, at reduced severity,
# with evidence reading "owner resolved — a question for that owner."
# There is no owner and no one to ask.
UNRESOLVED_OWNER_PREFIX = "unresolved:"


def is_resolved_owner(owner_id: str | None) -> bool:
    """True only for an owner that actually resolved to a platform user.

    Rules must use this rather than a None-check. The placeholder exists
    so the dependency graph has a node to attach to — it is deliberately
    NOT an assertion that anybody owns the thing."""
    return bool(owner_id) and not owner_id.startswith(UNRESOLVED_OWNER_PREFIX)


@dataclass
class Credential:
    """An identity/secret a tool or agent authenticates with.

    This models the *account or credential record*, not the secret
    value itself. AgentCensus never reads or stores secret material —
    only metadata about who/what a credential is and who owns it.
    """
    id: str
    name: str
    account_type: AccountType
    owner_id: str | None
    provenance: Provenance = Provenance.NATIVE
    confidence: Confidence = Confidence.CONFIRMED
    provider: str | None = None          # e.g. "anthropic", "openai" — set when this
                                          # credential was discovered via LLM-provider
                                          # signal matching, else None
    source: str | None = None             # which detection module PRODUCED this
                                          # credential. Declared by the producer, never
                                          # inferred from the wire response.
                                          #
                                          # Rules previously identified integration
                                          # accounts by `"web_service_access_only" in
                                          # raw` — a field-level ACL can drop a single
                                          # field from a row while the rest returns
                                          # fine (confirmed live on this project's own
                                          # test instance, for `locked_out`). When that
                                          # happened to the marker, two separate rule
                                          # skips failed OPEN at once and the noise
                                          # defect they were added to fix came back,
                                          # along with an explanation that was false of
                                          # that population. A guard keyed on data that
                                          # may or may not arrive is not a guard.
    is_platform_shipped: bool = False      # the platform vendor created this identity,
                                          # not the customer. Lowers exposure rather than
                                          # suppressing the finding — see
                                          # integration_accounts.PLATFORM_SHIPPED_ACCOUNTS
                                          # for the live measurement that motivated it.
    is_disabled: bool | None = None       # the platform says this identity cannot
                                          # currently authenticate (ServiceNow locked_out,
                                          # Splunk disabled, Anthropic archived).
                                          # None means NOT DETERMINED, never "enabled" —
                                          # a rule must keep reporting an unknown-state
                                          # credential, since suppressing a lead is worse
                                          # than surfacing one. Normalised here rather than
                                          # left in each connector's private `raw` keys:
                                          # rules were reading `raw["_locked_out"]` for
                                          # ServiceNow while Splunk's `_disabled` and
                                          # Anthropic's key status were computed, stored and
                                          # read by nothing — so a DISABLED HEC token with no
                                          # owner scored CRITICAL identically to a live one.
                                          # Teaching every rule three connectors' private key
                                          # names is the too-shallow shape; one model field
                                          # is the right layer.
    has_audit_logging: bool | None = None
    last_used_at: datetime | None = None
    correlation_key: str | None = None   # platform-agnostic identity fingerprint, set only
                                          # when a connector genuinely knows one (an OAuth
                                          # client_id, an API key id, an HEC token id) — lets
                                          # core/correlate.py recognize "this is the same
                                          # credential" across two independent connector runs
                                          # (e.g. the same OAuth client registered in both
                                          # ServiceNow and Splunk). None means "no known
                                          # cross-platform identity," not "unique" — connectors
                                          # must never invent one just to populate this field.
    raw: dict = field(default_factory=dict)


@dataclass
class Tool:
    """A capability an agent can invoke (action, skill, script, API call)."""
    id: str
    name: str
    description: str | None
    credential_id: str | None            # what identity this tool runs as
    provenance: Provenance = Provenance.NATIVE
    confidence: Confidence = Confidence.CONFIRMED
    direction: str | None = None         # "outbound" (calls an external LLM/API) |
                                          # "inbound" (exposes a surface to external callers)
    input_schema_typed: bool | None = None
    can_write: bool | None = None
    is_irreversible: bool | None = None  # e.g. delete, send, approve, pay
    raw: dict = field(default_factory=dict)


@dataclass
class Agent:
    id: str
    name: str
    description: str | None
    owner_id: str | None
    tool_ids: list[str] = field(default_factory=list)
    account_type: AccountType = AccountType.UNKNOWN
    provenance: Provenance = Provenance.NATIVE
    confidence: Confidence = Confidence.CONFIRMED
    detection_signal: str | None = None  # e.g. "rest_message:anthropic_endpoint" —
                                          # human-readable trail for *why* AgentCensus
                                          # believes this is an agent, required whenever
                                          # provenance is SYNTHESIZED so a reviewer can
                                          # go verify it directly instead of trusting us
    has_approval_gate: bool | None = None
    has_defined_fallback: bool | None = None
    last_active_at: datetime | None = None
    activity_window_days: int | None = None
    successful_outcomes: int | None = None
    target_table: str | None = None      # which platform table/collection this agent's
                                          # underlying artifact operates against, when
                                          # knowable (e.g. a Business Rule's `collection`
                                          # field) — feeds SeverityConfig.sensitive_tables
                                          # impact scoring in rules/access.py. None means
                                          # "not determined", not "not sensitive".
    raw: dict = field(default_factory=dict)


class AccessGapKind(str, Enum):
    TABLE_DENIED = "table_denied"          # 403 on the whole table
    FIELD_ACL = "field_acl"                # table readable, column withheld
    FILTER_DROPPED = "filter_dropped"      # condition on an unreadable field
    # NOT an access problem at all: this tool asked for a column the
    # platform does not have. Listed alongside the others because it
    # produces the identical symptom — a field missing from the response —
    # and telling them apart is the whole point. There is no grant that
    # fixes it, and saying otherwise is what shipped for months.
    SCHEMA_MISMATCH = "schema_mismatch"


@dataclass
class AccessGap:
    """One thing the scan account could not read, and what that cost.

    Recorded as DATA at the moment it happens rather than reconstructed
    later by parsing scan_notes. The notes are prose written for a human
    mid-report; turning them back into structure would mean regex over
    sentences this project rewrites constantly, and the first typo would
    silently empty the access section.

    Exists because the honest reporting this tool does about its own
    blindness had become unusable at volume: nine separate notes on one
    live run, each naming a table and a field, each stating a consequence,
    scattered across a report in the order the tables happened to be read.
    A reader who wants to fix it has to assemble the list by hand. The
    information was all there and none of it was actionable.
    """
    table: str
    kind: AccessGapKind
    fields: tuple[str, ...] = ()
    # What is regained by granting this. Filled from IMPACT_BY_SURFACE
    # where known; None means "read access to this table, purpose not
    # separately documented" rather than "no impact".
    impact: str | None = None

    @property
    def grant(self) -> str:
        """The thing to hand a ServiceNow admin — or an explicit statement
        that there is nothing to hand them."""
        if self.kind is AccessGapKind.SCHEMA_MISMATCH:
            return f"(no grant — AgentCensus bug) {self.table}.{{{', '.join(self.fields)}}}"
        if self.kind is AccessGapKind.TABLE_DENIED:
            return f"read on table {self.table}"
        return f"read on {self.table}.{{{', '.join(self.fields)}}}"


@dataclass
class Inventory:
    """Everything one connector run pulled from one platform."""
    platform: str
    scanned_at: datetime
    agents: list[Agent] = field(default_factory=list)
    tools: list[Tool] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    owners: list[Owner] = field(default_factory=list)
    # Every read the scan account was refused. Rendered as one closing
    # section so "what this scan could not see" is a single actionable
    # list rather than nine notes a reader must collate.
    access_gaps: list[AccessGap] = field(default_factory=list)
    # Free-text notes about the scan itself — e.g. "native AI Agent Studio
    # tables not present on this instance (no Now Assist entitlement)" —
    # surfaced in the report so a human knows what was and wasn't checked,
    # rather than silently returning zero native agents and looking broken.
    scan_notes: list[str] = field(default_factory=list)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingClass(str, Enum):
    ORPHANED = "orphaned_and_abandoned"
    ACCESS = "access_and_permission_risk"
    CONSTRUCTION = "construction_quality"
    REDUNDANCY = "redundancy_and_waste"
    UNGOVERNED = "ungoverned_integration"  # agents/tools with no native governance
                                            # record at all — see rules/ungoverned.py


@dataclass
class Finding:
    rule_id: str
    finding_class: FindingClass
    severity: Severity
    subject_type: str    # "agent" | "tool" | "credential"
    subject_id: str
    title: str
    explanation: str
    recommended_action: str
    confidence: Confidence = Confidence.CONFIRMED
    evidence: dict = field(default_factory=dict)
