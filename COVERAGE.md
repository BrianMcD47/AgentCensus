> **Engineering record.** What this tool can and cannot see, and every
> defect found while establishing that — including the ones that were
> the tool's own fault, and one claim significant enough to warrant a
> retraction. Kept in detail because a scanner's findings are only
> worth what its account of its own limits is worth.

# Scenario coverage matrix

This document maps every agent/tool/architecture scenario AgentCensus was
asked to cover to how it's actually detected — and, just as importantly,
states plainly where a scanner architecturally cannot see something,
rather than implying broader coverage than exists.

## ServiceNow (native to the scanned platform)

| Scenario | Module | Status |
|---|---|---|
| Out-of-box AI agents (AI Agent Studio, Build Agent) | `native.py` | Detected — native registry read |
| Out-of-box MCP server (MCP Server Console) | `mcp_server.py` | Detected, low schema confidence — table presence/count confirmed real, field-level schema unverified against a live instance (see module docstring) |
| Custom agents (Script Include / Business Rule / Scheduled Job) | `shadow.py` tier 4 | Detected — CONFIRMED when correlated to a tier-2 tool, NEEDS_REVIEW otherwise |
| Custom tools (REST Message, Scripted REST API) | `shadow.py` tiers 2–3 | Detected |
| Custom skills (Now Assist Skill Kit) | `nask.py` | Detected, schema unverified (same caveat class as `mcp_server.py`) |
| Custom flows (Flow Designer / IntegrationHub) | `flow_designer.py` | Detected |
| Custom/unknown architecture authenticating via any account | `integration_accounts.py` + `ungoverned.unattributed_integration_account` | Detected at the credential level — provider-agnostic, catches literally anything with a ServiceNow identity regardless of what it is |
| External agents/tools calling OUT from ServiceNow to a known LLM host | `shadow.py` tiers 1–2 | Detected |
| External agents/tools calling IN to ServiceNow (any origin, any platform) | `integration_accounts.py`, `shadow.py` tier 3 | Partially detected — sees the credential/surface, cannot identify what's on the other end |
| Agents connecting to Anthropic specifically | `shadow.py` (host/keyword match against `llm_providers.yaml`) | Detected when the call is structurally visible from ServiceNow's side |

## Anthropic (agents/credentials that live on the model provider's own infrastructure)

| Scenario | Module | Status |
|---|---|---|
| API keys issued by the org | `connectors/anthropic` | Detected — native Admin API read, owner resolved from `created_by` where it matches a current member |
| WIF service accounts (non-human identities) | `connectors/anthropic` | Detected, requires an `org:admin` OAuth token (Admin API key insufficient — Anthropic's own restriction) |
| Deactivated/removed organization member | `connectors/anthropic` | **Not detectable.** Anthropic's documented roles don't include an inactive/removed state, and the members list endpoint most likely only returns current members — every returned member is honestly marked ACTIVE rather than guessed at (an earlier draft of this connector had a fabricated check for this that never actually worked; see `_owner_from_member`'s docstring for the correction). `orphaned.credential_no_owner` still catches an API key whose `created_by` doesn't resolve to any current member at all. |
| What an API key/service account is actually used to build | — | **Not detectable.** Anthropic's Admin API is an org/workspace/credential management surface, not an agent registry — it does not track what customers build. No `Agent` objects are synthesized here; see the connector's module docstring. |

## Splunk (a second platform, alongside ServiceNow — the "integrations between other platforms" scenario)

| Scenario | Module | Status |
|---|---|---|
| Alerts (saved searches) calling out to a known LLM host via webhook | `connectors/splunk` | Detected, CONFIRMED — structural |
| Saved searches referencing an LLM provider via SPL/custom command | `connectors/splunk` | Detected, NEEDS_REVIEW — keyword heuristic |
| Installed apps matching an LLM provider or MCP Server for Splunk | `connectors/splunk` | Detected, NEEDS_REVIEW |
| External systems sending data in via HEC token | `connectors/splunk` | Detected at the credential level — same "see the door, not the caller" reasoning as ServiceNow's `integration_accounts.py` |
| Verified against a live Splunk instance | — | **Not done.** No developer instance was available this session. Endpoint paths and response shape are real/documented Splunk REST API (see `endpoints.py`); this connector's end-to-end behavior against live data is unverified, the same status several ServiceNow tiers carried before their own live-verification pass. |

## Cross-platform (an agent connected to two or more platforms simultaneously)

| Scenario | Module | Status |
|---|---|---|
| Same credential/identity visible on two platforms | `core/correlate.py` | **Implemented but INERT.** The merge machinery is correct and tested, and has no signal to act on: no shipped connector populates `Credential.correlation_key` (the only one that did was inventing it from an email, which merged unrelated service accounts sharing a team mailbox), and `Owner.email` edges connect graph sinks, so they de-duplicate people without widening any credential blast radius. A connector gap, not a module bug — stated in `correlate.py`'s docstring and README rather than left to be assumed working. |
| Same identity, but neither connector happened to expose a shared signal for it | `core/correlate.py` | **Not detectable.** A false merge (treating two different identities as one) is worse than a missed one on a security graph — this is a deliberate design boundary, not an oversight. |
| Multi-platform CLI run | `cli.py` (`--connector` is repeatable) | Implemented |

## Microsoft 365 / Copilot Studio

| Scenario | Module | Status |
|---|---|---|
| Copilot Studio agents, Power Platform/Graph-surfaced integrations | `connectors/microsoft365` | **Not built.** Still the genuine stub named in `PROJECT_PLAN.md` section 5 and `README.md`'s connector table — its module raises `NotImplementedError` at import time on purpose, and `core/registry.py` skips registering it cleanly. Named here explicitly, not left as a silent absence from this matrix, since this document's whole point is not implying broader coverage than exists. |

## The hard boundary — stated once, plainly

An agent or tool that leaves **zero footprint** on every platform this
project has a connector for, and zero footprint in Anthropic's own
Admin API (no credential, no API key, no service account, no log entry
reachable by any of the above) is **undetectable by any scanner**, this
one included. That is not a gap on a roadmap — it is a physical limit
of "read-only, evidence-based detection." Anything claiming to
inventory 100% of an organization's AI agents without that caveat is
either wrong or is including forms of surveillance (endpoint agents,
network traffic interception, browser extensions) that this project
deliberately does not do — see the project plan's "what this is not."

What this project *can* do, and does: maximize the surface area where a
footprint plausibly exists (accounts, credentials, API keys, structured
config, script source) and read every one of those surfaces it has a
connector for, honestly labeling confidence and verification status per
signal rather than presenting a uniform false confidence.

## Fixed in the fresh-eyes audit pass following the initial build

Named here rather than left implicit, since "fresh eyes" is only worth
something if what it found is on the record:

- **Security:** Splunk's config-read REST endpoints have no field
  allowlist the way ServiceNow's Table API does — the HTTP Event
  Collector token endpoint was returning the token's actual usable
  secret value in cleartext, which would have been written straight
  into the JSON report. Fixed with `_scrub_secrets`, applied everywhere
  a Splunk `raw` blob is built, and locked in with an end-to-end test
  (`tests/test_no_secret_fields.py`) that serializes a full report and
  asserts the secret string never appears in it — not just that one
  function redacts it in isolation.
- **Accuracy:** ServiceNow's tier-1 (OAuth) and tier-2 (REST message)
  shadow credentials were fetching `sys_created_by` into their raw data
  and never actually using it to resolve an owner — only tier-4 agents
  got that treatment. Every synthesized credential now gets the same
  best-effort owner attribution `orphaned.credential_no_owner` and
  `orphaned.creator_inactive`/`orphaned.creator_unresolved` depend on.
- **Accuracy:** the Anthropic connector's member-status check
  (`role == "removed"`) was checking for a value Anthropic doesn't
  actually document — dead logic that looked like a real signal but
  wasn't one. Replaced with an honest "every returned member is marked
  ACTIVE because this connector has no verified way to detect
  otherwise," rather than a fabricated check.
- **New rule:** `orphaned.credential_no_owner` — the project plan's own
  "credentials and integration users with no associated active owner"
  target existed for Agents but never for Credentials, even though the
  field (`Credential.owner_id`) existed on the model from the start.
  Now checked, and it's what makes an unattributed Anthropic API key or
  Splunk HEC token actually surface as a finding, not just as inventory.

## Fixed in the second fresh-eyes audit pass

- **Accuracy:** two more spots had the same "owner data was fetched but
  never actually used" shape the first audit pass fixed in ServiceNow's
  shadow.py — native.py's AI Agent Studio tool-credential (the `run_as`
  identity a tool executes as) was always built with `owner_id=None`;
  Splunk's HEC token credentials never read the `acl.owner` field the
  same file already reads for saved-search agents two functions away.
  Both now get the same best-effort owner attribution every other
  synthesized credential in this project gets.
- **Accuracy:** `llm_providers.yaml` listed `x-api-key` as an
  Anthropic-specific script-keyword signal. It isn't — it's a generic
  REST API header convention plenty of non-Anthropic services use, so a
  script authenticating to an unrelated API with that header would have
  been mislabeled as an Anthropic integration. Removed; host-based
  matching (the CONFIRMED-tier signal) still catches every real
  `api.anthropic.com` reference, and the `claude-`/`anthropic` keywords
  remain distinctive enough to keep.
- **Consistency:** README's "Ungoverned integration" bullet still said
  "Why the ServiceNow connector has two layers," a stale cross-reference
  from before `flow_designer.py` made it three; and the same bullet, plus
  "Access and permission risk," never mentioned two rules that actually
  exist and are CLI-documented (`access.sensitive_table_write`,
  `ungoverned.unattributed_integration_account`) — the second of which is
  the flagship rule for the "agent on a platform with no connector at
  all" scenario this document leans on heavily elsewhere. Both fixed.
  This document itself was also missing a Microsoft 365/Copilot Studio
  row entirely, inconsistent with README's connector table — added
  above rather than left as a silent gap in a document whose purpose is
  not implying broader coverage than exists.

## ServiceNow hardening pass (no live instance available)

With Splunk/Microsoft 365 work paused to focus on ServiceNow, the next
pass closed the one concretely-diagnosed (not hypothetical) gap that
didn't require live-instance access to fix safely:

- **Accuracy:** tier 2's own docstring had documented, for a while, that
  a REST message endpoint using an unresolved `${variable}` placeholder
  — observed live on a real PDI — can never match `match_host`, no
  matter how complete the provider list is, because the real host is
  resolved by ServiceNow elsewhere. The result was a silent miss: zero
  finding, not even a lead, for a real integration this connector could
  otherwise see exists. `_tier2_rest_message_tools` now falls back to a
  keyword match on the REST message's own `name` — a field tier 2 never
  read before — when the endpoint is templated, surfaced at
  NEEDS_REVIEW rather than dropped. A templated endpoint with no
  suggestive name still produces nothing, honestly, since there's no
  remaining signal to anchor a finding to.

Deliberately NOT attempted without live verification: closing
Flow Designer's action-input-value blind spot (the JSON-blob field
shape isn't documented with the same confidence `sn_mcp_server`'s app
scope name is — guessing it risks reading a wrong or nonexistent field
and either crashing or fabricating a false signal, which is worse than
the honestly-labeled gap already there) and expanding the MCP Server
Console / NASK table-name guesses to cover more possibilities (adding
more unverified guesses doesn't increase confidence, it just adds more
speculative surface — the same trap the Anthropic connector's
`_owner_from_member` fell into before the first audit pass corrected it).

## Live verification pass (real ServiceNow instance, via a connected read-only integration)

The gap named honestly everywhere else in this document — "not yet run
against a live instance" — got closed for real here, against a second
PDI independent of the one used during the original build. Read-only
calls only (`list_records`, `get_table_schema`, `get_current_user`,
`aggregate_records`); nothing that writes.

- **Real bug found and fixed, not just a table-name guess corrected:**
  ServiceNow's Table API returns reference-type fields as
  `{"link": "...", "value": "..."}` dicts by default — this connector
  wasn't requesting `sysparm_exclude_reference_link=true`, so any
  reference field read outside the handful already routed through the
  existing `ref()` helper was exposed to storing a dict where the model
  expects a plain string. Directly confirmed on `sys_user.department`.
  `SensitiveTableAccessRule` comparing a dict against a `set[str]` would
  raise `TypeError: unhashable type`, not just misbehave, if the same
  shape hit `sys_script.collection`. Fixed at the root — `http.py` now
  sends the parameter on every table read — plus defensively at each
  affected call site (`owners.py`'s department, `native.py`'s run_as,
  shadow.py tier 4's collection), each with a test proving the dict form
  is handled.
- **Table existence reconfirmed independently:** `sn_build_agent_conversation`,
  `sys_hub_flow` (every field in `HUB_FLOW_FIELDS` verified present on
  real data), `sys_generative_ai_provider_mapping` (directly readable),
  and `sys_generative_ai_model_config` (table-level 403, but "unauthorized"
  is a structurally different, more informative error than "invalid
  table" — it confirms the table exists) all check out on a second,
  independent instance from the one used during the original build.
- **MCP Server Console confirmed absent, not just unreachable:** a
  `sys_db_object` registry scan for any table name containing
  "mcp_server" returned zero rows on this instance — the scoped app
  isn't installed there at all, which is a different finding from "the
  guessed table name is wrong" and doesn't resolve that question either
  way. It did prove `mcp_server.py`'s honest "not detected" degrade path
  fires correctly against a real instance, not just a test fixture.
- **Field-level ACLs are a real, separate thing from table-level ACLs:**
  on the specific read-only integration account tested, `oauth_entity`
  was fully readable for `name`/`sys_id` but silently omitted
  `client_id`/`sys_created_by`/`sys_updated_by`/`sys_updated_on` on
  every row; `sys_user` similarly omitted `locked_out` while returning
  `user_name`/`active`/`department`/`email` fine. Neither is a naming
  bug — both are documented, standard fields — and neither crashes
  anything, since every field read in this connector already goes
  through `.get()` rather than a bare index. Worth naming because it's
  live proof the "leave fields None rather than guessing" design
  principle (`core/connector.py`'s own interface docstring) is load-
  bearing in practice, not just a nice sentiment.
- **Table-level ACL denials reconfirmed the fault-isolation design
  works under real restriction, not just simulated denial:** this
  integration account was denied on `sys_rest_message`,
  `sys_script_include`, `sys_script`, `sys_ws_operation`,
  `sys_hub_action_instance`, and `sys_store_app` — a materially more
  restricted grant than the account used during the original build.
  Every denial degraded to a scan note, as designed; nothing crashed.
  This didn't newly confirm those tables' field shapes (already
  confirmed on the original build's PDI), but it's a real second data
  point that the degrade path holds up under a properly restricted
  account, which is the account shape most real deployments will
  actually use.
- **Discovered, not pursued:** the same `sys_db_object` scan surfaced
  several more real `sys_generative_ai_*` tables not currently read
  (`prompt_config`, `capability_definition`, `feedback_score`, among
  others) — noted in `tables.py` as a candidate follow-up rather than
  added speculatively. `prompt_config` in particular likely holds
  literal prompt template text, the same sensitivity class this
  project already avoids in NASK's log tables by design.

## Second live verification pass (user-run CLI, real PDI, real custom app)

The most consequential round of live testing yet — run entirely by the
project's own user, on their own PDI, with their own OAuth client-
credentials app, `--include-script-scan` enabled, against a custom-built
native ServiceNow application they wrote independently
(`native-servicenow-app` in
[BrianMcD47/servicenow-claude-mcp-bridge](https://github.com/BrianMcD47/servicenow-claude-mcp-bridge)) —
a Script Include + Scripted REST API + async Business Rule calling the
Anthropic API directly via `sn_ws.RESTMessageV2`, with no formal
`sys_rest_message` record and no `oauth_entity`, exactly the "ad hoc,
no registered endpoint" shape tier 4's keyword fallback exists for.

**Two real, confirmed bugs in `get_all`'s pagination, found and fixed in
sequence — the first fix was real but incomplete, and the investigation
said so plainly rather than declaring victory early.**

*Bug 1 — no stable sort.* The same unfiltered `sys_script_include` read
returned 199 rows through the normal paginated code path, 996 rows
through a single large-limit request, and 1992 rows once an explicit
`ORDERBYsys_id` was added to that single request — three different
counts for what should have been the identical query. Fixed via
`_with_stable_order`, forcing a deterministic `ORDERBYsys_id` onto
every request. Real, and necessary, but shipping it and re-testing live
(including a retest 48 hours later, specifically to rule out a
time/consistency explanation for a related anomaly — see below)
returned the same 199-row count again. The ordering fix alone was not
sufficient.

*Bug 2 — the actual cause.* Direct page-by-page curl calls isolated it:
`offset=0` returned 100 rows, `offset=100` returned **99**, `offset=200`
returned 100 again. `get_all`'s loop treated any page shorter than
requested as "end of data" (`if len(page) < page_size: break`) — unsound,
because row-level ACL evaluation can silently drop a single row from an
otherwise-full pagination window without the server signaling anything
unusual, producing a short-but-not-final page indistinguishable from a
genuine last page. Page 3 returning a full 100 rows right after the
99-row page proved real data existed past where the old logic gave up.
Fixed by changing the stop condition to trigger only on a **fully
empty** page. Both fixes are kept — stable order prevents count drift
within a single request, the empty-page check prevents one ACL-filtered
row from truncating every page after it — and both are covered by
regression tests, including one reproducing the exact 100/99/100
sequence observed live.

**Resolved: the "invisible" custom agent was a direct casualty of Bug 2,
not a platform limitation.** Before finding Bug 2, `ClaudeAgentService`
— the custom Script Include this whole live-testing effort was built
around — was absent from every list-style query against
`sys_script_include`: the original buggy scan, the ordering-fixed
single-shot 1992-row scan, an explicit `sys_scope.scope=x_claude`
filter, and a fresh scan run 48 hours after the record was created
(with only Bug 1's fix shipped at that point). Three explanations were
tested live and each was disproven before the real cause was found:
scope-based exclusion (the record's `sys_scope` is `global`, same as
hundreds of visible records), `access=package_private` exclusion (many
private-access records list normally), and read-consistency lag (the
48-hour retest still missed it, with only the ordering fix in place).
A fourth signal — `sys_package` resolving to the literal string
`'global'` rather than a real package sys_id, unlike every comparison
record checked — looked like a real lead at the time and prompted
deeper investigation, but turned out to be coincidental, not causal:
every query that found the record (`name=`, `sys_created_by=admin^name=`,
`sys_package=global`) happened to return a small enough result set to
fit in one page, and every query that missed it needed multiple pages
and hit Bug 2 somewhere before reaching this record's position in
`sys_id` order. Once Bug 2 was fixed, a full unfiltered scan fetched
4854 `sys_script_include` rows (versus 199 before) and `ClaudeAgentService`
was among them — and the real, end-to-end scan (`--include-script-scan`)
correctly built it into an Agent at `needs_review` confidence with
`detection_signal: "shadow:script_keyword:script_include:anthropic"`,
correlated to a synthesized tool describing exactly what was found: "no
REST message record found for this call (Anthropic)." That's precisely
the detection shape tier 4's design docstring describes for an ad hoc
`RESTMessageV2` call with no formal REST message record — confirmed
correct, live, against a real custom build. The same fixed scan also
surfaced six other previously-buried shadow agents and a Scripted REST
API flagged as a possible inbound tool surface, all of which Bug 2 had
been silently hiding.

**Why this matters more than any other finding in this document:** this
was the direct test of the project's own central thesis — can this tool
find a hand-built agent regardless of naming or structure — using a
real custom application built independently by someone other than this
project's author, without foreknowledge of AgentCensus's detection
logic. Across three rounds of live testing, two real bugs found and
fixed, and one red-herring lead investigated and ruled out on its own
merits, the final, confirmed answer is yes: the fixed connector finds
it, correctly, with the right confidence level and the right
explanation of why it's uncertain. Getting there required not
believing the first fix was the whole story just because it was
plausible and evidence-backed — the ordering fix was both of those
things and still wasn't enough.

## Hardening pass: security, applicability, polish (2026-08)

A deliberate review round with three questions, in order: is this safe
for a real company to run on a production instance; what agent shapes
can it still not see; and is it usable by the person who has to act on
the output. Findings and what changed:

### The security hole that mattered

**Script source was being written verbatim into the report.** Tiers 3-4
read script bodies to detect anything at all, and every matched Script
Include, Business Rule, Scheduled Job, and Scripted REST API resource
had its full source stored in `raw` and serialized into the JSON —
system prompts included. Found by reading a real report generated from
a real instance, not by inspection of the code.

This is worse than an ordinary leak because of *which* scripts it
affects. The population this tool flags is, by construction, the
ungoverned integrations nobody reviewed — which makes them the likeliest
place on the whole instance to hold a hardcoded API key. A report
designed to be handed to auditors was therefore aimed precisely at the
highest-risk scripts it had just identified.

The existing `test_no_secret_fields.py` did not catch this and could
not have: it checks field NAMES against a forbidden-substring list, and
`script` contains no forbidden substring. A field-name allowlist is the
wrong instrument for a field whose contents are arbitrary. That's the
generalizable lesson — the guard was well-built and aimed one level
too shallow.

Fixed by dropping script bodies entirely (sha256 + length kept, which
is enough to diff scans and correlate duplicates), with
`--include-script-excerpts` as an informed opt-in for a short scrubbed
window. New `core/redaction.py` adds value-shape scrubbing on top of
the existing key-name layer, across all three connectors — a field
called `endpoint` is innocent, but `?api_key=` inside its value is not.
`tests/test_redaction.py` plants a real key-shaped literal in a scanned
script and asserts it never reaches the serialized report.

Also: reports are now written 0600 (an inventory of every ungoverned
integration and its blast radius, previously world-readable on any
shared jump host), `test_connection` stopped pulling a full PII user
row on every scan, and error strings are scrubbed before landing in
scan notes.

**Splunk had the same pagination bug ServiceNow did** — `if len(page) <
count: break`. Fixed here *before* being observed live, because the
ServiceNow case proved the reasoning ("a short page means the end") is
unsound in general rather than that one vendor pages badly. Splunk also
gained the safety cap and retry/backoff ServiceNow already had;
Anthropic gained retry too.

### Applicability: what it still couldn't see

**The engineering-quality inversion.** A well-built integration keeps its
endpoint in a system property or a Connection & Credential Alias rather
than hardcoded — at which point the script contains no provider hostname
and no provider keyword, so tiers 2 and 4 both see nothing. The better
the integration, the less visible it was. New `config_surfaces.py`
reads `sys_properties` and connection records, matching values against
the same host list tier 2 uses, so these are CONFIRMED-grade structural
signals in the default scan (no script access needed). Password-typed
properties are skipped without their values being read at all — a key
stored *correctly* is deliberately invisible.

**Domain separation.** ServiceNow filters every read by the scan
account's domain, silently, with no error. An MSP or multi-brand
enterprise scanning from a child domain gets a clean, complete-looking
report covering one tenant. Same failure class as the pagination bug —
quietly returns less than the truth — and it hits exactly the customers
most likely to buy this. `domain_scope.py` detects and reports it rather
than escalating privilege past it.

**Tier 4 was reading three tables; agents live in more than three.**
Added Service Portal widgets (where a chat UI actually lives), UI
Actions ("Summarize with AI" buttons), inbound email actions, fix
scripts, and processors. Most importantly, `sys_ws_operation` is now
read for *outbound* calls as well as inbound surfaces: tier 3 only ever
asked "does this expose something outward?", so a bridge endpoint
(receive request → call model → return answer) had its outbound half
go unreported. Confirmed against the real custom app used for live
testing, whose `/start` endpoint is exactly that shape.

Provider list gained DeepSeek, xAI, Groq, Together, Perplexity,
OpenRouter, Hugging Face, and self-hosted gateway keywords (Ollama,
vLLM, LiteLLM) — that last group matters most, since an enterprise
that has already thought about AI governance is running an internal
gateway with no public hostname anyone could ship a default for.

### Polish

`scan_notes` were being written to stdout and dropped from the report
file — every caveat about denied tables, skipped tiers, and cap
truncation existed only in the terminal of whoever ran the scan. For a
project whose credibility rests on disclosing what it can't see, that
was the wrong place to put it. Now in the JSON, and given top billing
in the new HTML report.

`--format html` renders a self-contained shareable report (JSON is a
machine format, not a deliverable for a governance lead). `preflight`
answers "what will this read, and can my account read it?" without
running a scan — the first question any enterprise security team asks,
previously answerable only by running a full scan against production.
`--fail-on <severity>` exits 2 for scheduled/CI use, distinct from exit
1 meaning the scan couldn't run at all. `--sensitive-role` now warns
that no rule consumes it instead of silently doing nothing.

## Independent review round (2026-08, v14)

The v13 hardening round was written and reviewed by the same model in the
same session. This round was an independent pass with a fresh context,
explicitly instructed to assume the previous one was wrong somewhere. It
was, in six places — and its own fixes were then wrong in two more, found
by re-reviewing them here. Both layers are recorded because the pattern
is the point.

### What the independent review found

Every defect had the project's signature shape: **a guard aimed one level
too shallow, passing its own test while the harm walks past.**

- **The final redaction pass ran after escaping, and escaping defeats it.**
  `_final_scrub` was applied to the output of `json.dumps` and
  `html.escape`, both of which rewrite the exact delimiters (`&`, `"`,
  `'`) the redaction patterns key on. Verified leaks: a credential as the
  *second* query parameter survived into HTML (`&` → `&amp;` broke
  `parse_qsl`); a *double-quoted* assignment survived into JSON; a
  *schemeless* path with a query string was never examined at all.
  The docstring claimed "there is no path around it, no field it doesn't
  cover." Format was the path around it. That claim is now deleted with a
  note not to restore it.
- **`sys_properties` is an entity-attribute-value table, so the key-name
  scrub is structurally blind to it.** A property named
  `x_acme.anthropic.api_key`, typed `string`, had its plaintext value
  written into the report — the semantic field name lives in the row's
  `name` *value*, never in a dict key. This is the same field-name-
  allowlist failure that let script bodies leak in v12, one table over.
- **`_is_secret_property` failed OPEN** on any type string outside a
  hand-written five-element list. Now fails closed against a positive
  allowlist.
- **Encrypted property values were requested over the wire** despite two
  comments claiming otherwise, then discarded client-side. Now excluded
  server-side by encoded query.
- **Splunk pagination skipped rows near the safety cap** — it requested
  `min(count, remaining)` but advanced `offset += count`. Only fires when
  the server also returns short pages, at which point rows vanish *and*
  the result finishes under the cap, so no truncation note is emitted:
  "incomplete, and I told you" becomes "complete."
- **`preflight` printed "one row probed per table" while reading up to
  5,000 rows per table**, and its hand-maintained table list had already
  drifted from what the scan reads — missing three tables added by the
  same round that wrote the list. Both sides now read one manifest.
- **The Anthropic connector never called `scrub`**, defended by a
  docstring arguing a mechanical test was unnecessary because the
  upstream API doesn't return secrets *today*.

### What re-reviewing those fixes found

- **The escape hatch didn't open.** The new vendor-scope and inactive
  filters exclude findings by default and emit a scan note saying to pass
  `include_vendor_scope=True` — but the parameter existed only on the
  tier-4 helper. Not on `fetch_shadow`, not threaded through the
  connector, no CLI flag. Findings were dropped by default with no
  reachable way to recover them, while the note claimed otherwise. Now
  wired end to end (`--include-vendor-scope`, `--include-inactive`) with
  a test asserting the whole chain.
- **Two very different skips were reported as one number.** "Skipped
  because encrypted" (the guard working) and "skipped because the type
  wasn't recognised" (a coverage gap where an endpoint may sit
  unexamined) were summed into a single reassuring note. Split, with the
  second labelled COVERAGE GAP.
- `core/report.py` was untouched by the review's own patch, so the
  primary D1 fix — scrub *before* escaping, at `_esc`, the single funnel
  every HTML field passes through — was missing. The hardened backstop
  patterns alone did close every verified case, but relying only on
  patterns that must survive escaping is the fragile half of the design.
  Both layers now present.

### Standing caveat on the noise filters

Vendor-scope exclusion is the one change here that *removes* findings by
default, and it rests on `sys_scope` semantics not yet confirmed against
a live instance. `global` scope holds both vendor and customer code and
is deliberately never excluded. The scan notes report exact drop counts
and the flag to re-include. If a live run shows the counts are large,
treat that as a reason to re-examine the filter, not to trust it.

## Round 3 independent review (v15)

Third independent pass, on code already reviewed twice. It found six
defects — and unlike round 2, several were in areas neither earlier
round had examined: the rules engine, the severity model, and
determinism.

**Two put credential material or false verdicts into the deliverable.**
`_ASSIGNED_SECRET_PATTERN` listed `bearer` among its names, which read
as covered — but it requires `[:=]` between name and value, so it never
matched `Bearer <tok>` or `setRequestHeader('x-api-key', '<tok>')`, the
only two forms anyone writes. It shipped under
`--include-script-excerpts`, whose documented contract is that excerpts
are scrubbed. Separately, the same pattern is structurally incapable of
matching `"api_key": "X"` after `json.dumps`, because the key's own
closing quote sits where the pattern requires its separator — so
`_final_scrub` was load-bearing only for the value-shape patterns,
materially less than its docstring claimed for the second time.

**The NEEDS_REVIEW cap didn't hold.** `score()` capped heuristic
findings at MEDIUM; `escalate_findings` then raised by up to two tiers
without ever reading `confidence`. A keyword match with ten dependent
agents rendered CRITICAL while the HTML footer told the reader,
verbatim, that needs_review findings are capped at MEDIUM. Both prior
test suites tested the cap and the escalation in isolation; nothing
tested the composition, which is the only thing the CLI runs. Fixed by
exporting `apply_confidence_cap` and routing both paths through it —
in the severity model, not at the call site, since a local clamp is
correct for two callers and wrong for the third.

**The determinism guarantee was false.** Two set-iteration
dependencies. Neither is visible from an in-process loop, because
CPython randomises str hashing per process — which is exactly why a
five-run check in round 2 passed. The material one: a Build Agent app
with multiple conversation creators was attributed to whichever the set
yielded first, so `orphaned.creator_inactive` fired on roughly one run
in three against byte-identical input. A governance lead re-running a
scan to check a finding could fail to reproduce it. The regression test
shells out under six `PYTHONHASHSEED` values; an in-process loop is not
an acceptable substitute.

**Signal-to-noise made the report unusable.** On 200 API-only accounts
(unremarkable for an enterprise — MID servers, spokes, monitoring, ITOM
discovery), the scan produced 416 findings, 405 of them HIGH, of which
11 concerned anything AI-related. Each ordinary account triggered two
HIGH findings from two rules, one of which described it with two
sentences that were both false of that population. Three changes:
de-duplicate, score `UnattributedIntegrationAccountRule` on the
`owner_resolved` signal it was already computing and discarding, and
score `CredentialNoOwnerRule` against severity.py's own documented
exposure scale instead of a hardcoded 3 (that scale reserves 3 for
compounding signals; "no owner" alone is a 2). Realistic instance after:
22 HIGH, both real agents still detected, no CRITICAL noise.

**Two unrelated identities could merge.** `integration_accounts.py` set
`correlation_key` from an email — the one thing `models.py` explicitly
forbids, since the key means "same credential" and a team mailbox
(`integrations@corp.com`) is shared by many. Two service accounts were
joined by `same_identity_as` edges, so one inherited the other's blast
radius and therefore its severity. No shipped connector populates the
key now, which is the honest state: cross-platform *credential*
correlation has no real signal yet. `Owner.email` correlation still
works, and is now normalised on both paths.

**`--include-inactive` reached one of five surfaces.** `active` is
requested by 16 field lists; only shadow.py's tier 4 consulted it, so
an inactive Flow, MCP registration, NASK mapping or connection alias
was reported as live and the flag could suppress none of them — while
its help text said, without qualification, "include records marked
inactive." Hoisted to one shared `is_inactive` helper and threaded
through every surface, verified in both directions (suppressed by
default, recoverable via the flag) because that end-to-end check is
precisely what the round-1 exclusion fix skipped.

Also: an inert credential scored like a live one (`_locked_out` was
read for ServiceNow while Splunk's `_disabled` and Anthropic's key
status were computed, stored, and read by nothing) — normalised onto
`Credential.is_disabled`, since teaching every rule three connectors'
private raw keys is the too-shallow shape again. And
`access.irreversible_no_approval_gate` used `not agent.has_approval_gate`,
which reads `None` ("undetermined") as "no gate"; the rule is currently
unreachable, which is exactly why it cost nothing to fix before it
becomes a false accusation at HIGH and CONFIRMED.

Three rules are now marked in README as not-yet-reachable: no shipped
connector populates `is_irreversible`, `has_audit_logging`, or
`has_defined_fallback`.

## Round 4 independent review (v16)

The first round explicitly told to weight accuracy, adaptability and
polish equally with security — and the first whose findings were mostly
NOT security. Security held: a canary planted in five places at once
with `--include-script-excerpts` on, plus XSS in three name fields,
leaked nothing and escaped everything. Every defect below is
over-correction, the direction this codebase has consistently been
worst at.

**One root cause behind four of them: a guard whose input is DERIVED
rather than DECLARED.**

- **The marker field could vanish.** Round 3's noise fix keyed off
  `"web_service_access_only" in cred.raw`. `raw` is the wire response,
  and this connector's own docstring records a field-level ACL silently
  dropping `locked_out` from a live instance while other fields on the
  same row returned fine. When that happens to the marker, two separate
  rule skips fail open at once: 60 ordinary accounts became 120 HIGH
  findings, and the "found via OAuth entity or REST message inspection"
  sentence — deleted in round 3 as false — came back verbatim. Fixed by
  adding `Credential.source`, declared by the producer.
- **A placeholder owner counted as an owner.** `fetch_owners`
  manufactures `Owner(id="unresolved:<user>", status=UNKNOWN)` so the
  graph has a node to attach to. The credential rules checked only
  `owner_id is not None`, so that placeholder read as ownership: an
  account whose creator is genuinely gone scored MEDIUM with evidence
  reading "owner resolved — a question for that owner." There is nobody
  to ask. `CreatorUnresolvedRule` on the agent side had always checked
  the status correctly, which is what made the inconsistency visible.
  Fixed with a shared `is_resolved_owner`.
- **Findings claimed more confidence than their subjects.**
  `Finding.confidence` defaults to CONFIRMED and only 4 of 12 rules
  passed the subject's value through. A keyword-matched shadow agent
  rendered as `high / confirmed` in the findings table while the same
  document's agent-inventory row said `needs_review` and its footer said
  needs_review is capped at MEDIUM — three contradictory statements
  about one record in one artifact, which is worse than any single one
  being wrong. Fixed in the rule ENGINE (a finding can never be more
  confident than its subject) rather than at ten call sites, because
  the call-site fix is correct until an eleventh rule is written.
- **`construction.missing_description` reported our own synthesis gap
  as the customer's defect.** Shadow agents have no description because
  a Script Include has no field meaning what that rule means. Every
  shadow agent got a finding whose recommended action nobody can take.
  Now scoped to NATIVE agents.

**And the report itself was still unreadable — found by generating it
and reading it, which no prior round had done.** Round 3 cut volume from
405 HIGH to 62 without touching ORDERING, so 62 byte-identical rows sat
above the two CONFIRMED `api.anthropic.com` / `api.openai.com` matches.
Severity sorting cannot fix that, because the ordinary rows genuinely
are higher severity; the problem is that they are the same row 62 times.
Identical findings are now collapsed into one row with every subject id
still listed behind a disclosure, and smaller groups sort first within a
severity band — a specific finding is actionable today, a population is
a project. Measured after: 64 findings render as 5 rows, with the real
LLM integrations first.

**Two over-redactions, both introduced by round 3's own fixes:**
`credential_id` and `token_url` were being redacted (the key-name
pattern matched on containment, not identity), so the only redaction in
an otherwise clean report was of two non-secrets — while the graph
section carried the same `credential_id` unredacted. And
`\b(?:bearer|basic)\s+` rewrote the prose "basic authentication" in this
project's own documentation. Both patterns tightened; a credential value
must now contain a digit, and a key must BE a secret name rather than
merely contain one.

**Cross-platform correlation is inert, and now says so.** No connector
populates `correlation_key` (the only one that did was inventing it from
an email), and `Owner.email` edges connect graph sinks, so they can
never widen a credential's blast radius. The machinery is correct and
tested with nothing to act on. That is a connector gap, not a
`correlate.py` bug, and both its docstring and README now state it
rather than leaving a reader to assume the feature is exercised.

**One judgment call reversed.** Round 3's de-duplication of
`CredentialNoOwnerRule` against `UnattributedIntegrationAccountRule`
went one step too far: it made that rule structurally unable to report
its single most important case, an API-only account nobody owns. The
de-dup now applies only where the two rules genuinely say the same
thing — no creator recorded at all — and not where a creator WAS
recorded and could not be resolved, which is positive evidence someone
built this and is now gone.

## First live scan (2026-08, v17) — what four code reviews could not find

Four independent review rounds preceded this, all reading code. The tool
was then pointed at a real ServiceNow instance and produced **seven more
defects in one afternoon**. Not one was findable by review, because
every one is a fact about the world rather than a fact about the code.

That is the generalizable lesson, and it will apply to the next platform
too: **a review checks a program against its author's model of reality.
Only contact with the real thing checks the model.**

### What the run CONFIRMED

Thirteen table names that were pure documentation guesses are real and
readable: `sys_connection`, `http_connection`, `sys_scope`, `sp_widget`,
`sys_ui_action`, `sysevent_in_email_action`, `sys_script_fix`,
`sys_processor`, `sys_properties`, `sys_rest_message_fn`,
`sys_hub_action_instance`, and both NASK tables. That was the stated
publication blocker and it is largely cleared.

Working on live data: the inactive filter (37 Flow records), the vendor
filter (3,046 script records), COVERAGE GAP reporting, script-body
suppression, and — new since v12 — `sys_ws_operation` outbound detection,
which found the `/start` bridge endpoint that earlier versions missed
entirely. `ClaudeAgentService` still detected.

Two things a PDI **cannot** settle, stated plainly: `sn_aia_agent` and
`sn_mcp_server_registry` are absent here, which is the expected result
for an unlicensed feature and an uninstalled app — and is
indistinguishable from outside from a table name this tool has wrong.

### The seven defects

1. **The test suite read the developer's own credentials.** Nine tests
   failed on a second machine because `ServiceNowClient()` falls back to
   `AGENTCENSUS_SN_*`; on a machine configured to USE the tool, the
   client took the OAuth path with real credentials and tried to exchange
   a token against a live instance the tests had only mocked GET for.
   Worse than flakiness: a test run reaching a customer's production
   ServiceNow because of ambient shell state. Fixed with a `conftest.py`
   clearing the whole namespace.
2. **Eight ordinary property types were refused as "unrecognised."** The
   fail-closed guard is right in principle, but a list built from
   imagination excluded `short_string`, `color`, `date_format`, `image`,
   `time_format`, `timezone`, `true` and `uploaded_image` on the first
   real instance it met. `short_string` routinely holds a URL — exactly
   what the tier exists to find.
3. **An unlicensed feature reported as ERROR.** ServiceNow answers an
   unknown table with 400 + "Invalid table", which contains neither "not
   found" nor "denied", so substring classification called it an error
   and the summary counted it as a failure. The two most common real
   outcomes rendered as "something is broken."
4. **Preflight verified tables and never fields.** It probed
   `sysparm_fields=sys_id`, so `OK` proved a table existed and said
   nothing about `connection_url`, `sp_widget.script` or
   `sys_properties.type` — each read with `.get()`, so a wrong name
   yields None and that surface silently finds nothing. The feature
   built to reassure a security team was structurally unable to check
   the thing that matters. Now probes with the real field list.
5. **The safety cap was spent on records the vendor filter discarded.**
   `sys_script` hit the 5,000-row cap while 3,046 records were separately
   excluded as vendor scope — the cap applies when FETCHING, the filter
   ran AFTER. On a large instance the cap could be exhausted entirely
   inside vendor code, returning ZERO customer findings behind a
   truncation note. Now filtered server-side, with a fallback so a
   rejected query costs the filter and never the table.
6. **The manifest had drifted again** — `domain` was missing while
   `domain_scope.py` read it on every scan. Same drift the manifest was
   introduced to prevent, one round later.
7. **Ten ServiceNow-shipped accounts dominated the report at HIGH** —
   `soap.guest`, `virtual.agent`, `securitycenter.user`,
   `mic.administrator`. Literally true, entirely useless: the customer
   neither created them nor can remove them. Now annotated and ranked
   below customer-built accounts, never suppressed.

### The precision question, and what it actually means

The script scan reported 5 agents, of which 2 were genuinely the user's.
Read carefully, that is **not** a 40% precision result: OOB noise is a
FIXED cost — the same shipped scripts and accounts appear on every
instance regardless of size — while customer agents scale with the org.
On this single-project PDI that is 2/(2+3); on an instance with twenty
real agents it is 20/23. The floor, not the typical case. What does NOT
improve with scale is defect 5, which gets strictly worse.

### `sys_package`, and the design principle this round settled

Confirmed live: three ServiceNow-shipped Script Includes in `global`
SCOPE all carried the same real `sys_package` sys_id, while a hand-built
custom agent in that same scope carried the literal `"global"`.
`sys_scope` and `sys_created_by` were identical across all four and are
therefore useless discriminators; `sys_package` separated them perfectly.
This is the same field ruled out as *causal* during the pagination hunt —
it turns out to be exactly right as a *classifier*.

It is used to **annotate and rank, never to exclude**, and that is now
the standing rule. The inverse doesn't hold — a customer's own scoped app
carries a real package too — and every over-correction defect across four
review rounds came from dropping records on a signal like this one.
Nothing has ever gone wrong from ranking.

## Second live scan (2026-08, v18-v23) — the report's own claims under test

The first live scan found defects in the code. This pass, run four times
against the same PDI, found them almost entirely in *what the report
says*. That is a harder class to see and a worse class to ship, because a
scan note is read as a finding: a customer does not audit the sentence,
they act on it.

Every defect below is one instance of a single failure. **The tool could
not distinguish ABSENCE from IGNORANCE, and resolved the ambiguity in the
reassuring direction.** A scanner's entire product is the difference
between "there is nothing there" and "I could not see."

### The discovery that reframed the rest

**A server-side filter on a field the account cannot read is silently
discarded.** ServiceNow drops the condition, returns HTTP 200, and hands
back the FULL UNFILTERED SET. No error, no warning, no way to tell from
the response.

Proven with a negative control on a table whose `endpoint` column was
under a field-level ACL:

```
unfiltered (all readable rows)                4
endpointISNOTEMPTY                            4
endpointLIKEapi.anthropic.com                 4
endpointLIKEzzz-no-such-host-9f3a.invalid     4   <-- impossible
```

The rule turns out to be narrow and predictable — **the filter applies if
and only if the field is readable** — which is why it can be guarded
rather than merely documented. Every filter that worked on this instance
named a readable field; the one that vanished named the ACL-blocked one.

Four filters in this connector are load-bearing, and all four now declare
`filter_fields` so the guard can verify them:

| Filter | Cost if silently dropped |
|---|---|
| `sys_db_object` `name=` | backs `table_exists` — EVERY table reports as existing, every honest "not detected" note inverts into a false positive, and modules go on to read tables that aren't there |
| `sys_user` `web_service_access_only=true` | all 639 users on the instance reported as unattended API-only identities |
| `sys_properties` `type!=<encrypted>` | encrypted property values cross the wire; the report stays correct (the client-side check fails closed) but "never transmitted" becomes "fetched and not printed" |
| `sys_script` `sys_scope.scope NOT LIKE` | mildest — costs row budget, not correctness |

All four measured as still filtering here, because those fields were
readable for this account. That is a fact about one account's ACLs, not
about the platform, which is exactly why it needed a guard.

### The feature this killed before it was written

Tier 2 is blind wherever `endpoint` is unreadable, and the proposed fix
was to push host matching server-side and never read the value at all.

That design would have reported **Firebase Cloud Messaging and Yahoo
Finance as CONFIRMED-grade LLM integrations** — the highest confidence in
the product — on precisely the instances where nobody could read
`endpoint` to check. A false positive unverifiable by the tool that
produced it.

It was proposed on the strength of an earlier inference from the same
instance: `endpointISNOTEMPTY` returned 3 rows, read as "filtering works
where reading doesn't." It returned 3 because 3 was every row it could
see. **The negative control is the only reason this wasn't built**, and
the lesson is cheaper stated than relearned: a positive result from a
query you cannot independently check is not evidence the query ran.

### The false claims, and what replaced them

1. **"MCP Server Console not detected... either the app isn't installed,
   the instance is below Zurich Patch 9, or the guessed table name is
   wrong."** Three branches offered, the reassuring one taken by any
   reader. On this instance the third was true: four real MCP governance
   tables (`mcp_auth_scopes`, `aig_scope_tool_mapping`,
   `aig_access_policy`, `aig_access_policy_scope_mapping`) were sitting
   there answering 403 — *denied*, meaning they exist. Now probes five
   tables; a denial is reported as affirmative proof the surface exists.

   Found sideways, and the method generalizes: two Business Rules
   (`validateMCPServerForMcpAuthScopes`, `validateMCPServerForAigPolicy`)
   surfaced as tier-4 hits, and their `collection` field named the tables
   they validate. **The satellites of a feature are findable when its
   registry is not, because something has to validate them.**

2. **"Native schema detected: Build Agent"** — printed for two EMPTY
   tables, on the strength of `table_exists` alone. The platform ships
   them to everyone. Detected and populated are different claims.

3. **NASK records labelled "(unnamed)"** when the `name` column was
   withheld by an ACL. That asserts a property of the data to describe a
   property of the credential. Now `<name unreadable: field-level ACL>`,
   with the genuinely-blank case still reading "(unnamed)". The second
   time this project answered a detection blindness with a cosmetic
   label; the first was caught in review, this one shipped.

4. **Dead constants contradicting prose.** `sn_build_agent_skill` and
   `sn_build_agent_skill_resource` were declared and read by nobody while
   native.py's docstring said Build Agent has no registry beyond
   conversations. Both tables are real. An unread table and an empty
   table produce an identical report, which is why nothing forced the
   issue.

### New surfaces

- **`gen_ai_service_secret`** — held a row on an instance where every
  other generative-AI table was empty. A credential can outlive the
  integration that used it, which is exactly when nobody is watching it.
  Metadata only; the field lists name no secret column and
  `test_no_secret_fields.py` scans them mechanically.
- **`sys_generative_ai_custom_header_api_key_credentials`** — same class.
- **Row cap 5,000 -> 10,000.** 5,085 non-vendor `sys_script` rows on a
  *PDI* meant ~85 customer-authored Business Rules were never examined on
  the smallest instance this will ever run against. Truncation is worse
  than it looks: rows come back ordered, so the same tail drops every
  run — a stable, confident, incomplete answer.

### The access section (v22-v23)

Nine separate blindness notes on one run, each naming a table, each
stating a consequence, ordered by whenever that table happened to be
read. All the information a customer needs and none of it actionable.

Gaps are now recorded as **data at the moment of refusal** — not
reconstructed by parsing scan_notes, which are prose this project
rewrites constantly and would silently empty the section on the first
reword. One closing section, plus `access_gaps` in the JSON so a pipeline
can gate on coverage.

Grants are **field-level** (`read on sys_rest_message.{endpoint}`, not
"widen access to sys_rest_message"). The product asks customers for least
privilege; its remediation advice has to respect that too.

The first live run of the section reported **8 grants where the same
scan's notes described 12** — omitting all four MCP tables, because
`mcp_server.py` discovers them by probing and only `safe_get_all`
recorded gaps. The section named every grant except the most valuable one
and looked complete doing it. A customer grants 8 permissions, believes
coverage is total, and MCP stays dark.

Third occurrence of one shape, now guarded mechanically: **a
cross-cutting record must be written at every point the condition occurs,
and "every point" is never the set the author had in mind.** Same failure
as the manifest drift and the twelve call sites that treated a warning
note as fatal.

### Why admin is not the answer

`admin` is not a bypass — it is a role that satisfies most ACLs. It still
fails: ACLs naming a different role (`admin_overrides=false`);
`security_admin`, which requires session elevation the REST API has no
step for; and **cross-scope application access**, where a scoped app
declares whether other scopes may read its tables at all. The `aig_*`
tables belong to ServiceNow's own AI Gateway app. No role fixes that one.

"Enough access" is therefore not a single grant, and for vendor-scoped
tables there may be no answer short of reading them in the UI by hand.
The access section reports the boundary rather than pretending a role
exists that dissolves it.

### Results across the four runs

| | v18 | v19 | v20 | v23 |
|---|---|---|---|---|
| Agents | 5 | 7 | 7 | 7 |
| Findings | 24 | 28 | 29 | 29 |
| Wall time | 2:57 | 2:32 | 1:56 | 1:57 |
| `sys_script` truncated | yes | yes | no | no |
| Access gaps listed | — | — | — | 12 |

The 5 -> 7 jump is the "warning note discards rows" fix: `sys_script` hit
the cap and every row was thrown away. Both recovered agents turned out
to be ServiceNow's own code, so the fix made the report more complete and
slightly noisier — worth recording, because "the bug was real and fixing
it did not improve the output" is a result too.

Raising the cap recovered ~85 rows and changed no agent count. It did
move the inactive-exclusion count 193 -> 194: the truncated tail was not
empty of relevant records, it just happened to hold an inactive one here.

## RETRACTION and the worst defect in the project (2026-08, v25)

The section above ("Second live scan") asserts a confident diagnosis that
was **wrong**, and the correction matters more than anything else in this
document.

### What it said

That seven field surfaces were blocked by field-level ACLs, that a
server-side filter is dropped when it names an ACL-denied field, and that
customers should request read access to those fields.

### What was actually true

**Six of the seven were wrong column names in AgentCensus.** Verified
against `sys_dictionary` on the same instance:

| Requested | Real column |
|---|---|
| `sys_rest_message.endpoint` | **`rest_endpoint`** |
| `sys_rest_message_fn.endpoint` | **`rest_endpoint`** |
| `sys_connection.connection_url` | **`host`** / `protocol` / `port` (the URL is on the `http_connection` child) |
| `sys_hub_action_instance.name` | **`action_type.name`** (dot-walk; the table has 5 columns) |
| `sys_hub_action_instance.active` | *does not exist at any name* |
| `sys_generative_ai_provider_mapping.name` | **`provider`** |
| `sys_generative_ai_model_config.name` | **`model_display_name`** |
| `sn_build_agent_skill_resource.name` | **`filename`** |

Only `gen_ai_service_secret.sys_created_by` was a genuine ACL.

### Why this is the worst one

**Tier 2 never worked. On any instance. For the entire life of the
project.** It is the only CONFIRMED-grade outbound detection — the thing
the tool exists to do — and it requested a column that has never existed.
Every "0 outbound LLM REST messages matched" it ever printed was that
typo. Same for action-step matching in Flow Designer, which compared
keywords against an absent column and could never hit.

### Why four reviews, two live runs and 190 tests missed it

1. ServiceNow omits a **nonexistent** requested field exactly as it omits
   a **denied** one: absent from the row, HTTP 200, no error.
2. The v17 field-blindness machinery — built specifically so this tool
   would stop mistaking "could not see" for "nothing there" — had exactly
   one explanation available, so it reported FIELD-LEVEL ACL for both. A
   bug in this repo's own `tables.py` was rendered to users as a
   permissions problem on their instance, with instructions to go ask
   their admin for access to columns that do not exist.
3. The test fixtures used the same wrong names. The suite agreed with the
   code; both disagreed with the platform.

**A diagnostic that can name only one cause will name that cause for
every symptom.** A crash would have been found in an hour. A fluent,
plausible, wrong explanation survived indefinitely and was believed —
including by its author, who built an entire access-remediation feature
on top of it.

### What changed

- All eight names corrected against `sys_dictionary`.
- `columns_of()` walks the `super_class` chain (inherited columns live on
  ancestor tables — without this, every inherited field would be flagged
  as a schema bug, and a diagnostic nobody believes is worse than none).
- `classify_missing_fields()` splits withheld fields into denied vs. not
  a real column, and the note says the opposite thing for each: *go ask
  for access* vs. *do not ask for anything, this is our bug*.
- `preflight` prints **SCHEMA MISMATCH** as its loudest output, not
  counted alongside denied/absent, because those describe the instance
  and this describes AgentCensus.
- Fails open: if `sys_dictionary` can't be read, neither cause is
  claimed. Guessing "your ACL" was the original bug; guessing "our bug"
  would be the same overconfidence mirrored.

### Two corrections to the previous section's other claims

- The dropped-filter rule is real but was **misattributed**. The honest
  statement: a condition on a field the query cannot resolve — denied
  *or* nonexistent — is silently dropped. The instance it was measured on
  had a wrong column name, not an ACL.
- `sys_hub_action_instance` has no `active` column, so the
  include-inactive filtering applied to action steps was filtering on
  nothing and the "N inactive records excluded" count for that surface
  was meaningless. Removed rather than fixed: there is no such concept at
  step level, and the claim could not be kept.

### What the corrected names bought

Not just repair. `sys_connection.host` is the hostname already parsed by
the platform, so the URL parser this tier was going to need was sitting
in its own column. And NASK's `connection` field references `sys_alias`,
giving a structural chain — model config → connection alias →
`sys_connection.host` — from "a generative-AI model is configured here"
to "and it calls this host", with no keyword matching anywhere in it.
`nask.py` previously documented that as impossible.

### The methodological lesson

Every prior round asked "is the code right?" This one asked **"is the
platform shaped the way the code assumes?"** — and answering it took one
query against `sys_dictionary`. That query should have existed in week
one, and now runs automatically in `preflight` for every field in the
manifest.

## Third live pass (2026-08, v25-v32) — schema, and the reader

Two distinct arcs. The first found that this project had been guessing at
ServiceNow's schema and only checking the guesses that failed loudly. The
second was the first time anyone looked at the rendered HTML.

### Eight wrong field names, and what they cost

Recorded in full in the RETRACTION section above. The headline: **tier 2
never worked on any instance for the life of the project**, because
`sys_rest_message.endpoint` should have been `rest_endpoint`. Also
`sys_connection.connection_url` (real, but only on the `http_connection`
child), `sys_hub_action_instance.name`/`.active` (a five-column table
with neither), both NASK `name` fields, and
`sn_build_agent_skill_resource.name`.

**The first fix for the flow-step name did not work either.** Replacing
`name` with a dot-walked `action_type.name` looked correct, passed its
tests, and shipped — and the Table API silently does not honour dot-walks
in `sysparm_fields`. The response came back with `action_type` as a bare
sys_id and no dotted key at all. Two silent failures on the same tier, in
consecutive releases, is the argument for the boring approach: a second
read of `sys_hub_action_type_base` and a client-side join. **There are now
no dot-walks anywhere in this connector.**

That third failure also defeats the sys_dictionary check built for the
first two: the base field is real, the dictionary confirms it, and the
request still returns nothing. Three causes, one symptom.

### What the corrected names revealed

| Surface | Before | After |
|---|---|---|
| Tier 2 | "0 matched" on every instance, ever | executes; correctly matched 0 on an instance with no LLM REST messages, and did **not** false-positive Firebase or Yahoo Finance |
| NASK | three records rendered "(unnamed)" | **VA Azure OpenAI, gpt-4o, an Amazon Bedrock handler** — i.e. which model providers the instance actually calls |
| `sys_connection` | requesting a column that isn't there | `host` — the hostname already parsed by the platform, so the URL parser this tier was going to need never had to be written |
| MCP registry | `sn_mcp_server_registry`, a name that exists nowhere | **`auth_server_connection`**, found by searching sys_db_object LABELS rather than names |

The MCP find is worth the method note: **ServiceNow names tables after
the mechanism and labels them after the concept.** Two searches for
tables named like "mcp" could never have found it; the search that worked
looked at labels, surfaced "MCP Tool Scan Results", and its parent was
the registry.

### The satellites, and a schema source that isn't the API

`auth_server_connection_tool_scan_result` is the richest AI-governance
surface on the platform: tool name, **threat category**, **safety score**,
scan status, input schema. ServiceNow is already scoring the tools an MCP
server exposes. A scan that can read it reports the vendor's assessment
rather than a keyword guess.

Its columns are 403 to the API and were transcribed **from the UI list
view by a person**. Recorded as a legitimate method: for tables the API
refuses, the screen is the only schema source available, and it is the
one that produced the most valuable field list in the connector.

### ServiceNow's own AI stack was invisible

A plain PDI with no third-party LLM spoke still ships `OneExtend
Invocation`, `One API - Feature Completion`, `GlobalToolExecutor`,
`Semantic Search`. **A flow calling `OneExtend Invocation` is invoking an
LLM**, and the provider list — which knows only third-party hostnames —
had never heard of any of them. Four flows on the test instance were
using them and no scan had ever said so.

Reported as an informational note, deliberately **not** as agents or
tools: findings are generated from inventory objects, so anything added
there reaches the severity table through some rule. These ship with the
platform and appear throughout OOB content; promoting them would bury
customer-built integrations under ServiceNow's own code — the "ten
shipped service accounts at HIGH" failure, a third time.

### `!=` does not match NULL

`sys_properties` held 3,673 rows; the secret-exclusion query returned
3,657. The 16 missing were 12 genuinely encrypted (correct) and **4 with
an empty `type`**, dropped at the database.

Those four mattered out of proportion to their number. config_surfaces
fails closed on an unrecognised type *and* emits a COVERAGE GAP note
naming it, precisely so a property it declines to read is still reported.
The rows never arrived, so the note could not fire — **a guard and its
own alarm, both bypassed by a NULL.** Since empty is an allowed type,
the fix means those four are now examined for the first time.

Generalizes to every `!=` and `NOT LIKE` here. `sys_scope.scopeNOT
LIKE...` has the same property; left alone because a script always
carries a scope, but noted rather than rediscovered.

### A note that could never fire

The reassurance that credential material is deliberately untouched was
gated on a counter that is **structurally always zero** — encrypted
properties are excluded server-side and never reach the code that counts
them. It had never appeared in any report. Now stated unconditionally,
and it claims no number, because the exclusion happens at the database
and the code genuinely does not know how many there were.

### The reader (v29-v32)

The first time the HTML was opened by someone who hadn't written it. Every
judgement about layout up to that point had been made from source code.

**The verdict, and the reversal it caused.** Twelve access-requirement
rows and nineteen coverage notes ran BEFORE any finding. Every line was
accurate. The effect was that the tool looked like it hadn't worked —
trust dropped before the results were reached. The original rule (notes
first, because a partial scan that looks complete is the most dangerous
output) is sound; the execution inverted it. Now: a one-line coverage
banner above the findings, full detail at the bottom. **Accuracy that
costs you the reader before they reach the results is not a good trade.**

Also from that reading:

- **Owners rendered as sys_ids.** Every agent showed
  `6816f79c...` while the resolved Owner record with a real name sat in
  the same inventory. The most consequential column in the report,
  answered with 32 hex characters. *The first fix was also wrong* — it
  read `.name`, and the field is `display_name`, so `getattr` silently
  returned empty. Caught only because the test asserted the name APPEARS
  rather than that the sys_id doesn't; a negative assertion alone would
  have passed against a completely broken implementation.
- **Grouped rows with no title.** Two of five finding groups rendered as
  "11×" and "7×" followed by nothing, because the group label is the
  shared title prefix and a title opening with a quoted subject name has
  an empty prefix.
- **No "where to find it".** The report named an ungoverned agent and left
  the reader to locate it. Now every agent and finding carries a
  paste-able `sys_script_include.do?sys_id=...`.
- **The access section named tables and stopped**, which is unusable for
  the likely reader of a governance report. It now carries the steps,
  including the two non-obvious ones: field ACLs are separate records
  from table ACLs, and editing ACLs requires elevated `security_admin`.
- **A self-contradiction shipped for one release.** Finding the real MCP
  registry name made the report say both "the registry table exists" and
  "the registry was not found under that name", in the same run. A fix
  that improves detection while degrading what the report says is not a
  net improvement.
- **A count that disagreed with its own list**: "2 configuration(s) found
  — VA Azure OpenAI, gpt-4o" while three existed. Counting one sequence
  and naming a filtered subset is two sources of truth for one sentence.

### Standing lessons from this pass

1. **A diagnostic that can name only one cause will name that cause for
   every symptom.** The field-blindness machinery turned a typo in this
   repo into a fluent accusation against the customer's ACLs.
2. **Existence is not correctness.** Every field name passed a "does the
   table exist" check for months.
3. **The UI is a legitimate schema source** where the API refuses.
4. **Assert the positive.** "The right value appears" catches what "the
   wrong value doesn't" cannot.
5. **Report ordering is part of correctness.** A true statement in the
   wrong position costs the reader.
