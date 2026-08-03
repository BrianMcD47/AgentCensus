> **Historical document.** This is the original scoping brief, kept
> unedited as a record of what was decided before any code existed.
> It is not current documentation and parts of it are now wrong. For
> what the tool actually does, see [README.md](./README.md); for what
> has been verified against live instances, see
> [COVERAGE.md](./COVERAGE.md).

# Agent Sprawl Scanner: Project Plan

**Owner:** Alex McDonald
**Status:** Pre-build, scoping (original scoping brief — kept as-is below for the historical record of what was decided and why; it predates build)
**Purpose of this doc:** Brief for a working session. Decisions already made are marked as such. Open questions are listed at the end and are what the session should resolve.

> **Status update, post-build:** everything in section 11's Phase 1
> shipped and was then exceeded. Section 5's "Microsoft 365 and Copilot
> Studio is connector two" did not happen in that order — Splunk shipped
> as connector two instead (buildable without learning Graph/Power
> Platform admin APIs first, same rationale this section already gives
> for ServiceNow going first), and a fourth connector was added that
> this plan didn't anticipate at all: Anthropic's own Admin API, for
> visibility into agents/credentials that live on the model provider's
> side rather than on a scanned platform. Microsoft 365/Copilot Studio
> remains the one connector from this plan not yet built. A
> cross-platform correlation layer (`core/correlate.py`) was also added,
> outside this plan's original scope, so a single scan can merge
> multiple connectors' output and recognize the same agent/credential
> across platforms. **For current, accurate status — what's built, what
> confidence level, what's verified against a live instance versus not —
> see README.md and COVERAGE.md, not the sections below.** They're the
> plan as originally written, not a changelog; nothing below this notice
> was edited to match reality after the fact.

---

## 1. The problem

Agent creation became trivially easy in early 2026. Non-technical employees can build autonomous workflows in minutes, with no approval step and no owner of record. The result is accumulation rather than a single event.

Documented conditions as of mid-2026:

- Average enterprise runs 12 or more AI agents, projected to reach 20 within two years
- Roughly half operate in isolated silos with no shared context or governance
- 27% of APIs connecting these agents are ungoverned, with no audit trail or access controls
- Only 54% of organizations have centralized governance for agentic capabilities
- 86% of organizations have delayed agent rollouts, averaging six months
- Gartner projects over 40% of agentic AI projects will be canceled by end of 2027, largely over inadequate risk controls

The recurring failure pattern: someone builds an agent, changes teams, then leaves the company. The agent keeps running with production credentials and nobody remembers it exists. Permissions outlive the people who created them, and no decommissioning step exists in any standard offboarding process.

## 2. The gap

Every vendor in this space sells a governance platform you adopt going forward. That market is crowded and funded.

Nobody is selling the step that has to happen first: finding out what already exists. Organizations cannot govern an inventory they do not have.

## 3. What this is

An open source, read-only scanner that a customer runs themselves, inside their own environment, against their own platform. It produces an inventory of every agent, tool, and credential, maps the dependencies between them, and flags risk.

No data leaves the customer environment. No access is granted to a third party. The customer authenticates with their own credentials and the output is written locally.

## 4. Why open source and self-run

**Decision made.** This is not a preference, it removes the single most likely thing to kill the project.

A hosted or delivered-as-a-service version requires the customer to grant admin-level read access to an unknown vendor. In practice that means an MSA, errors and omissions insurance, a security review, and in many cases SOC 2 before the conversation can even start. That wall is not about product quality and it cannot be engineered around from a standing start with no capital.

Self-run removes it entirely. Open source removes the remaining trust question, because the customer can read exactly what the tool does before running it.

Precedent: Prowler, ScoutSuite, and comparable security scanners are adopted this way routinely, with no vendor relationship required.

Secondary benefit, and the reason to ship publicly early: publishing a working tool in this space converts an unknown individual into the person who built the agent sprawl scanner. That is a credential that cannot be purchased and it accrues within weeks.

## 5. Scope for v1

**Decision made: ServiceNow connector first.**

Rationale, despite Microsoft 365 and Copilot Studio having the larger sprawl surface:

- Buildable correctly and quickly with existing platform depth, rather than learning Graph and Power Platform admin APIs mid-build
- Differentiated, since the general MCP and agent security vendors will not specialize down into ServiceNow
- Real distribution exists into the ServiceNow community, versus competing for attention as an unknown in the Microsoft ecosystem
- Directly reinforces the professional positioning already in progress

**Architecture requirement:** the scanner core must be platform-agnostic with a pluggable connector interface. ServiceNow is connector one. Microsoft 365 and Copilot Studio is connector two. Do not hardcode ServiceNow assumptions into the core.

## 6. What it detects

Grouped by finding class. Each finding needs a severity, an explanation of why it matters, and a recommended action.

**Orphaned and abandoned**
- Agents whose creator is no longer active in the system
- Agents whose creator has changed roles or departments
- Agents with no activity in a configurable window
- Credentials and integration users with no associated active owner

**Access and permission risk**
- Agents holding write access to sensitive tables or records
- Agents with permissions exceeding what their tool surface actually requires
- Agents operating under shared or human user accounts rather than scoped service accounts
- Agents with no audit logging configured
- Agents capable of irreversible actions with no human approval gate

**Construction quality**
- Agents with unbounded or undefined tool scope
- Tools with untyped or unvalidated input schemas
- Agents with no defined failure or fallback behavior
- Missing or empty descriptions, which affect both governance and model routing behavior

**Redundancy and waste**
- Duplicate or near-duplicate agents across teams
- Overlapping tools performing the same function
- Agents consuming resources with no recorded successful outcomes

**Dependency mapping (the differentiating capability)**

Everyone else produces a list. This produces a graph.

Map the relationships between agents, the tools they call, the credentials those tools use, and the human owners attached to each. This makes findings actionable rather than informational. A single orphaned credential surfaces every agent downstream of it. A deprecated tool surfaces every agent that will break when it is removed.

This is the piece to get right. It is the reason someone chooses this over a spreadsheet.

## 7. Hard constraints

**Read-only, enforced in code.** The tool must be architecturally incapable of writing, updating, or deleting. Not a convention, not a config flag. This is a one-line trust argument in the README and it should be true.

**No egress.** No telemetry, no phone-home, no analytics. Scan runs locally, output written locally. State this prominently.

**Least privilege.** Document the minimum permission set required to run, and make it work with that set. Do not require admin where read is sufficient.

**Deterministic core.** Detection logic should be rule-based and reproducible. If an LLM is used, confine it to summarization and explanation of findings, never to the detection itself. A security tool that returns different results on different runs is not usable.

## 8. Output

- Machine-readable inventory: JSON, for anyone who wants to pipe it elsewhere
- Human-readable report: HTML or Markdown, ranked by severity, with the dependency graph rendered
- Executive summary: a short section a non-technical stakeholder can read and understand the exposure from

The report is the artifact that sells follow-on work. It should be good enough that someone forwards it to their director without editing it.

## 9. Positioning and README

The README does most of the selling. It needs to cover:

- What it does, in one sentence
- The read-only and no-egress guarantees, stated up front
- Exact permissions required
- How to run it in under five minutes
- A sample report, redacted
- What it does not do, stated honestly

## 10. Licensing and repository setup

**Decision made: Apache 2.0.**

Rationale. There are no customers and no revenue to defend, so a competitor absorbing the work is a success problem while low adoption is the immediate and likely failure mode. The detection rules are not a moat regardless, since anyone with platform depth could rewrite them in a couple of weeks. Optimizing the license against the distant risk at the cost of the near one is the wrong trade.

AGPL was considered and rejected. It only triggers on distribution or offering the software as a network service, so an enterprise running it internally would have no obligations in theory. In practice many corporate open source policies carry blanket AGPL bans that never get parsed that carefully. The entire adoption thesis is that an engineer can run this without asking permission, and a license that routes them through legal defeats the design.

Apache 2.0 over MIT for three specific reasons:

- Explicit patent grant, protecting both the project and anyone running it. MIT is silent on patents.
- Requires attribution and notice of modification, so forks carry the origin forward. This serves the credibility goal directly.
- Enterprises are already comfortable with it for infrastructure tooling, which lowers adoption friction.

**What Apache 2.0 does not grant: trademark rights.** The name stays owned. Code can be forked, but not shipped under the project name. Being known as the tool is what compounds, so the name is the thing worth defending, not the source.

**Cost and process.** Zero dollars, under ten minutes. Open source licenses are not granted or registered by anyone. Copy the Apache 2.0 text into a LICENSE file at the repository root. GitHub offers this during repository creation.

**Do not publish without a license.** Unlicensed code is all rights reserved by default under copyright, not public domain. Anyone cloning, running, or modifying it would technically be infringing, and enterprise legal teams treat unlicensed repositories exactly that way. An unlicensed repository looks open source while being legally unusable, which inverts the entire strategy.

**Use a DCO, not a CLA.** Accepting outside contributions without a contributor agreement means those contributors retain copyright on their work, permanently removing the ability to relicense or dual-license later. That would close off the phase 5 commercial layer before it has been decided on. A Developer Certificate of Origin is one line in CONTRIBUTING.md plus contributors adding `-s` to commits. Near-zero friction, preserves optionality, and cannot be added retroactively once contributions land.

**Trademark.** Common law rights accrue from public use, which is sufficient for now. Federal registration through the USPTO runs a few hundred dollars per class and is only worth considering if the project gets real traction.

**Treat this as a one-time decision.** Starting permissive and tightening later is legally possible while sole copyright is retained, but expensive in goodwill. HashiCorp, Elastic, and Redis all made that move and all took real community damage.

**Before the first commit:** LICENSE file with Apache 2.0 text, DCO note in CONTRIBUTING.md.

## 11. Sequence

**Phase 1: Core and connector**
Scanner core with pluggable connector interface. ServiceNow connector. Detection rules for the finding classes above. JSON output.

**Phase 2: Dependency graph and reporting**
Relationship mapping. Severity model. Human-readable report. Executive summary.

**Phase 3: Publish**
Public repository, README, sample report. Announce into the ServiceNow community and adjacent AI governance channels.

**Phase 4: Aggregate research**
Run against whatever environments become available, including a personal developer instance. Publish anonymized aggregate findings. The report markets the tool, the tool feeds the report.

**Phase 5 (deferred, not committed)**
Commercial layer, if adoption warrants it. Candidates include a hosted dashboard, historical tracking and drift detection, remediation playbooks, or a commercial license for partners running it across multiple client environments. Do not build this until the free tool has users.

## 12. What this is not

Not a governance platform. Not a remediation tool. Not a monitoring service. Scope discipline here is what makes it shippable.

The second product is deliberately undecided. Ten scans will indicate what the most common and most severe finding class actually is, and that determines what gets built next. Committing now means guessing.

## 13. Open questions for the session

1. **Language.** Python has the stronger security tooling ecosystem and is what practitioners expect from a scanner. JavaScript is faster to write given existing fluency. Consider which audience matters more.

2. **Distribution format.** CLI only, or CLI plus a local web report viewer. The second is better output, more build.

3. **Naming.** Needs to be searchable, not cute, and not imply a vendor relationship. Also needs to be defensible as a trademark, so avoid purely descriptive terms.

4. **ServiceNow scope specifics.** Which tables and APIs actually expose agent, tool, and credential inventory in current releases. This requires verification against a live instance rather than assumption.

5. **Severity model.** What makes a finding critical versus informational, and whether severity is fixed or configurable per environment.

6. **Realistic build estimate** for phases 1 and 2, given the above decisions.
