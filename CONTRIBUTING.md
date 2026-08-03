# Contributing to AgentCensus

Thanks for considering a contribution. A few ground rules keep this
maintainable and keep the trust story intact.

## Developer Certificate of Origin (DCO)

This project uses a DCO instead of a CLA. You retain copyright on your
contributions; you're just certifying that you have the right to submit
the code under this project's license (Apache-2.0).

Sign off every commit:

```
git commit -s -m "your commit message"
```

That adds a `Signed-off-by: Your Name <you@example.com>` trailer. PRs with
unsigned commits will be asked to amend before merge.

## Read-only is a hard constraint, not a style preference

Any connector or core code you contribute must not implement a write,
update, or delete path against a scanned platform. This is enforced by
the `Connector` base class only exposing `fetch_*` methods — do not add
mutating methods to it, and do not add them to a connector subclass either.
PRs that introduce write capability will be rejected regardless of the
use case behind them. See section 7 of the project plan for the reasoning.

## Deterministic detection

Detection rules (`src/agentcensus/rules/`) must be rule-based and
reproducible — same input, same output, every run. If you want to use an
LLM for anything, it's limited to summarization/explanation of findings
already produced by deterministic rules, never to producing the findings
themselves.

## Setting up a dev environment

```
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Adding a connector

Implement `agentcensus.core.connector.Connector` and register it in
`agentcensus.core.registry` (`_register_builtins`). Three working
references exist now, each a genuinely different shape worth looking at
before starting a fourth:

- `connectors/servicenow/connector.py` — a platform with a real native
  agent registry (sometimes) plus several "shadow" detection layers for
  everything that isn't in it. The deepest connector, good reference for
  the fault-isolation (`safe_get_all`/`table_exists`) and
  provenance/confidence conventions everything else follows.
- `connectors/splunk/connector.py` — a platform with no native agent
  concept at all; every Agent this connector produces is inferred.
  Notice `_scrub_secrets` here — Splunk's config-read endpoints have no
  field-projection option, so this connector redacts secret-shaped
  fields at write time instead of relying on a field allowlist the way
  ServiceNow does. If your new connector's API has the same "returns the
  whole blob, no field selection" shape, copy this pattern, not
  ServiceNow's.
- `connectors/anthropic/connector.py` — not a platform being scanned for
  agents at all, but the provider side: an org/workspace/credential
  management API with no agent registry of its own. Notice it
  deliberately synthesizes zero `Agent` objects — see its module
  docstring for why inventing one would misrepresent what's known.

`connectors/microsoft365/connector.py` is still the genuine
not-yet-implemented stub — its module body raises `NotImplementedError`
at import time on purpose, and `core/registry.py` catches exactly that
to skip registration cleanly. That pattern is for connectors that don't
exist yet, not a style choice to reuse for a connector that does.

See `COVERAGE.md` for the full scenario-coverage matrix these three
connectors currently produce together, and its stated hard boundary on
what no connector can ever see.

## Handling credentials and secrets

Read metadata about a credential — never the credential's own secret
value. If the platform you're integrating exposes secret material
through the same read used to get everything else (Splunk's HEC token
endpoint is the concrete example, see `_scrub_secrets` in
`connectors/splunk/connector.py`), redact it explicitly before it ever
reaches a `raw` field, evidence dict, or anything that gets written to
the report. `tests/test_no_secret_fields.py` enforces this mechanically
for every connector that has a way to enforce it — read that file's
docstring before adding a connector with a new secret-handling shape.

## Reading from a platform: two invariants

Both were learned from live instances after four code reviews missed
them, and both fail silently, which is why they're stated as rules
rather than left to judgement.

**1. Declare the fields your server-side filter depends on.**

ServiceNow silently discards a query condition naming a field the
account cannot read — HTTP 200, full unfiltered result set, no warning.
So a filtered read must say what it filters on:

```python
client.safe_get_all(
    table, fields,
    query="web_service_access_only=true",
    filter_fields=["web_service_access_only"],   # <- required
)
```

The field is then requested (so its readability is observable) and a
dropped filter is reported instead of trusted. Without this, a tier can
report every row in a table as a match.
`tests/test_dropped_query_filters.py` greps for unguarded call sites.

**2. Record every refused read, at every point it can happen.**

Refusals feed the report's access section, which tells a customer
exactly what to grant. If a code path concludes "denied" without calling
`_record_gap`, the section under-reports and looks complete doing it —
which is worse than not having it, because the customer stops looking.

This has now gone wrong three times in the same shape: a cross-cutting
record written at the points that came to mind rather than at every
point the condition occurs. When you add a new denial path, add the
record in the same commit. `tests/test_access_gaps.py` fails if a
denial path in the client has no `_record_gap` near it.

If a new surface can go blind in a way that costs detection, add it to
`IMPACT_BY_SURFACE` in `connectors/servicenow/tables.py` — but only once
you've *measured* what goes dark. An unmapped gap is still listed with
its grant; an invented impact is the failure mode this project has spent
several rounds removing.

## Adding a detection rule

Implement `agentcensus.core.rules.Rule` and add it to the relevant module
under `src/agentcensus/rules/` (grouped by finding class: orphaned,
access, construction, redundancy, ungoverned). Every rule needs a
severity rationale — see `core/severity.py`.
