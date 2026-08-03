"""Test isolation.

Found by running the suite on a second machine — one that was actually
configured to USE the tool. Nine tests failed there and passed here,
because `ServiceNowClient()` falls back to `AGENTCENSUS_SN_*`
environment variables when no credentials are passed. On a developer's
machine those are set, so the client silently picked up REAL OAuth
credentials instead of the test fixtures, took the OAuth code path, and
tried to exchange a token against a live instance that the tests had
only mocked `requests.get` for.

Two things wrong with that, the second much worse than the first:

  1. Anyone who installs this tool, configures it, and then runs the
     tests sees 9 failures on a healthy tree. That is the first-run
     experience for every real user, and it destroys confidence in a
     suite whose entire job is to be believable.
  2. A test suite that reaches a customer's production ServiceNow
     because of ambient shell state is not acceptable at any severity.
     Tests must never depend on — or touch — the outside world.

Clearing the whole `AGENTCENSUS_` namespace rather than the three
variables that happened to break: the next connector will add its own,
and this should already cover it.
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _isolate_agentcensus_environment(monkeypatch):
    for key in [k for k in os.environ if k.startswith("AGENTCENSUS_")]:
        monkeypatch.delenv(key, raising=False)
