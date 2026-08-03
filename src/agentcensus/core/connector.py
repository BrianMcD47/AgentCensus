"""Abstract connector interface.

READ-ONLY IS ENFORCED HERE, ARCHITECTURALLY, NOT BY CONVENTION.

This base class exposes only `fetch_*` methods. There is no `create`,
`update`, `delete`, or `write` method on this interface, and there must
never be one added — a connector that needs to mutate the platform it
scans is not a connector this project accepts. If your HTTP client
wrapper only ever issues GET requests (see `connectors/servicenow/connector.py`
for the reference implementation), a coding mistake that tries to write
fails at the transport layer too, not just at the interface layer.

Every connector for every platform (ServiceNow, Splunk, Anthropic,
Microsoft 365/Copilot Studio, ...) implements this same interface and
returns the same platform-agnostic models from `core.models`. The core,
the rule engine, the severity model, and the report generator never
import anything platform-specific — that's what "pluggable" means here.
Note that "platform" is used loosely: Anthropic isn't a platform being
scanned for agents in the way ServiceNow or Splunk are, it's the model
provider's own management surface — see its connector's module
docstring for what that distinction means for what it returns.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from agentcensus.core.models import Inventory


class Connector(ABC):
    """Implement this for a new platform. Do not add mutating methods."""

    #: short, stable identifier used in CLI args and report output
    platform_id: str = "unset"

    @abstractmethod
    def fetch_inventory(self, **options) -> Inventory:
        """Pull agents, tools, credentials, and owners from the platform
        and return them as a single normalized Inventory.

        `**options` is for connector-specific scan options that don't
        belong in the generic interface — e.g. ServiceNow's
        `include_script_scan` for the higher-privilege detection tiers.
        A connector that doesn't need any should simply ignore extras
        rather than erroring on them, so the CLI can pass a common set
        of flags without knowing which connector is active.

        Implementations should:
        - use the least-privileged, read-only credential the platform
          supports (document the exact scope/role in the connector's
          README or docstring), and treat any *broader* grant as an
          opt-in scan option, not a default requirement
        - degrade gracefully on a per-table/per-resource basis when
          access is denied or a call fails, recording what happened
          in the returned Inventory's `scan_notes` rather than raising
          and losing the rest of the scan — real instances have
          inconsistent ACLs across the resources a connector reads
        - handle pagination themselves
        - leave fields None/unknown rather than guessing when the
          platform doesn't expose the data cleanly, so downstream rules
          can treat "unknown" as its own signal instead of a false negative
        """
        raise NotImplementedError

    @abstractmethod
    def test_connection(self) -> bool:
        """Cheap read-only call to verify credentials/reachability before
        a full scan. Should not raise for auth failures — return False."""
        raise NotImplementedError
