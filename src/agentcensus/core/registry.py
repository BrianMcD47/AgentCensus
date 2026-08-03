"""Connector registry.

Explicit registration, not magic discovery — keeps it obvious which
connectors exist and makes it easy to see when one is a stub.
"""

from __future__ import annotations

import os

from agentcensus.core.connector import Connector

_REGISTRY: dict[str, type[Connector]] = {}


def register(platform_id: str, connector_cls: type[Connector]) -> None:
    _REGISTRY[platform_id] = connector_cls


def get(platform_id: str) -> type[Connector]:
    try:
        return _REGISTRY[platform_id]
    except KeyError:
        available = ", ".join(sorted(_REGISTRY)) or "(none registered)"
        raise ValueError(
            f"No connector registered for '{platform_id}'. Available: {available}"
        ) from None


def available() -> list[str]:
    return sorted(_REGISTRY)


def _register_builtins() -> None:
    # Imported lazily so a missing optional dependency for one connector
    # (e.g. a future platform SDK) can't break `import agentcensus` for
    # everyone else.
    #
    # ServiceNow, Splunk, and Anthropic are real, working connectors —
    # importing them cannot raise NotImplementedError, so they're
    # registered directly. Microsoft 365/Copilot Studio is still a
    # genuine stub (see its module docstring) whose module body raises
    # NotImplementedError at import time on purpose; the try/except below
    # exists for that one case only. Don't wrap a real connector in it —
    # a connector that's actually implemented and still silently fails to
    # register would look identical to "not built yet" in `agentcensus
    # connectors`' output, which defeats the point of that command.
    from agentcensus.connectors.servicenow.connector import ServiceNowConnector
    register(ServiceNowConnector.platform_id, ServiceNowConnector)

    # Splunk and Anthropic are NOT registered in v1.
    #
    # Both are implemented and both are unrun. Neither has any of what
    # thirty releases taught the ServiceNow connector: no access-gap
    # recording, no schema validation, no field-blindness machinery, no
    # `preflight` support, no probe, and no live execution of any kind.
    #
    # An independent review showed the report actively misreported them:
    # because
    # only ServiceNow produces `AccessGap` records, a Splunk scan in which
    # every endpoint returned 403 rendered "Full coverage — every table and
    # field this scan needs was readable." The coverage banner cannot tell
    # "nothing was refused" from "this connector has no way to report a
    # refusal", which is the exact distinction this product exists to make.
    #
    # Registering them made them look like peers of a connector they are
    # not peers of. Set AGENTCENSUS_EXPERIMENTAL_CONNECTORS=1 to load them
    # anyway — the code is kept, and it is the starting point for v0.2 —
    # but the default surface is the one connector whose claims have been
    # tested.
    if os.environ.get("AGENTCENSUS_EXPERIMENTAL_CONNECTORS"):
        from agentcensus.connectors.splunk.connector import SplunkConnector
        register(SplunkConnector.platform_id, SplunkConnector)

        from agentcensus.connectors.anthropic.connector import AnthropicConnector
        register(AnthropicConnector.platform_id, AnthropicConnector)

    try:
        from agentcensus.connectors.microsoft365.connector import Microsoft365Connector
        register(Microsoft365Connector.platform_id, Microsoft365Connector)
    except NotImplementedError:
        pass


_register_builtins()
