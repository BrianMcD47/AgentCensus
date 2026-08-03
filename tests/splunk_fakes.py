"""Fake Splunk REST API client — no network, mirrors the subset of
SplunkClient's interface (get_all, safe_get_all) that
connectors/splunk/connector.py actually uses."""

from __future__ import annotations


class FakeSplunkClient:
    def __init__(self, data: dict[str, list[dict]] | None = None, deny: set[str] | None = None):
        self._data = data or {}
        self._deny = deny or set()

    def get_all(self, endpoint: str, count: int = 100) -> list[dict]:
        if endpoint in self._deny:
            raise RuntimeError(f"simulated failure reading {endpoint}")
        return self._data.get(endpoint, [])

    def safe_get_all(self, endpoint: str) -> tuple[list[dict], str | None]:
        if endpoint in self._deny:
            return [], f"Access denied reading '{endpoint}' — the scan credential lacks access to this endpoint."
        return self._data.get(endpoint, []), None
