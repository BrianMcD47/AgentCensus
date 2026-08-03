"""Fake Anthropic Admin API client — no network, mirrors the subset of
AnthropicAdminClient's interface (get, safe_get_all, oauth_token) that
connectors/anthropic/connector.py actually uses."""

from __future__ import annotations


class FakeAnthropicClient:
    def __init__(
        self,
        data: dict[str, list[dict]] | None = None,
        deny: set[str] | None = None,
        oauth_token: str | None = None,
    ):
        self._data = data or {}
        self._deny = deny or set()
        self.oauth_token = oauth_token

    def get(self, path: str, params: dict | None = None) -> dict:
        if path in self._deny:
            raise RuntimeError(f"simulated failure reading {path}")
        return {"id": "org_test", "type": "organization", "name": "Test Org"}

    def safe_get_all(self, path: str, params: dict | None = None) -> tuple[list[dict], str | None]:
        if path in self._deny:
            return [], f"Access denied reading '{path}' — this credential lacks the required scope."
        return self._data.get(path, []), None
