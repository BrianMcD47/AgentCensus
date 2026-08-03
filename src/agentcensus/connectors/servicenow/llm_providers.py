"""Loader for `llm_providers.yaml`.

Kept tiny and separate from `shadow.py`/`flow_designer.py` so the
matching logic is easy to unit test against an in-memory provider list
without touching disk.

Customers WILL need to extend this list — an internal/self-hosted LLM
gateway has no public hostname AgentCensus can ship a default for.
Two ways in, both env-var and CLI driven so nothing requires editing
the installed package:

  AGENTCENSUS_LLM_PROVIDERS_EXTRA=/path/to/extra.yaml
      Same `providers:` shape as the bundled file. Entries are merged
      on top of the defaults — same provider `id` in both replaces the
      bundled entry (so you can add hosts to an existing provider by
      re-declaring it), a new `id` adds a new provider outright.

  AGENTCENSUS_LLM_PROVIDERS_CONFIG=/path/to/replacement.yaml
      Replaces the bundled file entirely rather than merging with it.

CLI: `--llm-providers-extra` / `--llm-providers-config` (scan command),
map straight to the two env vars above.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

_CONFIG_PATH = Path(__file__).parent / "llm_providers.yaml"


@dataclass(frozen=True)
class Provider:
    id: str
    label: str
    hosts: tuple[str, ...]
    keywords: tuple[str, ...]


def _parse(data: dict) -> list[Provider]:
    providers = []
    for entry in data.get("providers", []):
        providers.append(
            Provider(
                id=entry["id"],
                label=entry.get("label", entry["id"]),
                hosts=tuple(h.lower() for h in entry.get("hosts", [])),
                keywords=tuple(k.lower() for k in entry.get("keywords", [])),
            )
        )
    return providers


def load_providers(path: Path | None = None) -> list[Provider]:
    path = path or _CONFIG_PATH
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return _parse(data)


def resolve_providers(
    extra_path: str | Path | None = None,
    override_path: str | Path | None = None,
) -> list[Provider]:
    """The one entry point connectors should call — reads the two env
    vars documented above if the explicit args aren't given, so CLI
    users and library users both get the same extension behavior."""
    override_path = override_path or os.environ.get("AGENTCENSUS_LLM_PROVIDERS_CONFIG")
    if override_path:
        return load_providers(Path(override_path))

    base = load_providers()
    extra_path = extra_path or os.environ.get("AGENTCENSUS_LLM_PROVIDERS_EXTRA")
    if not extra_path:
        return base

    extra = load_providers(Path(extra_path))
    by_id = {p.id: p for p in base}
    for provider in extra:
        by_id[provider.id] = provider  # re-declaring an id replaces it; new ids just add
    return list(by_id.values())


def match_host(hostname_or_url: str, providers: list[Provider]) -> Provider | None:
    """Substring match, not exact — REST message endpoints are full URLs
    (https://api.anthropic.com/v1/messages), not bare hostnames."""
    if not hostname_or_url:
        return None
    haystack = hostname_or_url.lower()
    for provider in providers:
        for host in provider.hosts:
            if host and host in haystack:
                return provider
    return None


def match_keywords(haystack: str, providers: list[Provider]) -> list[Provider]:
    """Every provider whose keyword appears in `haystack`, word-bounded.

    Returns a LIST — detection signals join them
    (`script_include:openai,azure_openai`), so a script touching two
    providers must report both. An intermediate version of this fix
    returned a single Provider and broke that, which is the argument for
    running the full suite before trusting a rewrite.

    WORD-BOUNDED, which it was not. This is the matcher behind tiers 1,
    3 and 4, flow names, spoke names, property names and both other
    connectors — i.e. most detections in the product — and it was a bare
    `in` test. Verified false positive: `"// ensure data coherence across
    nodes"` matched the provider `cohere`.

    Two other places in this codebase had already reasoned their way to
    `\b` and written out why; the conclusion was never carried to the
    primary matcher. Hyphenated keywords (`claude-`, `gpt-4`) still work:
    `\b` sits before the token.
    """
    text = haystack or ""
    hits: list[Provider] = []
    for provider in providers:
        for keyword in provider.keywords:
            if re.search(_keyword_pattern(keyword.lower()), text):
                hits.append(provider)
                break
    return hits


def _keyword_pattern(keyword: str) -> str:
    """No leading boundary; a trailing guard only for ambiguous keywords.

    Three attempts got this wrong in three different ways, all found by
    running rather than reasoning, so the reasoning is written out.

    1. Bare `in` (the original). `"data coherence"` matched `cohere`.
    2. `\b` on both sides. Broke `gpt-4o`.
    3. `\b` leading + `(?![a-z])` trailing, on a LOWERCASED haystack.
       This is the one that shipped for a release and cost a real
       detection: `AmazonBedrockResponseHandler` stopped matching
       `bedrock`, and the same rule would have killed `ClaudeClient`,
       `VertexAIClient`, `PaLMClient`.

    The lesson from (3): **`\b` does not see CamelCase.** There is no
    word boundary between `n` and `B` in `AmazonBedrock` — both are word
    characters — so a leading `\b` rejects exactly the compound
    identifiers this tier most wants to find. Lowercasing the haystack
    first destroys the only signal that distinguishes them.

    So: no leading boundary at all (it was never doing useful work, and
    it was actively harmful), and a trailing `(?![a-z])` applied only to
    keywords that collide with English. Case-sensitivity is scoped —
    `(?i:...)` on the token, plain `[a-z]` in the lookahead — because
    `re.IGNORECASE` on the whole pattern makes `[a-z]` match uppercase
    and silently undoes the guard.

    Net effect: a lowercase letter after an ambiguous keyword means it is
    part of an English word (`coherence`) and is rejected; anything else,
    including an uppercase letter, is a boundary and matches.
    """
    escaped = re.escape(keyword)
    if keyword in _ENGLISH_AMBIGUOUS:
        return r"(?i:" + escaped + r")(?![a-z])"
    return r"(?i:" + escaped + r")"


_ENGLISH_AMBIGUOUS = frozenset({
    "cohere",     # "coherence", "coherent" — the measured case
    "bedrock",    # "bedrock principle"
    "vertex",     # graph/geometry vocabulary, and this is a graph tool
    "palm",       # anatomy, trees
    "titan",      # mythology, and a common product name
    "gemini",     # astrology, and a common product name
    "mistral",    # a wind
    "claude",     # a person's name — including, plausibly, a colleague's
})
