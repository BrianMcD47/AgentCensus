
from agentcensus.connectors.servicenow.llm_providers import (
    load_providers,
    resolve_providers,
)


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def test_resolve_providers_defaults_to_bundled_list_when_nothing_set(monkeypatch):
    monkeypatch.delenv("AGENTCENSUS_LLM_PROVIDERS_EXTRA", raising=False)
    monkeypatch.delenv("AGENTCENSUS_LLM_PROVIDERS_CONFIG", raising=False)
    assert resolve_providers() == load_providers()


def test_extra_file_adds_a_new_provider_and_can_augment_an_existing_one(tmp_path):
    extra = _write(
        tmp_path,
        "extra.yaml",
        """
providers:
  - id: internal_gateway
    label: Internal LLM Gateway
    hosts: [llm.internal.example.com]
    keywords: [internal-llm]
  - id: anthropic
    label: Anthropic
    hosts: [api.anthropic.com, llm-proxy.internal.example.com]
    keywords: [anthropic, "claude-"]
""",
    )
    providers = resolve_providers(extra_path=extra)
    by_id = {p.id: p for p in providers}

    assert "internal_gateway" in by_id
    assert "llm.internal.example.com" in by_id["internal_gateway"].hosts
    # bundled providers not touched by the extra file are still present
    assert "openai" in by_id
    # re-declared provider's host list is replaced by the extra file's version
    assert "llm-proxy.internal.example.com" in by_id["anthropic"].hosts


def test_override_file_replaces_the_bundled_list_entirely(tmp_path):
    override = _write(
        tmp_path,
        "override.yaml",
        """
providers:
  - id: only_this_one
    label: Only This One
    hosts: [only.example.com]
    keywords: []
""",
    )
    providers = resolve_providers(override_path=override)
    assert [p.id for p in providers] == ["only_this_one"]


def test_env_vars_are_used_when_explicit_args_are_not_given(tmp_path, monkeypatch):
    extra = _write(tmp_path, "extra.yaml", "providers:\n  - id: env_test\n    hosts: [env.example.com]\n")
    monkeypatch.setenv("AGENTCENSUS_LLM_PROVIDERS_EXTRA", str(extra))
    monkeypatch.delenv("AGENTCENSUS_LLM_PROVIDERS_CONFIG", raising=False)

    providers = resolve_providers()
    assert any(p.id == "env_test" for p in providers)
