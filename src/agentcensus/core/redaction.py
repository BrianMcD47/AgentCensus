"""Secret redaction, shared by every connector.

WHY THIS MODULE EXISTS, AND WHY IT'S NOT OPTIONAL

AgentCensus writes a report that is meant to be shared — with a
security team, an auditor, a ticket, a slide. The population it flags
is, by design, the hand-built ungoverned integrations nobody
registered. That is *precisely* the population most likely to contain
a hardcoded credential, because the whole reason those integrations
are ungoverned is that nobody applied the normal review to them.

So the tool's own output is a credential-exfiltration risk unless
something actively stops it. "We only request non-secret fields" is
necessary but nowhere near sufficient:

  - A field named `script` passes every field-name check ever written
    and can still contain `var apiKey = 'sk-ant-...'` on line 40. This
    was a real hole, found by reading a real report generated from a
    real instance: the full source of every matched Script Include,
    Business Rule, Scheduled Job, and Scripted REST API resource was
    being written verbatim into the JSON, system prompts and all.
  - A field named `endpoint` is not a secret field, but
    `https://api.example.com/v1?api_key=abc123` is a secret value.

Hence two layers, both applied, neither trusted alone:

  1. `scrub_keys`   — key-NAME matching (a field called `token` is
                      redacted whatever it holds). This is the layer
                      the Splunk connector already had; it moved here
                      so all three connectors share one implementation
                      instead of one connector being protected.
  2. `scrub_values` — value-SHAPE matching (anything that looks like a
                      provider key, JWT, or URL-embedded credential is
                      redacted wherever it appears, including in the
                      middle of a blob of source code or a scan note).

Layer 2 is deliberately pattern-based and will never be complete —
a bespoke internal token format won't match. That's exactly why
script bodies are dropped entirely by default (see
`connectors/servicenow/shadow.py` and `script_metadata` below) rather
than being kept and scrubbed: redaction is the second line of defense
for content that must be kept, not a license to keep everything.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

REDACTED = "<redacted-by-agentcensus>"

# Substrings that mark a *field name* as secret-bearing regardless of
# what the value looks like. Kept in sync in spirit with
# tests/test_no_secret_fields.py's forbidden list — that test stops a
# secret field being *requested*, this stops one being *stored* if it
# arrives anyway (Splunk's REST API has no field projection, so it
# always does).
_SECRET_KEY_MARKERS = (
    "secret", "password", "passwd", "private_key", "privatekey",
    "token", "api_key", "apikey", "session_key",
    "sessionkey", "client_secret", "auth_key", "passphrase",
    # NOT bare "credential". On ServiceNow that is the real column name on
    # sys_connection / http_connection and holds a sys_id REFERENCE to a
    # discovery_credentials record — the join from a connection alias to
    # the credential it uses, which is the single most useful field on
    # that row for a governance reader. Marking it secret destroyed it in
    # every report.
    #
    # Same reasoning as the earlier fix for `credential_id`, which added a
    # lookahead for qualified forms and missed the bare one. An actual
    # secret stored under this key is still caught by the value-shape
    # layer, which does not depend on the key name at all.
    "credential_value", "credential_secret",
)

# URL query parameter names that carry credentials. Matched
# case-insensitively against the parameter name only, so a legitimate
# `?model=gpt-4` survives untouched.
_SECRET_QUERY_PARAMS = (
    "api_key", "apikey", "access_token", "token", "auth",
    "password", "secret", "client_secret", "sig", "signature",
)

# Separator + credential-bearing parameter + its value, matched directly
# rather than via parse_qsl/urlencode. Two reasons this is a regex and
# not a URL parse:
#   * `&amp;` — after html.escape, parse_qsl splits on the wrong
#     boundary and yields the parameter name `amp;api_key`, which no
#     allowlist contains. Matching the entity explicitly fixes that.
#   * urlencode re-encodes the whole query even when nothing was
#     redacted, turning `?sysparm_query=key=INC001` into
#     `?sysparm_query=key%3DINC001` in the report.
# Also matches schemeless query strings (a ServiceNow `relative_path`,
# a `setEndpoint('/v1/chat?...')` fragment), which the URL-only pass
# never examined at all.
# `scheme://user:pass@host` — the credential half is replaced, the
# host is kept.
_URL_NETLOC_CREDENTIAL_PATTERN = re.compile(
    r'(?P<scheme>https?://)[^/\s"\'<>@]+@(?P<host>[^\s"\'<>)\]/]+)' 
)

_SECRET_QUERY_PARAM_PATTERN = re.compile(
    r"(?i)(?P<sep>&amp;|[?&;])(?P<name>" + "|".join(_SECRET_QUERY_PARAMS) + r")"
    r'(?P<eq>=)(?P<value>[^&\s"\'<>)\]]+)' 
)

# Value shapes worth redacting anywhere they appear. Every one of these
# is a published, documented prefix format — this is not an attempt at
# generic entropy detection, which produces false positives on sys_ids
# and hashes (ServiceNow sys_ids are 32 hex chars and would trip almost
# any entropy heuristic, so an entropy-based approach would redact half
# of every report).
_SECRET_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}"),            # Anthropic
    re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{16,}"),          # OpenAI project keys
    re.compile(r"\bsk-[A-Za-z0-9]{32,}"),                  # OpenAI classic
    re.compile(r"\bAKIA[0-9A-Z]{12,}"),                    # AWS access key id
    re.compile(r"\bASIA[0-9A-Z]{12,}"),                    # AWS temporary key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),           # GitHub
    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"),        # Slack
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),             # Google API key
    re.compile(r"\bgsk_[A-Za-z0-9]{20,}"),                 # Groq
    re.compile(r"\bsk-or-v1-[A-Za-z0-9]{20,}"),            # OpenRouter
    re.compile(r"\bhf_[A-Za-z0-9]{20,}"),                  # Hugging Face
    re.compile(r"\bey[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),  # JWT
)

# `apiKey = "literally anything"` / `password: '...'` — catches bespoke
# and internal credential formats the prefix list above can't know
# about, which is the majority of them at a real company. Only the
# assigned VALUE is replaced; the assignment itself stays visible so a
# reviewer can still see that a hardcoded credential is there, which is
# itself a finding worth seeing.
_ASSIGNED_SECRET_PATTERN = re.compile(
    r"""(?ix)
    \b(
        api[_-]?key | secret | password | passwd | token |
        client[_-]?secret | auth[_-]?key | passphrase | bearer
    )
    \s* [:=] \s*
    # The opening delimiter as it may appear AFTER escaping. A bare
    # `"` only survives in an unescaped string; json.dumps rewrites it
    # to \" and html.escape rewrites both quote characters to
    # entities. Open and close are the same literal in every case, so a
    # backreference still closes the match correctly.
    (?P<q> \\" | &quot; | &\#x27; | &\#39; | ["'] )
    (?P<value> (?: (?! (?P=q) ) [^\n] ){4,} )
    (?P=q)
    """
)


# Credentials that follow their label across a separator the assignment
# pattern cannot express: a space (`Bearer <tok>`) or an argument
# boundary (`setRequestHeader('x-api-key', '<tok>')`).
# `_ASSIGNED_SECRET_PATTERN` requires `[:=]` between name and value and
# therefore matches NEITHER, despite listing `bearer` among its names —
# so it read as covered while never firing on the two forms anyone
# actually writes. This is the same shape as every other defect in this
# project: the guard names the right thing and is aimed one level to the
# side of where it happens.
#
# Quote forms include the post-escape variants for the same reason the
# assignment pattern does — this also runs inside `_final_scrub`, after
# json.dumps / html.escape have rewritten the delimiters.
_QUOTE = r"""(?:\\"|&quot;|&\#x27;|&\#39;|['"])"""

_HEADER_SECRET_PATTERN = re.compile(
    r"""(?ix)
    (?P<prefix>
        \b(?:bearer|basic)\s+
      | \b(?:x-)?(?:api[_-]?key|auth[_-]?token|access[_-]?token|
              private[_-]?token|session[_-]?key)\b
        \s* (?: """ + _QUOTE + r"""\s*,\s* | :\s* | ,\s* ) \s* """ + _QUOTE + r"""?
    )
    # The value must LOOK like a credential, not merely follow the word.
    # `\b(?:bearer|basic)\s+` alone matched the prose "basic
    # authentication" in this project's own documentation and rewrote it
    # to "basic <redacted>". Requiring a digit is a cheap, high-precision
    # discriminator: issued tokens essentially always contain one, and
    # English words never do. A credential that is genuinely all-letters
    # is missed here and still caught by the key-name layer and by the
    # value-shape prefixes — this pattern is one of several, not the only
    # line of defence, so precision is worth more than reach.
    (?P<value>(?=[A-Za-z0-9_\-\.=+/]*\d)[A-Za-z0-9_\-\.=+/]{8,})
    """
)


# `"api_key": "value"` as it appears AFTER json.dumps. The assignment
# pattern is structurally incapable of matching this: the key's own
# closing quote sits exactly where that pattern requires `\s*[:=]\s*`.
# Without this, `_final_scrub` is load-bearing only for the value-shape
# patterns, which is materially less than its docstring used to claim.
_JSON_PAIR_SECRET_PATTERN = re.compile(
    r"""(?ix)
    (?P<key>
        (?:\\"|&quot;|["'])
        \s*
        # The key must BE a secret name, not merely CONTAIN one. Matching
        # on containment redacted `credential_id` (a foreign key), and
        # `token_url` (an OAuth endpoint) — so the only redaction in an
        # otherwise clean report was of two non-secrets, while the graph
        # section still carried the same credential_id unredacted. A
        # redaction that fires on the wrong field is not conservative,
        # it is wrong twice: it destroys evidence and it teaches the
        # reader that the marker is noise.
        #
        # A trailing qualifier that names a REFERENCE to a secret rather
        # than the secret itself is excluded explicitly.
        (?: [\w.\-]*? [_.\-] )?
        (?: api[_-]?key | secret | password | passwd | token
          | passphrase | client[_-]?secret )
        (?! (?: _ | \- ) (?: id | url | uri | type | name | count | at | on | by ) )
        \s* (?:\\"|&quot;|["'])
        \s* : \s*
        (?:\\"|&quot;|["'])
    )
    (?P<value>(?:(?!\\"|&quot;|["']).)+)
    """
)


def _redact_prefixed(match: re.Match[str]) -> str:
    """Keep the label, replace only the credential — same principle as
    `_redact_assigned_value`. The reader should still see THAT a
    hardcoded credential is present, which is itself a finding worth
    acting on, without the credential itself."""
    full = match.group(0)
    offset = match.start()
    return (
        full[: match.start("value") - offset]
        + REDACTED
        + full[match.end("value") - offset :]
    )


def _redact_url_credentials(text: str) -> str:
    """Redacts credential-bearing query parameters and any `user:pass@`
    netloc, leaving everything else byte-for-byte intact — the host and
    path are exactly what a reviewer needs to see, and are the whole
    basis of tier-2 host matching.

    Operates by direct substitution rather than urlsplit/urlencode so
    that (a) nothing is re-encoded when nothing was redacted, and (b) a
    query string still matches after html.escape has rewritten its
    separators to `&amp;`. Applies to schemeless paths too, not just
    fully-qualified URLs.
    """
    def _fix_netloc(match: re.Match[str]) -> str:
        return f"{match.group('scheme')}{REDACTED}@{match.group('host')}"

    text = _URL_NETLOC_CREDENTIAL_PATTERN.sub(_fix_netloc, text)
    return _SECRET_QUERY_PARAM_PATTERN.sub(
        lambda m: f"{m.group('sep')}{m.group('name')}{m.group('eq')}{REDACTED}", text
    )


def _redact_assigned_value(match: re.Match[str]) -> str:
    """Replaces only the quoted value inside a `key = "secret"`
    assignment, leaving the key, operator, and quotes exactly as they
    were — so the reader still sees that a hardcoded credential exists
    (a finding in itself) without seeing the credential."""
    full = match.group(0)
    offset = match.start()
    return (
        full[: match.start("value") - offset]
        + REDACTED
        + full[match.end("value") - offset :]
    )


def scrub_values(text: str) -> str:
    """Redacts secret-shaped substrings anywhere in a string. Safe to
    call on anything — source code, a URL, an error message, a scan
    note. Non-str input is returned unchanged."""
    if not isinstance(text, str) or not text:
        return text
    out = _redact_url_credentials(text)
    for pattern in _SECRET_VALUE_PATTERNS:
        out = pattern.sub(REDACTED, out)
    # Header/argument forms first: `Bearer <tok>` and
    # `setRequestHeader('x-api-key', '<tok>')` have no `[:=]` between
    # name and value, so the assignment pass below can never see them.
    out = _HEADER_SECRET_PATTERN.sub(_redact_prefixed, out)
    out = _JSON_PAIR_SECRET_PATTERN.sub(_redact_prefixed, out)
    return _ASSIGNED_SECRET_PATTERN.sub(_redact_assigned_value, out)


def is_secret_key(key: str) -> bool:
    lowered = str(key).lower()
    return any(marker in lowered for marker in _SECRET_KEY_MARKERS)


def scrub(value: Any) -> Any:
    """Recursively applies both layers to any JSON-ish structure.

    dicts: a secret-NAMED key has its value replaced outright; every
    other value is recursed into and value-scrubbed. This is the one
    function connectors should call on anything headed for a `raw`
    blob or a scan note.
    """
    if isinstance(value, dict):
        return {
            k: (REDACTED if is_secret_key(k) else scrub(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [scrub(v) for v in value]
    if isinstance(value, str):
        return scrub_values(value)
    return value


def script_metadata(script: str, excerpt_around: str | None = None,
                    include_excerpt: bool = False) -> dict:
    """What a `raw` blob should carry INSTEAD of a script body.

    Script source is the single most dangerous thing this tool touches:
    it is the most likely place to find a hardcoded credential, it is
    proprietary business logic, and on a real instance it includes
    system prompts. None of that belongs in a report that gets emailed
    to an auditor, and no redaction pass is good enough to make keeping
    it the safe default.

    What's kept is what a reviewer actually needs to act:
      - `script_sha256` — a stable fingerprint. Lets you diff scans
        ("did this script change since last month?") and correlate
        duplicates across instances without holding the content.
      - `script_length` — rough sense of what's there.
      - `script_excerpt` — ONLY when explicitly opted into
        (`--include-script-excerpts`), and even then scrubbed through
        `scrub_values` first. A few lines around the matched keyword,
        not the whole body.

    The agent's `detection_signal` already names which provider keyword
    matched, so the default (no excerpt) still tells a reviewer exactly
    what to go look at and where — it just makes them open ServiceNow
    to read it, which is the correct place for source code to live.
    """
    script = script or ""
    meta: dict[str, Any] = {
        "script_sha256": hashlib.sha256(script.encode("utf-8", "replace")).hexdigest(),
        "script_length": len(script),
        "script_excerpt_included": bool(include_excerpt),
    }
    if not include_excerpt:
        return meta

    excerpt = script
    if excerpt_around:
        idx = script.lower().find(excerpt_around.lower())
        if idx != -1:
            start = max(0, idx - 200)
            meta["script_excerpt"] = scrub_values(script[start:idx + 300])
            return meta
    meta["script_excerpt"] = scrub_values(excerpt[:500])
    return meta
