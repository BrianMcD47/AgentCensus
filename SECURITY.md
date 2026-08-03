# Security Policy

## Reporting a vulnerability

Please report security issues privately, **not** as a public GitHub issue.

Open a [private security advisory](../../security/advisories/new) on this
repository, or email the address on the maintainer's GitHub profile.

Please include what you were running (`agentcensus --version`), the
platform and release you scanned, and enough detail to reproduce. If the
issue involves report content, **redact it** — a report is an inventory
of ungoverned integrations and their owners, and pasting one into a bug
report recreates the problem it describes.

Expect an acknowledgement within a few days. This is a small project with
no SLA; the honest expectation is best effort, not a guaranteed window.

## What counts as a vulnerability here

This tool reads credential-adjacent data on production instances and
writes a file meant to be shared, so the interesting failures are mostly
about disclosure rather than code execution:

- **Secret material reaching either output format.** Two redaction layers
  plus a final backstop are supposed to prevent it. A bypass is the most
  serious class of bug this project can have. See `core/redaction.py`.
- **Script source reaching a report.** Detection reads script bodies;
  reports carry a sha256 fingerprint instead. Any path that publishes the
  body itself (outside `--include-script-excerpts`) is a vulnerability.
- **Any write to a scanned platform.** The connector interface exposes
  only `fetch_*` methods and there is no write path by design. A write of
  any kind is a defect regardless of impact.
- **Report file permissions.** Reports are written 0600.

## What is a bug, but not a vulnerability

- **False negatives** — a missed agent. Serious, and this project's
  history is largely a record of them, but not a security issue in the
  disclosure sense. File a normal issue.
- **Over-redaction.** Destroying a non-secret field is wrong and worth
  reporting, but it fails safe.

## Known limitations

Please read the "Verified against" section of the README before
reporting. The connector has been exercised against a narrow set of live
instances, several detections have never executed against real data, and
those gaps are documented rather than hidden. A report that a detection
"doesn't work" on a configuration listed there is useful — but it is a
known gap, not a discovery.
