## Problem and resulting behavior

Explain what is wrong or missing, why it matters, and what users will experience
after this change. Link a related issue if one exists.

## Changes

Describe the relevant implementation and documentation changes. Call out effects
on the v2 Go API, CLI flags/exit codes, JSON/CSV/TXT contracts, and evidence
completeness. For a proposed incompatible change, explain the versioning plan.

## Validation

List exact commands and results. Include a focused reproducer for a bug and
whether it failed before the fix. Mark checks not run, skipped, or blocked by the
environment explicitly; ordinary Go tests do not cover every CI/release gate.

| Check | Result |
| --- | --- |
| Focused regression / CLI or library smoke | |
| Formatting, vet, and relevant tests | |
| Additional affected-surface checks | |

## Evidence and compatibility review

- [ ] The diff excludes secrets, private targets, raw production captures, generated reports, and unrelated changes.
- [ ] Relevant user docs and compatibility contracts have been reviewed.
- [ ] New or changed fingerprints include reviewed positive and negative evidence, provenance, source attribution, and updated coverage identities, or this PR does not change fingerprints.
- [ ] Expected labels and review status were assessed independently rather than generated from detector output.

For suspected vulnerabilities, use the process in
[SECURITY.md](https://github.com/Lu1sDV/wafmeow/blob/main/SECURITY.md) before posting
details in this public pull request.
