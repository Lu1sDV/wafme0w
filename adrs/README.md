# Architecture decision records

[Project overview](../README.md) · [Contributing](../CONTRIBUTING.md)

Architecture decision records (ADRs) explain significant design choices, their
alternatives, consequences, and the evidence needed to revisit them. They
complement the usage and operations guides; a proposed interface in an ADR is
not a supported CLI or library API.

## Decision index

| ADR | Title | Status | Recorded |
| --- | --- | --- | --- |
| [0001](0001-optional-http-and-browser-acquisition-backends.md) | Optional curl_cffi and Patchright acquisition backends | Proposed | 2026-10-30 |
| [0002](0002-http1-connection-reuse-for-probes.md) | Reuse HTTP/1 connections between a target's probes | Accepted | 2026-10-30 |

## Reading and maintaining records

- **Proposed:** a documented recommendation awaiting a maintainer decision.
- **Accepted:** the recorded decision has been adopted. Implementation and
  experimental validation remain separate statuses stated in the record.
- **Rejected:** the proposal was considered and declined; retain the reasoning.
- **Superseded:** a newer ADR replaces the decision; link both records.

Use sequential four-digit identifiers and descriptive filenames. Keep the
decision date, context, alternatives, consequences, sources, and outstanding
questions in each record. Distinguish observed facts, hypotheses, planned
experiments, and measured results. Update this table when a status changes.

Preserve the reasoning behind an accepted decision. Record material changes in
a superseding ADR rather than silently rewriting its historical assumptions.
Link experiment reports and implementation changes as they become available;
do not describe a planned test as a completed validation.
