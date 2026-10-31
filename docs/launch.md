# Launch checklist

[Quick start](../README.md) · [Release gates](releases.md#publication-gates) · [Contributing](../CONTRIBUTING.md)

Use this checklist for the exact candidate being announced. Repository settings,
a published release, package visibility, and a separate Homebrew tap cannot be
completed by merging documentation alone.

## Before publishing a release

- [ ] The candidate's full source, native archive, Chromium, container and
  vulnerability gates pass, including the optional Python dependency audit.
  Screenshot export must withhold uncertain credential geometry instead of
  publishing an apparently successful partial mask.
- [ ] Require all eight PR CI jobs in branch protection: both Go checks, native
  Chromium, and the five platform archive jobs. Adding Linux ARM64 and macOS
  Intel to workflow YAML does not automatically add them to required checks.
- [ ] Packaged notices in `LICENSE.md` are current, complete and present in every
  archive/image.
- [ ] Release under a **v2** tag consistent with `go.mod`. Explain the `/v2`
  import-path change with the [v2 API guide](library.md#v2-evidence-api), and link
  the [wafw00f migration guide](migrating-from-wafw00f.md) for CLI users.
- [ ] Verify the actual release hashes, binary identities, manifest and
  attestations; confirm immutable releases are enabled in repository settings.
- [ ] Make the new scanned release the supported installation route. The old
  v1.0.0 archives predate security fixes; retain clear supersession guidance.
  Confirm the published-binary security scan passes for the actual new downloads;
  a clean source scan or merged PR does not close the distribution gap.
- [ ] Check the resulting GHCR package's visibility and anonymous pull behavior
  before advertising a container installation command. Enabling publication in
  a workflow is not evidence that an image already exists.
- [ ] Exercise the generated Homebrew formula against the published archive
  URLs, then publish it in a maintained tap if Homebrew distribution is wanted.
  Do not advertise a tap that has not been created and tested.

## CI coverage and recovery

The [CI workflow](../.github/workflows/ci.yml) runs the full suite for pull
requests and for pushes to `main`. Open PRs provide feature-branch validation,
avoiding a second copy of the same suite on each push. The
[release workflow](../.github/workflows/release.yml) still calls reusable CI with
the prepared, frozen source SHA in `inputs.ref`; all CI jobs check out that
candidate. All eight existing check contexts remain: the two Go `check` jobs,
`Local Chromium integration`, and `Native PR test and archive smoke` for
Linux x64/ARM64, macOS x64/ARM64 and Windows x64. Keep their names and branch
protection requirements aligned when changing the workflow.

The pinned httpx installation, candidate build, loopback smoke test and usage
matrix have separate step deadlines and visible progress. Setup and artifact
uploads also have explicit deadlines within the existing job budgets. These
execution limits cannot resolve a job that is still waiting for a runner.

Investigate the actual Actions run before recovering a pending check:

| Observed state | Next action |
| --- | --- |
| Queued or waiting for a hosted runner | Confirm this is the current attempt, then check runner allocation and service availability. Command timeouts cannot resolve provisioning. |
| Executing without progress | Inspect the active step, logs and its deadline. Use normal cancellation first if the run must be stopped. |
| Completed run with a pending PR check | Refresh the run/check data and compare the event, head SHA and attempt with the current PR. Check whether strict branch protection requires an updated base. |

Record the run identity and obtain the affected job's `databaseId`, then rerun
that job after resolving the cause. The
[CLI rerun guidance](https://cli.github.com/manual/gh_run_rerun) distinguishes
this ID from the number shown in a job's web URL:

```sh
gh run view RUN_ID --repo Lu1sDV/wafmeow --json event,headSha,attempt,status,conclusion
gh run view RUN_ID --repo Lu1sDV/wafmeow --json jobs --jq '.jobs[] | {name, databaseId, status, conclusion}'
gh run rerun RUN_ID --repo Lu1sDV/wafmeow --job JOB_DATABASE_ID
```

Use [force-cancel](https://docs.github.com/en/rest/actions/workflow-runs#force-cancel-a-workflow-run)
only for a still-active run that does not respond to normal cancellation.
[Reruns](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs)
retain the original event's SHA and ref. If the PR needs a newer base, update it
and validate the resulting candidate before merging. Preserve the required
gates; do not remove checks or replace them with automatically successful
statuses. A completed old run does not validate a newer candidate.

## Positioning and evidence

Use this tagline consistently in the README, release introduction and launch
posts:

> wafw00f's fingerprints. Go speed. Pipeline-native.

Lead with a verifiable number and credit the upstream project:

> 172 WAF product identities, built on wafw00f's fingerprints. A static Go CLI and library for live HTTP and offline response analysis.

Suggested GitHub **About** description:

> wafw00f's fingerprints. Go speed. Pipeline-native. WAF detection from live HTTP and offline captures.

Use that description without “AI Assisted”: detection uses deterministic
fingerprints. Development assistance is not a runtime product capability.
An MCP integration would be a separate feature with its own scope and tests;
it is not needed to justify the description.

Use the [reproducible offline comparison](benchmarks.md#reproduce-the-current-checkout)
and retain its source, hardware, dependency and corpus identities. Publish the
verified artifacts with a benchmark claim. Do not rerun the unpatched v1.0.0
binary to market the current v2 candidate.

A ratio can be reported as “wafw00f/wafmeow median classification latency on this
saved synthetic corpus,” with the exact workload and environment. The live table
completes different amounts of work and does not support an unqualified “× faster”
headline. The README carries the recorded live comparison with explicit mode,
date, build and accounting links: on the 500-target VPS run completed 30–31
October 2026, with a 500-target non-CDN Tranco sample, the **median elapsed ratio
was 12.86× at 100 workers in fast mode and 3.99× at one worker in fast mode; full
mode was 4.67× and 1.94× respectively**. Slower cells must stay visible beside
faster ones. Report per-block returned and complete counts with any live claim,
and keep offline conformance results attached to their own workload. The
[VPS comparison protocol](benchmarks.md#reproduce-the-vps-comparison) governs the
next run. The older 2,000-target laptop table and connection-reuse measurements
remain as historical evidence, not current primary numbers.

The README already has a mascot, animated demo, source build/install commands,
structured-output examples and an authorized discovery pipeline. Keep the first
screen focused on what the tool does and a working installation path. Add a
headline speed figure only after a comparable, reproducible measurement supports it.

### Claims and comparison tables

Use “alternative”, “built on wafw00f's fingerprints”, “pipeline”, “recon at scale”,
“static binary” and “offline” where they explain the tool. The README includes
“wafw00f alternative”, “WAF detection in Go”, “fast WAF fingerprinting” and “detect
WAF at scale” in ordinary prose. Keep release and article titles descriptive, for
example **“A wafw00f alternative for WAF detection in Go and JSONL pipelines”**.
Avoid “killer”, “replacement”, “better than wafw00f”, unmeasured “blazing fast”,
and “AI” as a runtime capability.

Present proof points in this order: catalogue provenance and 172 product
identities; a static CLI binary; JSONL/JSON/CSV; offline capture analysis; request,
redirect and connection budgets; and the importable Go library. Keep these
qualifications close to the claims:

- Ported product identities do not establish identical probe coverage, detection
  behavior or accuracy. Reviewed synthetic fixture links currently cover 28/172
  products. Do not claim “nothing is lost by switching”.
- Optional Chromium capture has its own dependency and isolation limits. The
  core scanner and offline classifier do not require Python.
- Budgets and scope rules bound configured acquisition; they are not proof that
  arbitrary target lists are authorized or a hosted-service SSRF sandbox.

For a fresh **live** comparison, use one row per mode and parallelism. The table
should include **parallelism, mode, wafw00f elapsed, wafmeow elapsed, returned and
complete target counts, and wafw00f/wafmeow elapsed ratio**. Name the ratio
“× faster than wafw00f” only when the workload and completed work are comparable;
otherwise call it an observed elapsed-time ratio and explain the difference.
Use medians of repeated alternating runs and publish the versions, source SHA,
hardware, target-selection method, authorization, raw outputs and limits.

For the **offline** comparison, use the generated report's shared-product
classification latency and explicit workload scope. It has no target
parallelism or Internet-request timing; do not label it a live parallelism table.
“Up to 4.6×” and “1,000 hosts in under a minute” remain unapproved launch claims
until a fresh comparable run of the release candidate establishes them.

## Repository settings and community

- [ ] Replace the About description with the text above.
- [ ] Add relevant topics: `waf-detection`, `wafw00f`, `recon`, `bugbounty`,
  `pentesting`, `reconnaissance`, `cybersecurity`; retain `golang`, `appsec`
  and `fingerprinting` where useful.
- [ ] Set a mascot-based social preview in repository settings. Use a properly
  sized preview and inspect its crop; the small README icon alone is not a
  verified social-preview layout.
- [ ] Enable and verify GitHub private vulnerability reporting, then update
  [SECURITY.md](../SECURITY.md) if a verified private contact route is added.
- [ ] Turn a small, curated selection of the
  [starter contributions](../CONTRIBUTING.md#small-contributions-to-start-with)
  into specific issues and apply `good first issue` where appropriate. Avoid
  creating empty issues to reach a numerical target.
- [ ] Keep the live CI badge linked to actual workflow results. The public
  [Go Report Card service](https://goreportcard.com/) was checked on 29 October
  2026 and has been retired; do not add a badge implying a current report.

[CONTRIBUTING.md](../CONTRIBUTING.md), [SECURITY.md](../SECURITY.md), fingerprint and
bug issue forms, and the pull-request template provide the initial contributor
and reporting path. Keep their commands and support claims aligned with the
shipped release.

Replacing the existing release pipeline with GoReleaser is optional future work.
Preserve its source-SHA freeze, native tests, binary scanning, no-overwrite policy
and attestations if the build orchestration is ever changed.
