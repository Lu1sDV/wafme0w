# Contributing to wafmeow

wafmeow accepts fixes, documentation, and carefully reviewed fingerprint evidence.
Start with a small change that explains the problem and the resulting behavior.
For suspected vulnerabilities in wafmeow, follow [SECURITY.md](SECURITY.md)
before posting details in a public issue or pull request.

## Set up a checkout

Use a security-patched Go 1.26 or newer toolchain. The exact versions tested by
CI are in [.github/workflows/ci.yml](.github/workflows/ci.yml). Python 3.12 or
newer runs the development helpers; Python is not a dependency of the CLI.
The examples below use a POSIX shell and run from the repository root.

```sh
git clone https://github.com/Lu1sDV/wafmeow.git
cd wafmeow
go mod download
go build -o wafmeow ./cmd/wafmeow
./wafmeow --help
./wafmeow --evidence assets/demo/captures.jsonl --jsonl --no-colors
```

The last command uses synthetic saved responses and sends no requests. Build
`wafmeow.exe` on Windows. For network behavior, use `httptest` servers or other
owned loopback fixtures. A public hostname or an existing capture is not
authorization to scan its source.

Read [AGENTS.md](AGENTS.md) for repository conventions and
[docs/library.md](docs/library.md) for API ownership and evidence semantics.
Create a task branch, preserve unrelated changes, and keep generated binaries,
coverage, reports, and local captures out of commits.

## Make and verify a change

For a bug, first reproduce the incorrect behavior with a focused regression.
Verify that it fails before the fix and passes afterward. Prefer deterministic
saved evidence, injected readers/transports, and owned loopback fixtures.
Keep the test focused on observable behavior rather than duplicating the
implementation.

For Go changes, run:

```sh
gofmt -l cmd internal pkg
go vet ./...
go test -count=1 -timeout=5m ./...
go test -count=1 -timeout=5m -race -covermode=atomic -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

`gofmt -l` must print no filenames; a zero exit status alone does not prove the
files are formatted. Format only the files you change. The race detector needs
a supported platform and a working C compiler/CGO setup. On Linux, an installed
`bwrap` causes the isolation canary to run: denied namespaces are a failure,
not a reason to disable the check. Follow CI's host setup, or report the
environment limitation and rely on a successful hosted check before merge.

Exercise the actual CLI or public library path affected by the change as well.
For development-helper changes, select the relevant Python suite:

```sh
python3 -m unittest discover -s tools -p '*_test.py'
python3 -m unittest discover -s tools/offlinebench -p '*_test.py'
```

The first discovery command does not recurse into the separate offlinebench
test directory. Documentation-only changes need working links, accurate
commands, and relevant smoke checks; do not claim application suites passed
unless they ran.

### Checks for specific changes

| Changed area | Additional verification |
| --- | --- |
| Matcher or catalogue | Catalogue positive/negative tests, regexp-oracle regressions, and the bounded matcher fuzz check below |
| Evidence availability or httpx import | Availability/import regressions, both boundary fuzz checks below, and the pinned producer checks in [docs/usage.md](docs/usage.md#reproduce-the-producer-boundary-check) |
| Browser capture/export | Tagged native Chromium integration on supported Linux, using the command below |
| Packaging, dependencies, or workflows | Helper policy tests, source and binary vulnerability scans, native archive checks, and container checks in [docs/releases.md](docs/releases.md#publication-gates) |
| Offline comparison or reviewed fixtures | Both detector adapters and the isolated comparison/verification commands in [docs/benchmarks.md](docs/benchmarks.md#offline-comparison) |

```sh
go test ./pkg/wafmeow -run '^$' -fuzz '^FuzzMatcherRegexpEquivalence$' -fuzztime=30s -parallel=2 -timeout=3m
go test ./pkg/wafmeow -run '^$' -fuzz '^FuzzAvailabilityUnusableBody$' -fuzztime=10s -parallel=2 -timeout=2m
go test ./pkg/wafmeow -run '^$' -fuzz '^FuzzHTTPXImportCannotInventCompleteChannels$' -fuzztime=10s -parallel=2 -timeout=2m
```

For browser changes, run as a non-root Linux user with an installed native
Chromium executable. Set `WAFME0W_TEST_BROWSER` to its absolute path, then run:

```sh
go test -race -tags browser_integration ./pkg/wafmeow -run '^TestBrowser' -count=1 -timeout=3m
```

Ordinary `go test ./...` does not run the tagged browser integration or the
complete CI/release pipeline. Record exact commands, results, skips, and
limitations in the pull request. Release approval requires the full gates on
the exact committed candidate, including native checks for all shipped platforms.

## Add or change a fingerprint

Use the **Fingerprint report** issue form to discuss evidence before changing a
broad rule. A new product name or a detector's output alone does not establish
ground truth. Review one product/schema at a time where possible.

1. Identify the product and the specific response channel being matched. Explain
   independently why the positive example belongs to that product: for example,
   an owned deployment's known configuration or a cited upstream source. Keep
   fingerprint matches separate from claims of active WAF enforcement.
2. Provide a sanitized positive and a meaningful negative or near miss. The
   negative should exercise the proposed rule's boundary, not just an unrelated
   empty response. Preserve status, separate repeated header/cookie values, and
   body completeness accurately. Test incomplete/unavailable evidence when it
   could change the conclusion.
3. State whether each fixture is synthetic or a real capture. Real captures need
   traceable authorization, sanitization, collection/review dates, a reviewer,
   and an independent source of truth. Use safe reference identifiers and remove
   private target names, credentials, session cookies, personal data, and
   customer content. If removing sensitive values also removes the marker,
   discuss a synthetic reproducer instead of posting the original capture.
4. Update `cmd/wafmeow/resources/waf-fingerprints.json` and the relevant regression
   tests. For corpus fixtures, use SHA-256-addressed bodies under
   `tools/offlinebench/testdata/bodies/` and explicit expectations in
   `tools/offlinebench/testdata/corpus.json`.
5. Update the rule/fixture identities and reviewed positive **and** negative
   links in `tools/offlinebench/testdata/coverage-contract.json` after reviewing
   the evidence. New or changed rules cannot be grandfathered as
   `baseline-untested`. A synthetic fixture remains synthetic-conformance.
6. Run the relevant checks above. Explain changes in expected detector
   disagreements; never regenerate expected labels or review status from
   wafmeow/wafw00f output to make the checks pass.

### Preserve fingerprint review history

The history check compares `coverage-contract.json` with the contract from an
explicit trusted commit. An inherited `baseline-untested` entry may remain only
with the same product, schema number, and rule hash. New or changed rules need
reviewed fixture links; refreshing a hash cannot grandfather them. Existing
reviews cannot become `baseline-untested`, and `reviewed-real` coverage cannot
be downgraded to synthetic conformance. Reviewed updates and promotions are
allowed. Deliberately removing an obsolete rule is allowed when the catalogue
and contract are both updated and the removal is explained in review.

With the intended target branch already fetched, check local changes with:

```sh
review_base=$(git rev-parse origin/main)
python3 tools/check_fingerprint_review.py --base "$review_base"
python3 -m unittest discover -s tools -p 'check_fingerprint_review_test.py'
```

CI uses the pull request's exact base SHA, including when testing a merge
checkout, or the pre-push SHA for a push to `main`. Full checkout history makes
those commits available. Missing commits/contracts and all-zero branch-creation
baselines fail the check; they never cause it to be skipped. Reusable release
validation compares the frozen candidate with its first parent, assuming its
history already passed the PR/main checks. That release check is additional
validation of the candidate's change, not a substitute for the full PR/push
comparison. The helper reads baseline data without executing baseline code.

This history check supplements the Go assessor: the assessor still validates
current catalogue/fixture hashes, evidence provenance, and positive/negative
expectations. Neither check establishes real-world accuracy or substitutes for
human review of the evidence.

If adapting an upstream rule, cite its repository, immutable revision, and file.
Retain applicable attribution and redistribution terms in [LICENSE.md](LICENSE.md).
The inherited catalogue does not have a verified source revision for every rule;
do not present the comparison tool's pinned version as that missing provenance.

## Open a pull request

Explain the problem, the change, and the resulting behavior. Include a minimal
reproducer and the relevant validation evidence. Update the existing user docs
when behavior changes; keep detailed contracts under `docs/`.

Preserve the documented v2 Go API, CLI flags and exit codes, and result/report
contracts. Use keyed public struct literals. Call out any proposed incompatible
change so that its versioning can be reviewed explicitly. Keep unrelated
refactoring and generated artifacts out of the diff.

## Small contributions to start with

These are concrete suggestions, not assigned or already filed issues. Check
current work before starting, and propose the smallest useful scope.

| Contribution | Starting point and completion criterion |
| --- | --- |
| Document a custom catalogue | Add a minimal `--fingerprints` example to `docs/usage.md` with one positive and one near miss, both evaluated offline |
| Explain empty versus unavailable evidence | Add paired JSON examples to `docs/library.md` showing the different outcomes without inventing completeness |
| Add a Windows offline walkthrough | Validate PowerShell commands against the bundled demo and document paths, exit codes, and JSONL output |
| Review one inherited schema | Select one `baseline-untested` entry in `coverage-contract.json` and contribute reviewed positive/negative fixtures with honest provenance |
| Add a runnable library example | Add a small Go `Example` test for `Engine.Classify` that produces stable output from synthetic saved evidence |
| Improve isolation troubleshooting | Document how to distinguish missing `bwrap` from a namespace/AppArmor denial, using CI's setup without weakening isolation |
| Explain httpx fixture maintenance | Document the saved producer fixture manifest and hashes under `pkg/wafmeow/testdata/httpx-v1.12.0/`, including a safe review checklist for a future producer update |
