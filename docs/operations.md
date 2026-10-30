# Production operation

[Quick start](../README.md) · [CLI limits](usage.md#inputs-and-limits) · [Release controls](releases.md)

## Interpret results

Use detections as advisory evidence, not an enforcement decision or proof of
absence. Retain every result and inspect `outcome.state`, `outcome.diagnostics`,
and browser failures. A named match can coexist with incomplete evidence;
generic anomalies are separate from product matches.

| Exit code | Meaning |
| --- | --- |
| 0 | Run completed without a fatal error; without `--strict`, individual results may still be incomplete or failed |
| 1 | Configuration, input, or output failure |
| 2 | `--strict` found incomplete, failed, or diagnosed HTTP results, or browser/artifact failures, after report publication |
| 130 | Cancellation |

Treat nonzero exit codes as a reason to inspect both the results and stderr, not
as evidence that no output was produced.

## Reports and durable journals

JSONL stdout is incremental. Named reports are staged and atomically replace the
destination only after successful processing. Failures before publication preserve
the previous report. Later summary or journal-close errors can return exit 1
after the new report has been published. Streamed results and journal entries may
also exist after a failed or cancelled run.

Enable a body-free result and diagnostics journal when durable records are needed:

```sh
./wafmeow --input authorized-targets.txt --baseline --jsonl \
  --output results.json --diagnostics-journal results.journal.jsonl --strict
```

The journal appends and syncs each result before another sink sees it by default.
`--journal-batch-size` above 1 uses group sync: pending results are not published
to reports or output until their whole batch is synced. Partial batches flush
within 25 ms. A crash may lose a pending batch, but those results have not yet
been exposed to other sinks. See [journal limits](usage.md#inputs-and-limits).

Reports and journals can contain sensitive URLs and response metadata. Restrict
their permissions and retention; sanitized browser exports are not guaranteed
secret-free.

### Import CSV safely

CSV preserves original values. Spreadsheet applications can interpret cells
beginning with `=`, `+`, `-`, `@`, tab, or carriage return as formulas; CSV quoting
does not prevent that. Import every column explicitly as **Text** and disable
formula evaluation rather than opening an untrusted report directly. Use
JSON/JSONL if that import policy cannot be guaranteed.

## Deployment boundaries

Scan only authorized systems. Set explicit scope, timeouts, request budgets, and
rates for the deployment. Size worker concurrency and memory limits together;
the retained-evidence budget is not a process RSS cap.

A hosted service accepting arbitrary targets additionally needs independently
enforced egress and DNS/IP destination policies, isolated jobs, CPU/memory limits,
and controlled access. URL/redirect validation and browser CDP interception are
not an SSRF defense or an OS-enforced network/resource sandbox.

## Qualify a deployment

Require the [release validation gates](releases.md#publication-gates) for the exact
candidate being deployed. Synthetic conformance, regexp-oracle tests, and
detector agreement do not establish real-world WAF accuracy; see
[benchmark interpretation](benchmarks.md#offline-comparison).

Before using results in automated decisions, collect an independently labelled
validation set from the intended deployment: ordinary origins, CDN-only
deployments, actual WAF block pages, redirects, and incomplete responses. Record
capture provenance and product configuration independently of either detector.
Review held-out positives and negatives for the products relevant to the
deployment; do not use a fingerprint result as the sole basis for a security
decision.

Run operational checks against the candidate binary, native archive, and image:

```sh
# Linux: owned loopback traffic, mixed failures, and resource accounting.
# --seconds is the feed duration for each of baseline, fast, and full modes.
python3 tools/soak.py --binary ./wafmeow --output benchmarks/soak --seconds 60

# Extract the native release archive and exercise its binary and fixtures.
python3 tools/smoke.py archive /path/to/native-release.tar.gz

# Offline, non-root, read-only container checks; --runtime podman is also supported.
python3 tools/smoke.py docker wafmeow:candidate
```

Run from the repository root. The soak output directory must not already exist;
it records target accounting and RSS/file-descriptor samples. Failed assertions
return nonzero. A bounded loopback soak does not establish long-term leak freedom,
representative Internet throughput, or deployment accuracy.

