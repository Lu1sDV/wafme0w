# Production operation

[Quick start](../README.md) · [CLI limits](usage.md#inputs-and-limits) · [Release controls](releases.md)

Use detections as advisory evidence, not an enforcement decision or proof of
absence. In automation, retain every result and inspect `outcome.state`,
`outcome.diagnostics`, and browser failures. `--strict` exits 2 for incomplete,
failed, or diagnosed results **after** publishing the report; exit 1 is a
configuration/input/output failure, and cancellation exits 130. Earlier streamed
results and journal entries may exist when a run fails. Failures before atomic
publication preserve the previous report; later summary or journal-close errors
can return exit 1 after the new report has already been published.

The diagnostics journal syncs every result before another sink sees it by default.
`--journal-batch-size` above 1 uses group sync: pending results are not published
to reports or output until their whole batch is synced, and partial batches flush
within 25 ms. A crash may lose a pending batch, but results from that batch have
not yet been exposed to the other sinks.

CSV deliberately preserves original values. Spreadsheet applications can interpret
cells beginning with `=`, `+`, `-`, `@`, tab or carriage return as formulas; CSV
quoting does not prevent that. Import every column explicitly as **Text** and
disable formula evaluation rather than opening an untrusted report directly.
Use JSON/JSONL if that import policy cannot be guaranteed.

Choose explicit target scope, timeouts, request budgets, and rates for the
deployment. Only scan authorized systems. A hosted service accepting arbitrary
targets additionally needs independently enforced egress and DNS/IP destination
policies, isolated jobs, CPU/memory limits, and controlled access. URL/redirect
validation and browser CDP interception are not an SSRF defense or an OS-enforced
network/resource sandbox.

[Release validation and security maintenance](releases.md) describe the build,
artifact, and publication gates.

Synthetic conformance and regexp-oracle checks do not measure real-world WAF
accuracy; the reviewed offline corpus currently covers 28 of 172 products and
36 of 195 schemas, with no independently reviewed real captures.

Before automated decisions, collect an independently labelled validation set from
the intended deployment: ordinary origins, CDN-only deployments, actual WAF block
pages, redirects, and incomplete responses. Record capture provenance and product
configuration independently of either detector; review held-out positives and
negatives for the products that matter to that deployment. Detector agreement,
generated witnesses, and the 117 synthetic corpus cases are regression evidence,
not a measured production false-positive or false-negative rate.

Run the retained operational checks against the candidate being deployed:

```sh
# Linux only: owned loopback traffic, mixed failures, bounded resource checks.
# --seconds is the feed duration for each of baseline, fast, and full modes.
python3 tools/soak.py --binary ./wafme0w --output benchmarks/soak --seconds 60

# Extract the native release package and verify its actual binary and fixtures.
python3 tools/smoke.py archive /path/to/native-release.tar.gz

# Offline, non-root, read-only container checks; use --runtime podman if needed.
python3 tools/smoke.py docker wafme0w:candidate
```

These commands fail on violated assertions. The soak output directory must be
new; it records target accounting and RSS/file-descriptor samples. Its bounded
run is not proof against indefinite leaks or representative Internet throughput.
