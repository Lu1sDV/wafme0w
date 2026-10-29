# Benchmarks and detector validation

[Quick start](../README.md) · [Operational checks](operations.md)

Wall-clock timings describe a specific build, workload, and environment. Offline
conformance checks compare detector behavior with reviewed fixture expectations.
Neither measures real-world detection accuracy or proves WAF enforcement.

## Reproduce the current checkout

Use a **clean, committed Linux checkout**, a supported Go compiler, Python 3.12
or newer, and `bwrap` with working user, mount, PID and network namespaces.
The comparison replays the checked-in synthetic corpus; it accepts no live target
list and sends no requests to third-party targets. Package setup downloads
dependencies; detector workers have no external network access.

```sh
python3 -m venv .offlinebench-venv
.offlinebench-venv/bin/pip install -r tools/offlinebench/requirements.txt
python3 tools/reproduce_benchmark.py \
  --wafw00f-python "$PWD/.offlinebench-venv/bin/python" \
  --output benchmarks/reproduction-01 --iterations 100 --blocks 4
```

Choose a new output directory for every run. The wrapper builds the benchmark
binary itself, rejects dirty source or a mismatched binary VCS identity, verifies
every pinned Python package (including wafw00f 2.4.2), runs the isolated comparison,
and verifies its published generation. It records:

- The source SHA, initial/final clean state, binary hash and embedded VCS identity.
- Go version and build settings, Python version and dependency versions.
- OS/kernel, CPU model, architecture, logical CPU count and allowed CPU affinity.
- Corpus and requirements hashes, case counts/kinds, selection policy, iterations
  and blocks. Every checked-in case is used; targets are not sampled or replaced.
- The exact commands, stdout/stderr, manifest hash, timestamps and completion
  status. A failed build, isolation check or result verification remains a failure
  with `complete: false`; there is no fallback to an unisolated comparison.

`reproduction.json` describes the host and run; `run/report.txt` and
`run/summary.json` contain the measurements; `run/run-manifest.json` binds the
published result files. Retain the complete output directory with any published
claim. The CI artifact contains the same records for its exact checkout. A hosted
CI runner is suitable for conformance and reproducibility checks, but variable
shared-host load is a limitation for small timing differences.

The wrapper's `launcher_gomaxprocs_env` is recorded for context only. The isolated
workers clear inherited environment variables; Go chooses its worker runtime
parallelism. For controlled comparisons, use the same CPU affinity and resource
allocation for every candidate and retain repeated alternating blocks.

The reported `wafw00f_over_wafme0w_latency_ratio` is the median of the per-case
wafw00f/wafme0w ratios, using each case's median **saved-response classification
latency** across blocks. Only paired, expected-complete, conformant cases in the
shared-product profile contribute. The comparison times warm named-product
classification, excluding generic detection, live DNS/HTTP work, initialization
and preparation. It is not a number of Internet hosts per minute. Keep the
full-native-catalogue profile distinct and retain the bootstrap interval and
paired-case count. Do not substitute this ratio for a live CLI speedup.

## Live CLI comparison

The following measurements were collected on **29 October 2026**, using 500
targets and wafw00f 2.4.2. Each configuration has one completed observation, not
repeated statistical samples. The saved wafme0w build predates the v2 evidence
API and httpx importer; these timings do not measure those features.

### Wall-clock results

| Workers / processes | wafme0w fast | wafme0w full | wafw00f 2.4.2 |
| --- | ---: | ---: | ---: |
| 1 | 6m 49.44s | 15m 51.93s | 14m 38.21s |
| 10 | 52.89s | 1m 45.62s | 2m 53.39s |
| 50 | 24.06s | 44.26s | 1m 50.93s |

All nine configurations attempted the same targets and exited 0 without a
watchdog timeout. Different probe sets, TLS policies, evidence completeness, and
network state prevent interpreting elapsed-time ratios as equivalent-work
speedups.

### Result accounting

Counts are **targets**, not fingerprint matches, distinct products, or HTTP
requests. Named and generic detections may overlap and may coexist with
incomplete evidence.

| Workers | Mode | Returned | Missing | Complete | Incomplete | Named | Generic |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | wafme0w fast | 500 | 0 | 306 | 194 | 156 | 84 |
| 1 | wafme0w full | 500 | 0 | 316 | 184 | 157 | 108 |
| 1 | wafw00f | 342 | 158 | — | — | 153 | 91 |
| 10 | wafme0w fast | 500 | 0 | 318 | 182 | 156 | 83 |
| 10 | wafme0w full | 500 | 0 | 317 | 183 | 158 | 105 |
| 10 | wafw00f | 343 | 157 | — | — | 153 | 87 |
| 50 | wafme0w fast | 500 | 0 | 206 | 294 | 131 | 62 |
| 50 | wafme0w full | 500 | 0 | 280 | 220 | 139 | 90 |
| 50 | wafw00f | 341 | 159 | — | — | 155 | 87 |

`complete` describes the evidence supplied to the native classifier, not WAF
absence or active enforcement. wafw00f does not report equivalent completion
states; its missing records remain unknown despite successful process exits.
Higher concurrency changed evidence completeness, so shorter wall time alone
does not establish equal completed work or unchanged detection behavior.

### Build and input identity

| Component | Recorded identity |
| --- | --- |
| wafme0w | Source identifier `347f547`, Go `1.26.10-X:nodwarf5`, `vcs.modified=true` |
| wafw00f | Unmodified 2.4.2, Python 3.14.8; package files checked against the installation manifest |
| Targets | First 500 domains of [Tranco ZJ8PG, 28 October 2026](https://tranco-list.eu/list/ZJ8PG/1000000), as HTTPS root URLs |

The modified-tree build flag means the commit identifier alone cannot reproduce
the measured binary. Recorded SHA-256 identities:

- Binary: `442595cffd0801d38c5849c855ee8daa33e1120a88168022f137e8c34b83ec5f`
- Target file: `e74e8e65fffc1d18f5ddd82b7165641e0ad6e68f3553bcdb26df1d4f0f2a14f2`

The active comparison was explicitly authorized for that run. A public target
list is not permission to scan its entries.

### Method and limitations

- Both tools used a 3-second request timeout, disabled redirects, and cleared
  inherited proxy settings. Unreachable targets were retained, not replaced.
- wafme0w used fast mode or default serial-probe full mode. Target workers and the
  global connection cap equalled the table's concurrency. The target deadline was
  30 seconds, the target request budget 54, and the decoded-body limit 1 MiB.
  TLS verification remained enabled; browser capture and journaling were off.
- wafw00f used `--findall`. At concurrency N, N stock CLI processes consumed
  round-robin static shards, rather than starting a new process per target. Its
  connect/read timeout semantics differ; it uses a 100 KiB body-read threshold
  and disables certificate verification. Probe sets and headers also differ.
- Configurations ran separately on the same four allowed logical CPUs, with
  native `GOMAXPROCS=4`. Tool order was fast/full/wafw00f at 50 workers,
  wafw00f/fast/full at 10, and full/wafw00f/fast at 1.
- Timing included CLI startup and output writes, but excluded compilation and
  target partitioning. An interrupted one-worker full scan was excluded; its
  replacement completed. No completed configuration was repeated.
- Network/DNS state, load, and responses can change between configurations.
  Differences in named matches are not detection-accuracy evidence.

Raw captures, build manifests, process logs, and verification artifacts are not
distributed with the repository. The tables and recorded identities above are
the published measurement record.

### Reproduce an authorized comparison

Use an independently authorized target file and retain every attempted target,
process exit status, command, build identity, and raw output. Clear inherited
proxy settings and use the same CPU affinity for both tools.

```sh
# Choose 1, 10, or 50; add --fast for the fast-mode configuration.
N=10
GOMAXPROCS=4 ./wafme0w --input targets.txt --jsonl --silent --no-colors \
  --concurrency="$N" --max-connections="$N" --probe-concurrency=1 \
  --request-timeout=3s --target-timeout=30s --max-requests=54 \
  --max-body-bytes=1048576 --redirect-policy=none --max-redirects=0
```

For wafw00f 2.4.2, divide the same input into N round-robin shards and run N
copies of this command, one per shard:

```sh
python -m wafw00f.main -i shard.txt -a -r -T 3 --no-colors \
  -f json -o shard.json
```

Write outputs to files rather than rendering them in a terminal. Start the timer
before launching processes and stop it after every process exits. A
watchdog-aborted configuration is not a completed timing. Account for missing
upstream records as unknown, never negative.

## Local performance benchmarks

Run from the repository root:

```sh
go test ./internal/offlinebench -run '^$' \
  -bench 'BenchmarkClassify(Evidence|SingleBody|SmallCatalogue|UnguardedContent)$' -benchmem
go test ./pkg/wafme0w -run '^$' -bench '^BenchmarkAcquisitionPipeline$' -benchmem
```

The acquisition matrix uses owned HTTP/TLS loopback fixtures, four workers, and
the full catalogue. Baseline/full modes perform exactly one/nine probes and
fresh HTTP/1 connections per target. Bodies cover small HTML, 32 KiB HTML, and
gzip. Compilation and fixture setup are outside timing; acquisition,
classification, and serial result delivery are inside.

Compare revisions with the same compiler, CPU affinity, workload, and repeated
alternating runs. Retain allocation counts as well as timing. These workloads
are not Internet-throughput estimates or deployment-accuracy measurements.

## Offline comparison

The optional comparison uses pinned wafw00f 2.4.2 and Linux bubblewrap network
isolation. The corpus contains 117 synthetic cases; reviewed fixture links cover
28/172 native products and 36/195 schemas. It contains no independently reviewed
real captures. These figures describe synthetic conformance, not real-world
accuracy. Never derive expected labels from either detector's output.

```sh
python3 -m venv .offlinebench-venv
.offlinebench-venv/bin/pip install -r tools/offlinebench/requirements.txt
python3 -m unittest discover -s tools/offlinebench -p '*_test.py'
go run ./cmd/offlinebench \
  -wafw00f-python "$PWD/.offlinebench-venv/bin/python" \
  -output offlinebench-results -iterations 25 -blocks 4 \
  -min-coverage 1 -min-accuracy 1
go run ./cmd/offlinebench -verify-run offlinebench-results
```

Run from the repository root with usable `bwrap` namespaces. The output directory
must be absent or empty. Gate thresholds must be finite and in `[0,1]`; product
names must map uniquely to canonical identities within each detector. Worker
input is limited to 8 MiB, including whitespace.

Verify the published generation before consuming it. Cancellation before
publication removes staging; it cannot roll back an already committed rename.
Statement coverage, synthetic conformance, cross-detector agreement, and
real-world accuracy are separate measurements.

## Historical measurements

These records are retained for context, not as performance claims about a
released v2 build. The local optimization candidates are identified here only
as working tree snapshots, not reproducible release artifacts.

### Throughput comparison

Recorded on 29 October 2026. The baseline was commit
`74a28977b9b59cc7608b69596f40632d41bf7856`; the candidate was recorded only as the
`perf-throughput` worktree. Both used Go `1.26.10-X:nodwarf5` on Linux and an Intel
Core Ultra 9 275HX. Four alternating before/after blocks used CPU affinity 0–1,
`GOMAXPROCS=2`, and 250 ms per workload. Values are medians.

| Workload | Baseline (µs/op) | Candidate (µs/op) | Time change |
| --- | ---: | ---: | ---: |
| Full-catalogue synthetic corpus | 8.124 | 8.380 | +3.1% |
| 32 KiB diverse ASCII classification | 93.150 | 91.880 | −1.4% |
| 256 KiB ASCII classification | 275.909 | 247.583 | −10.3% |
| 512 KiB prefix-heavy HTML classification | 5,475.741 | 2,228.014 | −59.3% |
| 32 KiB malformed UTF-8 classification | 91.695 | 97.202 | +6.0% |
| Full HTTP target, nine 32 KiB responses | 1,071.443 | 916.496 | −14.5% |
| Full HTTP target, nine gzip responses | 1,200.385 | 1,282.001 | +6.8% |
| Full TLS target, nine small responses | 5,836.989 | 2,896.145 | −50.4% |
| Full TLS target, nine 32 KiB responses | 6,706.839 | 3,825.046 | −43.0% |

The full HTTP 32 KiB workload allocated 29.5% fewer bytes. TLS session resumption
retained fresh HTTP/1 connections and certificate verification, but increased
allocation counts by approximately 12–13%; small-response allocated bytes rose
about 11%. Short samples and single-host timing do not establish small
differences as statistically significant or predict Internet performance.

Owned-loopback CLI scenarios used CPU affinity 0–3 and `GOMAXPROCS=4`. Values are
medians of three runs except the single-observation probe-scheduling rows:

| CLI scenario | Baseline | Candidate |
| --- | ---: | ---: |
| Other-origin wait behind a paced origin | 450.6 ms | 1.0 ms |
| Fast mode, three 50 ms responses | 159.4 ms | 60.0 ms |
| Full mode, nine 50 ms responses; candidate uses `--probe-concurrency=4` | 468.4 ms | 163.6 ms |
| 64 targets, 10 ms responses, `--concurrency=64`, default connection setting | 53.5 ms | 35.8 ms |
| 1,000 ordered offline captures, 32 KiB bodies, four workers | 196.6 ms | 99.6 ms |

The full-mode comparison changes probe concurrency; it is not a default-mode
speedup. For 2,000 disk-backed journal records, the candidate's per-record sync
took 2.15–11.53 seconds across three runs, compared with 0.093–0.406 seconds at
batch size 32. These are storage-dependent ranges, not portable speedup claims.
Batching preserves sync-before-output; see [journal durability](operations.md#reports-and-durable-journals).

### Hardening comparison

Recorded on 29 October 2026 using Go 1.27.3, Linux, an Intel Core Ultra 9 275HX,
CPU affinity 0–1, and `GOMAXPROCS=2`. Six paired blocks alternated execution order,
with 200 ms per workload and the same catalogue, fixtures, and probe counts.
The baseline was a saved pre-audit working tree and the candidate an integrated
hardening snapshot, not the published v1.0.0 release. No immutable snapshot
identities are specified here. Values are medians.

| Workload | Baseline (µs/op) | Candidate (µs/op) | Less time |
| --- | ---: | ---: | ---: |
| Full-catalogue corpus classification | 7.723 | 7.484 | 3.1% |
| 256 KiB ASCII classification | 329.693 | 273.305 | 17.1% |
| Full HTTP target, nine 32 KiB responses | 1,105.651 | 980.936 | 11.3% |

The corpus row cycles through 117 synthetic captures. Acquisition includes nine
probes, classification, and result delivery with four workers and fresh HTTP/1
connections. Small-response changes across the acquisition matrix ranged from
about 1.4% faster to 3.5% slower; these selected rows do not establish a universal
speedup.

### 1,000-target network runs

No build, toolchain, or run date is specified for this table. Treat it as
historical observations only, not as a benchmark of a supported release. Named
and generic columns count targets, not distinct products, and may overlap.

| Workers / processes | Tool | Mode | Elapsed | Named | Generic |
| --- | --- | --- | ---: | ---: | ---: |
| 1 | wafme0w | Fast | 19m 10.43s | 359 | 180 |
| 1 | wafme0w | Full | 30m 2.91s | 354 | 206 |
| 1 | wafw00f | — | 47m 3.94s | 354 | 166 |
| 10 | wafme0w | Fast | 3m 39.69s | 358 | 178 |
| 10 | wafme0w | Full | 2m 49.17s | 355 | 207 |
| 10 | wafw00f | — | 9m 31.50s | 353 | 167 |
| 50 | wafme0w | Fast | 52.33s | 358 | 176 |
| 50 | wafme0w | Full | 1m 19.59s | 357 | 205 |
| 50 | wafw00f | — | 4m 1.22s | 351 | 162 |

