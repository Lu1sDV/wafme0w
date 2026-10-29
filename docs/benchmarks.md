# Benchmarks and detector validation

[Quick start](../README.md) · [Operational checks](operations.md)

## Live CLI comparison · 29 October 2026

### Wall-clock results

All nine cells completed with exit code 0 and no cell watchdog timeout. Each
cell attempted the same 500 targets. These are single observations of the
saved build described below, **not** a recalculation of the historical
1,000-target timings or a measurement of the newer v2/httpx-import code.

| Workers / processes | wafme0w fast | wafme0w full | wafw00f 2.4.2 |
| --- | ---: | ---: | ---: |
| 1 | 6m 49.44s | 15m 51.93s | 14m 38.21s |
| 10 | 52.89s | 1m 45.62s | 2m 53.39s |
| 50 | 24.06s | 44.26s | 1m 50.93s |

Full mode at one worker took longer than wafw00f in this sweep. The different
probe sets, TLS policies, evidence completeness and environmental state prevent
interpreting these elapsed-time ratios as equivalent-work speedups.

### Result accounting

All counts below are **targets**, not fingerprint matches, distinct products,
or HTTP requests. Complete and incomplete are native classification states;
wafw00f does not report equivalent states. Its missing records remain unknown
even though every CLI process exited successfully.

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

The native `complete` state only describes the evidence supplied to its
classifier; it is not proof of WAF absence or active enforcement. Named and
generic counts may overlap and can include incomplete native classifications.

### Scope and method

The input is the unchanged first 500 domains of
[Tranco ZJ8PG, dated 28 October 2026](https://tranco-list.eu/list/ZJ8PG/1000000),
as HTTPS root URLs. Unreachable targets are retained, not replaced.
The target-file SHA-256 is
`e74e8e65fffc1d18f5ddd82b7165641e0ad6e68f3553bcdb26df1d4f0f2a14f2`.
Active comparison at 1, 10, and 50 workers/processes was explicitly authorized
for this run; the list is not permission for others to scan these sites.

- **Native:** saved build identifying source commit `347f547`, built with Go
  `1.26.10-X:nodwarf5`; fast mode or default serial-probe full mode. The build
  reports `vcs.modified=true`, so the binary SHA-256 below identifies the actual
  measured artifact rather than asserting a pristine commit build. Target
  workers and the global connection cap both equal the table's concurrency.
- **Comparator:** unmodified wafw00f 2.4.2 on Python 3.14.8, `--findall`.
  Its installed package files were checked against its installation manifest.
  At concurrency N, N stock CLI processes consume round-robin static shards;
  they are not N fresh processes per target.
- Both use a 3-second request timeout and disabled redirects, with inherited
  proxy settings cleared. No replacement targets, browser capture, or native
  diagnostics journal. CLI startup and output writes are inside the timing;
  compilation and target partitioning are outside. One interrupted one-worker
  full scan produced 128 records without an exit status; its incomplete output
  is retained but excluded. Only that unfinished cell was restarted; completed
  cells were not repeated.
- Cells run separately, never concurrently: at 50, fast/full/wafw00f; at 10,
  wafw00f/fast/full; at 1, full/wafw00f/fast. Each tool occupies each position
  once. This is one observation per cell, not a repeated statistical benchmark.
  All processes share four allowed logical CPUs; native `GOMAXPROCS=4`.
- Native retains its 30-second target deadline, 54-request target budget,
  1 MiB decoded-body limit, and TLS verification. Upstream has different
  connect/read timeout semantics, a 100 KiB body-read threshold, and disables
  certificate verification. Probe sets and headers also differ. These are
  observed CLI wall times, not equivalent-request or isolated matcher timings.

The measured binary SHA-256 is
`442595cffd0801d38c5849c855ee8daa33e1120a88168022f137e8c34b83ec5f`.
It was kept unchanged across the interruption and resume. The checkout later
advanced to the v2/httpx-import changes; those changes are **not** measured by
this saved binary.

For an independently authorized target file, the native cell's command is:

```sh
# N is 1, 10, or 50; add --fast for the fast-mode cell.
./wafme0w --input targets.txt --jsonl --silent --no-colors \
  --concurrency="$N" --max-connections="$N" --probe-concurrency=1 \
  --request-timeout=3s --target-timeout=30s --max-requests=54 \
  --max-body-bytes=1048576 --redirect-policy=none --max-redirects=0
```

For wafw00f, divide the same input into N round-robin shards and run N copies
of the following stock command concurrently, one per shard, waiting for every
process before stopping the cell timer:

```sh
python -m wafw00f.main -i shard.txt -a -r -T 3 --no-colors \
  -f json -o shard.json
```

Use the same CPU affinity for both tools, `GOMAXPROCS=4` for native, and direct
file output rather than terminal rendering. Preserve all process exit statuses
and logs; a watchdog-aborted cell is not a completed timing. Account for each
original target: a missing upstream record is unknown, not a negative result.
Network/DNS state, load, and responses can change between cells; differences
in named matches are not detection-accuracy evidence.

### Interpretation

Higher concurrency did not preserve evidence completeness. Fast mode at 50
workers produced 206 complete classifications, versus 318 at 10 workers;
161 versus 29 targets had a `deadline_exceeded` diagnostic. These are observed
associations, not a controlled attribution to worker count. Shorter wall time
alone must not be read as equal completed work or unchanged detection behavior.
Named and generic detections can overlap, and either may coexist with incomplete
evidence. Upstream does not record the native three-valued completion state.

### Retained evidence

Local raw artifacts are under the ignored directory
`benchmarks/live-refresh-20261029-347f547-dn8436yx/`: target selection, binary,
build/dependency manifest, commands, process timestamps/statuses, raw records,
upstream logs, per-cell SHA-256 identities, and interruption metadata.
`verify.py` checked input/output identities, all 500 attempted targets per cell,
native uniqueness and settings, upstream missing-output accounting, elapsed
timestamps, zero exit statuses, and non-overlapping cell intervals. It published
`verification.json`; six saved-output comparisons retain common-target product
set disagreements without treating either tool's labels as ground truth.
No network requests or replacement scans are performed by that verifier.
These local artifacts are not committed; the tables and identities above are
the published measurement record.

## Throughput follow-up · 29 October 2026

This comparison uses commit `74a28977b9b59cc7608b69596f40632d41bf7856`
as the baseline and the `perf-throughput` worktree as the changed version.
Both binaries used Go `1.26.10-X:nodwarf5`, Linux, and the same Intel Core Ultra
9 275HX. These results are separate from the earlier hardening measurements below.

Four alternating before/after benchmark blocks used CPU affinity 0–1,
`GOMAXPROCS=2`, and 250 ms per workload. Selected medians:

| Workload | Before (µs/op) | After (µs/op) | Time change |
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

The full HTTP 32 KiB workload allocated 29.5% fewer bytes. Single-response
classification removed one allocation; the single-body and small-catalogue
benchmarks reached zero allocations. TLS session resumption retained fresh
HTTP/1 TCP connections and certificate verification, but increased allocation
counts by approximately 12–13%; small-response allocated bytes rose about 11%.
The cache is bounded and run-local. Not every workload improved; short samples
and single-host timing do not establish small differences as statistically
significant or predict Internet performance.

Actual CLI scenarios used owned loopback servers and CPU affinity 0–3 with
`GOMAXPROCS=4`. Repeated rows below are medians of three runs; probe schedule
rows are single observations. Output counts, evidence roles and ordering were
checked, not just elapsed time.

| CLI scenario | Before | After |
| --- | ---: | ---: |
| Other-origin wait behind a paced origin | 450.6 ms | 1.0 ms |
| Fast mode, three 50 ms responses | 159.4 ms | 60.0 ms |
| Full mode, nine 50 ms responses; after uses `--probe-concurrency=4` | 468.4 ms | 163.6 ms |
| 64 targets, 10 ms responses, `--concurrency=64`, default connection setting | 53.5 ms | 35.8 ms |
| 1,000 ordered offline captures, 32 KiB bodies, four workers | 196.6 ms | 99.6 ms |

Default full mode remains serial; its observed 470.0 ms after time was similar
to baseline. The CLI's default connection setting now follows target concurrency
instead of silently capping it at 20; an explicit limit still applies.
Offline admission remains bounded by worker count and raw record bytes.

For 2,000 disk-backed journal records, the changed binary's default per-record
sync took 2.15–11.53 seconds across three runs; opt-in batch size 32 took
0.093–0.406 seconds. Storage latency varied substantially, so these are ranges,
not a portable speedup claim. Every emitted record was checked against its
journal entry. A partial batch flushed while stdin stayed open, and SIGTERM
then exited with code 130. Batching preserves sync-before-output but may lose
accepted, unflushed records on abrupt process or machine failure; it defaults
to one record. See [operations](operations.md).

The attempted combined Unicode-folding/mask loop was discarded after profiles
and comparisons showed regressions. Required regexp guards instead check the
strongest literal group first, then remaining mandatory groups, before exact
regexp confirmation. Decoder pooling was not retained because decoder state
can retain response fragments.

## Earlier hardening measurements · 29 October 2026

The table below reports selected observed medians, not projections from the
historical network runs below. “Before” is the saved
pre-audit working tree, which already contained the earlier transport/security
hardening; it is **not** the published v1.0.0 release. “Current” is the integrated
hardening and performance work in this update. This is not a release-versus-release
comparison.

| Workload | Before (µs/op) | Current (µs/op) | Less time |
| --- | ---: | ---: | ---: |
| Full-catalogue corpus classification | 7.723 | 7.484 | 3.1% |
| 256 KiB ASCII classification | 329.693 | 273.305 | 17.1% |
| Full HTTP target, nine 32 KiB responses | 1,105.651 | 980.936 | 11.3% |

Both versions used Go 1.27.3 on Linux, an Intel Core Ultra 9 275HX, CPU affinity
0–1, and `GOMAXPROCS=2`. Six paired blocks alternated before/after and after/before
order, with 200 ms per benchmark workload; the table uses medians across those
six observations. The same catalogue, fixtures and probe counts were used.
The corpus row cycles through all 117 synthetic captures with the full catalogue.
The acquisition row includes all nine probes, classification and result delivery,
with four workers and fresh HTTP/1 connections.

All 14 matcher workloads had lower observed median time. Across the 12 acquisition
workloads, small-response changes ranged from about 1.4% faster to 3.5% slower.
These measurements do not establish a universal speedup or predict Internet
latency; handshake, scheduling, target behavior and intentional safety limits
remain material. No old live-network timing has been recalculated from these gains.

## Reproduce local performance measurements

```sh
go test ./internal/offlinebench -run '^$' \
  -bench 'BenchmarkClassify(Evidence|SingleBody|SmallCatalogue|UnguardedContent)$' -benchmem
go test ./pkg/wafme0w -run '^$' -bench '^BenchmarkAcquisitionPipeline$' -benchmem
```

The acquisition matrix uses owned HTTP/TLS loopback fixtures, four workers, and
the full catalogue. Baseline/full modes must perform exactly one/nine probes and
fresh HTTP/1 connections per target. Bodies cover small HTML, 32 KiB HTML, and
gzip. Compilation and fixture setup are outside timing; acquisition, classification
and serial result delivery are inside. These are not Internet-throughput estimates.
Use the same compiler, CPU affinity, workload and repeated alternating runs when
comparing revisions. Statement coverage, synthetic conformance and timing do not
measure deployment accuracy.

## Offline comparison

The optional comparison uses pinned wafw00f 2.4.2 and Linux bubblewrap network
isolation. Its 117 reviewed cases are synthetic: 28/172 native products and
36/195 schemas have reviewed fixture links, not independently labelled real-world
accuracy. Never derive expected labels from either detector’s output.

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
input is limited to 8 MiB, including whitespace. Cancellation before generation
publication removes staging; it cannot roll back an already committed rename.
Verify the published generation before consuming it.

## Historical network runs · 1,000 targets

These tables summarize previously saved runs with corrected detection counts; they are not a fresh benchmark of this checkout. “WAFs found” counts targets with named detections, not distinct WAF products. Named and generic detections can overlap.

### Parallelism: 1

| Tool | Mode / parallelism | Time elapsed | WAFs found | Generic WAFs found | Diff¹ |
| --- | --- | ---: | ---: | ---: | ---: |
| **wafme0w** | Fast, 1 worker | 19min 10.43s | 359 | 180 | 0% |
| **wafme0w** | Full, 1 worker | 30min 2.91s | 354 | 206 | +56.7% |
| wafw00f | 1 process | 47min 3.94s | 354 | 166 | +145.5% |

### Parallelism: 10

| Tool | Mode / parallelism | Time elapsed | WAFs found | Generic WAFs found | Diff¹ |
| --- | --- | ---: | ---: | ---: | ---: |
| **wafme0w** | Fast, 10 workers | 3min 39.69s | 358 | 178 | 0% |
| **wafme0w** | Full, 10 workers | 2min 49.17s | 355 | 207 | −23.0% |
| wafw00f | 10 processes | 9min 31.50s | 353 | 167 | +160.1% |

### Parallelism: 50

| Tool | Mode / parallelism | Time elapsed | WAFs found | Generic WAFs found | Diff¹ |
| --- | --- | ---: | ---: | ---: | ---: |
| **wafme0w** | Fast, 50 workers | 52.33s | 358 | 176 | 0% |
| **wafme0w** | Full, 50 workers | 1min 19.59s | 357 | 205 | +52.1% |
| wafw00f | 50 processes | 4min 1.22s | 351 | 162 | +361.0% |

¹ Elapsed-time difference from wafme0w fast mode at the same parallelism; negative
values mean less elapsed time. These historical results are not current accuracy
or performance claims.
