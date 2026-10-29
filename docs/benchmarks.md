# Benchmarks and detector validation

[Quick start](../README.md) · [Operational checks](operations.md)

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

### Saved runs · 1,000 targets

These tables summarize previously saved runs with corrected detection counts; they are not a fresh benchmark of this checkout. “WAFs found” counts targets with named detections, not distinct WAF products. Named and generic detections can overlap.

#### Parallelism: 1

| Tool | Mode / parallelism | Time elapsed | WAFs found | Generic WAFs found | Diff¹ |
| --- | --- | ---: | ---: | ---: | ---: |
| **wafme0w** | Fast, 1 worker | 19min 10.43s | 359 | 180 | 0% |
| **wafme0w** | Full, 1 worker | 30min 2.91s | 354 | 206 | +56.7% |
| wafw00f | 1 process | 47min 3.94s | 354 | 166 | +145.5% |

#### Parallelism: 10

| Tool | Mode / parallelism | Time elapsed | WAFs found | Generic WAFs found | Diff¹ |
| --- | --- | ---: | ---: | ---: | ---: |
| **wafme0w** | Fast, 10 workers | 3min 39.69s | 358 | 178 | 0% |
| **wafme0w** | Full, 10 workers | 2min 49.17s | 355 | 207 | −23.0% |
| wafw00f | 10 processes | 9min 31.50s | 353 | 167 | +160.1% |

#### Parallelism: 50

| Tool | Mode / parallelism | Time elapsed | WAFs found | Generic WAFs found | Diff¹ |
| --- | --- | ---: | ---: | ---: | ---: |
| **wafme0w** | Fast, 50 workers | 52.33s | 358 | 176 | 0% |
| **wafme0w** | Full, 50 workers | 1min 19.59s | 357 | 205 | +52.1% |
| wafw00f | 50 processes | 4min 1.22s | 351 | 162 | +361.0% |

¹ Elapsed-time difference from wafme0w fast mode at the same parallelism; negative
values mean less elapsed time. These historical results are not current accuracy
or performance claims.
