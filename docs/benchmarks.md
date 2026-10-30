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

The reported `wafw00f_over_wafmeow_latency_ratio` is the median of the per-case
wafw00f/wafmeow ratios, using each case's median **saved-response classification
latency** across blocks. Only paired, expected-complete, conformant cases in the
shared-product profile contribute. The comparison times warm named-product
classification, excluding generic detection, live DNS/HTTP work, initialization
and preparation. It is not a number of Internet hosts per minute. Keep the
full-native-catalogue profile distinct and retain the bootstrap interval and
paired-case count. Do not substitute this ratio for a live CLI speedup.

## Live CLI comparison

The **2,000-target run completed on 30 October 2026** measured every configuration
in three complete blocks and reports median elapsed time with its observed
per-block range. It used the first 2,000 ranked domains of
[Tranco ZJ8PG, 28 October 2026](https://tranco-list.eu/list/ZJ8PG/1000000) as HTTPS
root URLs, scanned under explicit authorization, and stock wafw00f 2.4.2. This
run predates HTTP/1 connection reuse
([ADR 0002](../adrs/0002-http1-connection-reuse-for-probes.md)); the same-day
reused-connection comparison is below.

### Wall-clock results

Times are **medians of three runs**; parentheses show the shortest–longest run.
Lower is better. Concurrency means target workers for wafmeow and separate CLI
processes for wafw00f.

| Workers / processes | wafw00f 2.4.2 | <img src="../assets/wafmeow.svg" width="20" height="20" alt=""> wafmeow fast | <img src="../assets/wafmeow.svg" width="20" height="20" alt=""> wafmeow full |
| ---: | ---: | ---: | ---: |
| 1 | 70m 27s (67m 27s–73m 44s) | 29m 29s (28m 54s–30m 15s) | 78m 05s (75m 17s–79m 18s) |
| 5 | 15m 26s (15m 09s–16m 16s) | 7m 27s (7m 26s–7m 32s) | 14m 30s (14m 21s–14m 40s) |
| 10 | 7m 46s (6m 52s–8m 14s) | 3m 48s (3m 46s–3m 51s) | 7m 18s (7m 10s–7m 28s) |
| 50 | 3m 45s (3m 43s–3m 51s) | 49s (49s–50s) | 1m 40s (1m 39s–1m 46s) |
| 100 | 2m 45s (1m 40s–2m 50s) | 28s (27s–28s) | 1m 02s (54s–1m 05s) |

#### Elapsed-time ratios

Each recorded ratio divides wafw00f's median elapsed time by wafmeow's for the
same concurrency. **Above 1 favors wafmeow; below 1 favors wafw00f.**

| Workers / processes | <img src="../assets/wafmeow.svg" width="20" height="20" alt=""> wafmeow fast | <img src="../assets/wafmeow.svg" width="20" height="20" alt=""> wafmeow full |
| ---: | ---: | ---: |
| 1 | 2.39× | 0.90× |
| 5 | 2.07× | 1.06× |
| 10 | 2.04× | 1.07× |
| 50 | 4.55× | 2.24× |
| 100 | 5.90× | 2.66× |

Fast mode's largest observed time advantage was at 100 workers; full mode was
slower than wafw00f at one worker. All 45 measured runs exited 0 without a
watchdog kill, and no completed run was repeated to replace an inconvenient
value. Different probe sets, TLS policies, evidence completeness and network
state prevent reading these ratios as equivalent-work speedups.

### Result accounting

Counts are **targets**, not fingerprint matches, distinct products, or HTTP
requests. Native named and generic detections may overlap and may coexist with
incomplete evidence. Each figure is the range across the three blocks when the
blocks differ.

| Workers / processes | Tool and mode | Returned | Named | Generic | Complete | Incomplete |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | wafmeow fast | 2000 | 858–862 | 433–434 | 1390–1415 | 585–610 |
| 1 | wafmeow full | 2000 | 864–868 | 511–515 | 1442–1452 | 548–558 |
| 1 | wafw00f 2.4.2 | 1542–1544 | 855–857 | 426–428 | — | — |
| 5 | wafmeow fast | 2000 | 856–862 | 409–433 | 1431–1437 | 563–569 |
| 5 | wafmeow full | 2000 | 863–865 | 477–512 | 1448–1450 | 550–552 |
| 5 | wafw00f 2.4.2 | 1539–1541 | 854–856 | 416–424 | — | — |
| 10 | wafmeow fast | 2000 | 857–860 | 425–431 | 1446–1454 | 546–554 |
| 10 | wafmeow full | 2000 | 863–864 | 506–513 | 1436–1452 | 548–564 |
| 10 | wafw00f 2.4.2 | 1539–1541 | 853–857 | 415–420 | — | — |
| 50 | wafmeow fast | 2000 | 858–860 | 427–432 | 1449–1455 | 545–551 |
| 50 | wafmeow full | 2000 | 861–863 | 502–507 | 1433–1446 | 554–567 |
| 50 | wafw00f 2.4.2 | 1537–1538 | 851–856 | 414–422 | — | — |
| 100 | wafmeow fast | 2000 | 853–858 | 424–430 | 1437–1460 | 540–563 |
| 100 | wafmeow full | 2000 | 845–852 | 492–504 | 1368–1410 | 590–632 |
| 100 | wafw00f 2.4.2 | 1534–1545 | 856–858 | 411–423 | — | — |

`complete` describes the evidence supplied to the native classifier, not WAF
absence or active enforcement. wafw00f does not report equivalent completion
states; its unreturned targets remain unknown despite successful process exits.
Fast mode's completeness stayed near 1,440 targets at every concurrency, while
full mode at 100 workers fell to 1,368–1,410 complete with 590–632 incomplete.
Higher concurrency can therefore change evidence completeness, so shorter wall
time alone does not establish equal completed work or unchanged detection
behavior.

### Build and input identity

| Component | Recorded identity |
| --- | --- |
| wafmeow (built as `wafme0w` at that commit) | Commit `836252b`, Go `1.26.10-X:nodwarf5`, `vcs.modified=false` |
| wafw00f | Unmodified 2.4.2, Python 3.14.8; 189 package files matched the installation manifest |
| Targets | First 2,000 ranked domains of [Tranco ZJ8PG, 28 October 2026](https://tranco-list.eu/list/ZJ8PG/1000000), as HTTPS root URLs |
| CPU | Intel Core Ultra 9 275HX, four allowed logical CPUs |
| RAM | 32 GB |
| OS | Linux `7.2.13-100.fc43.x86_64`, x86_64, glibc 2.42 |

`vcs.modified=false` records a clean source tree at build time. The binary hash
identifies the exact executable used for these measurements. Recorded SHA-256
identities:

- Binary: `3278f85f1a8134ef75d6181846f0841d0f8402008f90ad8a39ffab446f844319`
- Target file: `6f0633e401040fb2a5d76608952a6be8a81327c572bcafe5865f3421c09e29c6`
- Tranco list download: `c13d972cb8deb00bcada3d2087c283a067e7235e7acebd596ab21c0126cd95c5`

The comparison was explicitly authorized for this run. A public target list is
not permission to scan its entries.

### Method and limitations

- Both tools used a 3-second request timeout, disabled redirects, and cleared
  inherited proxy settings. Unreachable targets were retained, not replaced.
- wafmeow used fast mode or default serial-probe full mode. Target workers and the
  global connection cap equalled the table's concurrency, probe concurrency was
  one, and the target deadline was 30 seconds. The target request budget was 54
  and the decoded-body limit 1 MiB. TLS verification remained enabled; browser
  capture and journaling were off.
- wafw00f used `--findall`. At concurrency N, N stock CLI processes consumed
  round-robin static shards, rather than starting a new process per target. Its
  connect/read timeout semantics differ; it uses a 100 KiB body-read threshold
  and disables certificate verification. Probe sets and headers also differ.
- Cells ran sequentially and never overlapped, on the same four allowed logical
  CPUs with native `GOMAXPROCS=4`. Three blocks rotated tool order as
  fast/full/wafw00f, then wafw00f/fast/full, then full/wafw00f/fast; within each
  block the concurrency order was 100, 50, 10, 5, and 1.
- Timing covered process start through final output flush, excluding compilation
  and shard partitioning. Each cell had a 7,200-second watchdog. One one-worker
  full attempt was interrupted after 96 records by a harness session loss; its
  partial output was excluded and the cell re-ran to completion. No cell was
  killed by the watchdog, and no completed cell was retried or re-rolled.
- One one-worker upstream cell exited 0 after attempting 1,998 of 2,000 inputs:
  `karnataka.gov.in` and `pinimg.com` were never attempted. Its median timing is
  published with that skip recorded, not read as a clean negative.
- Network/DNS state, load, and responses changed between cells. Differences in
  named matches are not detection-accuracy evidence.

Raw captures, build manifests, process logs, and verification artifacts are not
distributed with the repository. The tables and recorded identities above are
the published measurement record.

### Reproduce an authorized comparison

Use an independently authorized target file and retain every attempted target,
process exit status, command, build identity, and raw output. Clear inherited
proxy settings and use the same CPU affinity for both tools.

```sh
# Choose 1, 5, 10, 50, or 100; add --fast for the fast-mode configuration.
N=10
GOMAXPROCS=4 ./wafmeow --input targets.txt --jsonl --silent --no-colors \
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

### A new 2,000-target run

Freeze the Tranco list ID/date and its first 2,000 ranked rows, then restrict the
actual scan input to authorized hosts. Retain the original selection, exclusions
and final target-file hash; if the admitted input has fewer than 2,000 targets,
report that actual count. Tranco ranks sites; it does not grant testing
permission.

Hold the build, input, environment, timeouts, limits, TLS policy, block count and
accounting method fixed, and retain the records described above with the results.
A replacement run must publish median elapsed time and spread per configuration,
per-block returned and complete counts with their range, and the ratio of the two
tools' medians, keeping fast and full separate and including cells where wafmeow
is slower. A rate or “hosts in under a minute” claim must also say how many
targets returned usable evidence.

## Connection reuse comparison

Recorded on 30 October 2026. The owned transport reuses verified HTTP/1
connections between a target's probes and counts transparent retries against the
request budget and pacing
([ADR 0002](../adrs/0002-http1-connection-reuse-for-probes.md)). The 2,000-target
run above predates this change. Every cell ran on four allowed logical CPUs with
`GOMAXPROCS=4`, a 3-second request timeout, redirects disabled and inherited
proxy settings cleared. wafmeow cells used `--concurrency` equal to the
configured workers, `--probe-concurrency=1`, a 30-second target deadline, a
54-request budget and a 1 MiB decoded-body limit, and verified TLS. Stock
wafw00f 2.4.2 used `--findall`, `-r`, `-T 3` and did not verify certificates.
The 500- and 100-target cells ran sequentially and alternated tool order; the
paired and scaling runs below state their concurrency explicitly.

### 500-target blocks

Input: the first 500 ranked domains of the authorized Tranco sample, as HTTPS
root URLs. Block A ran wafmeow and then wafw00f; block B reversed the order.

| Configuration | Block A | Block B | Median | Returned | Named | Generic | Complete |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| wafmeow full, reused connections | 587.5 s | 574.3 s | 580.9 s | 500/500 | 156–158 | 102–104 | 317–318 |
| wafw00f 2.4.2 | 872.8 s | 876.3 s | 874.6 s | 342–343/500 | 152–156 | 88 | Not reported |

wafw00f returned multiple records for some targets; **Returned** counts unique
URLs. At the medians, wafw00f took **1.51×** as long while omitting 157–158 of
the 500 inputs. Per-target completion timing from block B shows where the
reused-connection time goes: the 324 targets with nine observations consumed
485.3 s (median 1.03 s), while the 176 targets whose first request failed
consumed 89.0 s (median 0.04 s; a few reached the 3-second request timeout).

### One target worker, 100-target alternating blocks

Input: the first 100 entries of the authorized 500-target Tranco sample, as HTTPS
root URLs. Two observations per wafmeow configuration and three for wafw00f,
collected in alternating blocks.

| Configuration | Observations | Median | Range | Returned | Named | Generic |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| wafmeow full, fresh connections (before) | 2 | 173.4 s | 160.4–186.4 s | 100/100 | 21–22 | 14–15 |
| wafmeow full, reused connections (after) | 2 | 96.4 s | 95.3–97.4 s | 100/100 | 21 | 15 |
| wafw00f 2.4.2 | 3 | 143.3 s | 130.7–146.6 s | 72–73/100 | 21 | 14–15 |

Reuse reduced the wafmeow median by 44% relative to the fresh-connection cells.
The wafw00f median was 1.49× the reused-connection median. A paired run on ranks
101–200 executed both builds simultaneously against the same hosts, isolating
transport reuse from network drift: **198.1 s fresh versus 119.7 s reused**
(1.66×), under mutual load. wafw00f emits no record for targets whose initial
request fails; wafmeow returns every input with an explicit incomplete or failed
result. Named and generic counts are saved-output tallies on this sample, not
accuracy measurements.

### Scaling check

Single observations on disjoint 200-target slices (ranks 501–700 and 701–900 of
the authorized list), with each pair run in parallel on separate CPU sets.

| Workers / processes | Targets | wafmeow full (reuse) | wafw00f 2.4.2 | Ratio |
| ---: | ---: | ---: | ---: | ---: |
| 10 | 200 | 33.5 s | 102.3 s | 3.05× |
| 50 | 200 | 17.1 s | 20.0 s | 1.17× |

wafw00f returned 147–149 of 200 targets in these cells; wafmeow returned all 200.
The two rows use different target slices, so they are not a concurrency-scaling
curve.

### Controlled loopback acquisition

Owned HTTP/TLS loopback fixtures, full catalogue, four workers, 200 iterations per
count and three counts per configuration. The baseline is commit `d518b19`; the
reuse column is that tree plus the initial connection-reuse implementation,
before the retry write guard and cancellation-evidence review fixes. These
historical measurements have not been rerun for those fixes.

| Workload | Fresh (µs/op) | Reused (µs/op) | Change | Connections/target |
| --- | ---: | ---: | ---: | ---: |
| HTTP, small bodies | 350.4 | 168.2 | 2.08× faster | 9.00 → 1.54–1.85 |
| HTTP, 32 KiB bodies | 566.1 | 343.1 | 1.65× faster | 9.00 → 0.82–1.10 |
| TLS, small bodies | 1,683.5 | 477.2 | 3.53× faster | 9.00 → 2.01–2.06 |
| TLS, 32 KiB bodies | 1,997.1 | 665.3 | 3.00× faster | 9.00 → 1.59–1.73 |

Median allocations fell from 10,557 to 3,595 per TLS small-body target and from
2,064 to 1,648 per HTTP small-body target; allocated bytes fell from 1,482,862 to
442,590 B/op and from 239,081 to 148,053 B/op. Connections per target above one
reflect the four-worker pool on one fixture host; a scan of distinct origins
reuses one connection per target sequence.

### Limitations

- Live timings are single-host observations under shifting network and DNS state.
  The 100-target cells alternated tools; 500-target blocks are reported as
  observed rather than averaged across a single tool order.
- wafw00f and wafmeow issue different probe sets and body limits, apply different
  TLS policies, and do not return equivalent completion states. Counts are target
  outputs, not requests or accuracy.
- The loopback matrix isolates acquisition and classification on owned fixtures;
  it is not an Internet-throughput estimate.
- Reused connections change the connection-level request pattern. Reviewed
  captures and live comparisons remain the evidence for detection behavior.

## Local performance benchmarks

Run from the repository root:

```sh
go test ./internal/offlinebench -run '^$' \
  -bench 'BenchmarkClassify(Evidence|SingleBody|SmallCatalogue|UnguardedContent)$' -benchmem
go test ./pkg/wafmeow -run '^$' -bench '^BenchmarkAcquisitionPipeline$' -benchmem
```

The acquisition matrix uses owned HTTP/TLS loopback fixtures, four workers, and
the full catalogue. Baseline/full modes perform exactly one/nine probes over
reused HTTP/1 connections per target. Bodies cover small HTML, 32 KiB HTML, and
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
names must map uniquely to canonical identities within each detector. The
manifest is limited to 8 MiB and each body to 1 MiB. All referenced body bytes
together must fit within 4 MiB; repeated references count again because worker
JSON expands each response. Hash-verified repeated bodies share immutable
storage during loading. Split larger corpora into separate runs. These limits
are checked before workers start, and input-limit errors abort the run. The
coordinator also checks the complete encoded worker request against a separate
8 MiB limit before starting isolation or either detector. Base64 body encoding
and JSON string escaping count toward this limit, so a manifest and its bodies
can each pass their own limits while their combined request requires splitting
the corpus. Both adapters enforce the same 8 MiB byte limit, including trailing
whitespace, before decoding their input. The whole-run timeout includes corpus
loading, and manifest/body inputs must be regular files.

Manifest structure is checked before allocating typed records: arrays hold at
most 4,096 entries, narrowed to 64 responses per case and 256 headers per
response. Objects hold at most 64 fields, nesting is limited to 16 levels, and
the complete manifest holds at most 65,536 JSON values. The total-value limit
also bounds collections spread across otherwise valid cases.

Verify the published generation before consuming it. Cancellation before
publication removes staging; it cannot roll back an already committed rename.
Statement coverage, synthetic conformance, cross-detector agreement, and
real-world accuracy are separate measurements.

Schema 3 generations saved before the project rename remain verifiable with
their original `wafme0w` source and tool identities. Verification preserves the
saved manifest and artifact bytes and rejects mixed old/new native identities.
New runs use `wafmeow` identities.

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
| 1 | wafmeow | Fast | 19m 10.43s | 359 | 180 |
| 1 | wafmeow | Full | 30m 2.91s | 354 | 206 |
| 1 | wafw00f | — | 47m 3.94s | 354 | 166 |
| 10 | wafmeow | Fast | 3m 39.69s | 358 | 178 |
| 10 | wafmeow | Full | 2m 49.17s | 355 | 207 |
| 10 | wafw00f | — | 9m 31.50s | 353 | 167 |
| 50 | wafmeow | Fast | 52.33s | 358 | 176 |
| 50 | wafmeow | Full | 1m 19.59s | 357 | 205 |
| 50 | wafw00f | — | 4m 1.22s | 351 | 162 |

