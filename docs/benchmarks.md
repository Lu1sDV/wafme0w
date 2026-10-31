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

## 600-target VPS comparison

Recorded 30–31 October 2026. This run measured a reproducible 600-target sample
on a dedicated Debian 13 VPS rather than a laptop, with three complete blocks
per configuration. It is the primary live CLI comparison; the older 2,000-target
laptop run is retained below as historical evidence.

### Target selection

- Source: [Tranco ZJ8PG, 28 October 2026](https://tranco-list.eu/list/ZJ8PG/1000000),
  top 10,000 ranked domains.
- Selection: deterministic shuffles with seed `20261030` for the non-CDN set and
  seed `20261031` for the CDN set. Candidates were resolved and checked for
  known CDN fronting by CNAME suffix and ASN. Non-CDN candidates were fetched
  over HTTPS and then HTTP; any response below status 600 counted as alive. The
  first set discarded dead and known-CDN candidates; the second required known
  CDN fronting. Both discarded dead candidates and continued until 500 non-CDN
  and 100 CDN targets remained, then combined and sorted by Tranco rank.
- Result: 600 unique targets (571 HTTPS, 29 HTTP), Tranco ranks 31–9,978, all
  alive at selection. The target-file SHA-256 is
  `fbd8a3bbdd5903b7d53ab6f2ffe95c37b900f5728abb76b38ce7508863c09cf5`.
- The 100 CDN targets include Cloudflare, Amazon, Microsoft, Fastly and Google
  edge ASNs, so the sample measures detection on shared edge infrastructure
  without allowing CDN hosts to dominate the set. CDN classification is a
  heuristic, not an exhaustive inventory of every CDN.
- Scanning was explicitly requested for this benchmark. A public target list is
  not permission to scan its entries.

### Measurement setup

- Host: Hetzner Online GmbH vServer (AS24940), Helsinki, Finland; KVM
  virtualization. Debian GNU/Linux 13 (trixie), Linux
  `6.12.101+deb13-cloud-amd64`, x86-64.
- CPU: AMD EPYC-Rome, four vCPUs, one socket/four cores, one thread per core,
  reported at 2,495 MHz; 16 MiB L3 cache, 2 MiB L2 per core. `GOMAXPROCS=4`;
  inherited proxy variables cleared.
- Memory and storage: 7.6 GiB RAM, 2 GiB swap, 76.3 GB QEMU virtual disk.
  A 512 MiB `fdatasync` write measured about 1.5 GB/s; cached read measured
  about 8.0 GB/s.
- Network: Speedtest CLI against FDCservers Vienna (server 6070) measured
  **1.17 Gbit/s download, 392 Mbit/s upload and 41.5 ms latency** after the run.
  ICMP to `1.1.1.1` averaged 1.51 ms over four probes. These are shared virtual
  host measurements, not guaranteed bandwidth; the benchmark traffic is mostly
  many short TLS/HTTP exchanges rather than bulk transfer.
- wafmeow: commit `c12e7c5` (Go 1.26.10); only `.gitignore` was modified locally
  (`vcs.modified=true`), not application source. Binary SHA-256
  `f4cc7f61fa24f5e251688670ff6d4704eff4f8039cd3fa51d705116599db5274`.
- wafw00f: stock 2.4.2 on Python 3.13.5.
- Both tools used a 3-second request timeout and disabled redirects. wafmeow
  used verified TLS, a 30-second target deadline, a 54-request budget, a 1 MiB
  decoded-body limit, fast mode or default serial-probe full mode, target
  workers and the global connection cap equal to the table concurrency, and
  probe concurrency one. Browser capture and journaling were off.
- wafw00f used `--findall`, `-r` (no redirects), and `-T 3`. At concurrency N,
  N stock CLI processes consumed round-robin shards. It disables certificate
  verification and uses a 100 KiB body-read threshold; probe sets and headers
  differ, so detection counts are not an accuracy comparison.
- Three blocks ran sequentially. Within each block the concurrency order was
  100, 50, 10, 5, and 1; tool order rotated as fast/full/wafw00f, then
  wafw00f/fast/full, then full/wafw00f/fast. Cells never overlapped.
- Timing covered process start through final output flush, excluding compilation
  and shard partitioning. Every cell had a 3,600-second watchdog. All recorded
  cells exited zero; no cell was retried or re-rolled after a completed timer.

### Wall-clock results

Times are **medians of three runs**; parentheses show the shortest–longest run.
Lower is better.

| Workers / processes | wafw00f 2.4.2 | <img src="../assets/wafmeow.svg" width="20" height="20" alt=""> wafmeow fast | <img src="../assets/wafmeow.svg" width="20" height="20" alt=""> wafmeow full |
| ---: | ---: | ---: | ---: |
| 1 | 31m 37.6s (30m 44.7s–31m 44.4s) | 7m 49.5s (7m 34.3s–7m 54.4s) | 15m 50.5s (15m 13.1s–16m 3.1s) |
| 5 | 6m 53.3s (6m 51.4s–7m 3.8s) | 2m 18.2s (2m 18.1s–2m 22.5s) | 3m 10.3s (3m 8.6s–3m 15.5s) |
| 10 | 4m 46.8s (4m 43.1s–4m 57.6s) | 1m 15.8s (1m 15.2s–1m 17.3s) | 1m 34.8s (1m 33.6s–1m 37.2s) |
| 50 | 1m 59.4s (1m 57.8s–2m 0.2s) | 16.1s (16.0s–16.4s) | 26.6s (26.1s–29.8s) |
| 100 | 1m 52.2s (1m 51.4s–1m 56.3s) | 9.0s (9.0s–9.4s) | 21.9s (21.4s–23.7s) |

Each recorded ratio divides wafw00f's median elapsed time by wafmeow's for the
same concurrency. **Above 1 favors wafmeow; below 1 favors wafw00f.**

| Workers / processes | <img src="../assets/wafmeow.svg" width="20" height="20" alt=""> wafmeow fast | <img src="../assets/wafmeow.svg" width="20" height="20" alt=""> wafmeow full |
| ---: | ---: | ---: |
| 1 | 4.04× | 2.00× |
| 5 | 2.99× | 2.17× |
| 10 | 3.79× | 3.03× |
| 50 | 7.40× | 4.49× |
| 100 | 12.45× | 5.12× |

### Result accounting

Counts are targets, not fingerprint matches or HTTP requests. Each count is the
range across the three blocks when the blocks differ. wafw00f does not report
equivalent evidence-completion states; its unreturned targets remain unknown.

| Workers / processes | Tool and mode | Returned | Named | Generic | Complete | Incomplete |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | wafmeow fast | 600 | 154–158 | 115–123 | 519–521 | 79–81 |
| 1 | wafmeow full | 600 | 158–159 | 142–146 | 521–525 | 75–79 |
| 1 | wafw00f 2.4.2 | 580–582 | 156–157 | 122–128 | — | — |
| 5 | wafmeow fast | 600 | 157–158 | 115–123 | 524–527 | 73–76 |
| 5 | wafmeow full | 600 | 158–159 | 141–143 | 521–525 | 75–79 |
| 5 | wafw00f 2.4.2 | 578–580 | 154–157 | 121–125 | — | — |
| 10 | wafmeow fast | 600 | 154–155 | 114–116 | 522–524 | 76–78 |
| 10 | wafmeow full | 600 | 154–157 | 139–144 | 518–525 | 75–82 |
| 10 | wafw00f 2.4.2 | 577–580 | 155 | 118–126 | — | — |
| 50 | wafmeow fast | 600 | 156–159 | 115–117 | 529–531 | 69–71 |
| 50 | wafmeow full | 600 | 158 | 144 | 525–526 | 74–75 |
| 50 | wafw00f 2.4.2 | 575–578 | 154–158 | 116–126 | — | — |
| 100 | wafmeow fast | 600 | 157–158 | 118–120 | 529–531 | 69–71 |
| 100 | wafmeow full | 600 | 157–160 | 145–146 | 523–528 | 72–77 |
| 100 | wafw00f 2.4.2 | 580–581 | 155–157 | 121–126 | — | — |

For wafmeow, `complete` describes the evidence supplied to the classifier, not
WAF absence or active enforcement. At 100 workers, fast mode returned
529–531 complete targets and full mode 523–528; higher
concurrency can still change evidence completeness, so shorter wall time alone
does not establish equal completed work.

#### Interpreting the Generic WAF signal

Generic signals are target-level heuristics, not WAF product identities, and they
are not mutually exclusive with named matches. wafw00f can emit a named record
and a `Generic` record for the same target under `--findall`; the table counts
**any** Generic record, while its **Generic-only** subset at 100 workers was
66–69. At that concurrency, 55–57 wafw00f targets had both a named and generic
result. The earlier 66–69 figure was a generic-only count accidentally produced
by collapsing multiple wafw00f records per URL; it is not the total generic
signal count.

wafw00f's generic detector checks for a changed response to a missing
User-Agent, XSS, LFI or SQLi request, a changed Server header, or a
connection-level block. wafmeow's separate detector checks status and Server
changes across its probes, plus explicit WAF marker headers. Fast mode sends
three request roles; full mode sends eight, giving full mode more opportunities
to observe a status change and explaining why its generic count is higher
(145–146 versus 118–120 at 100 workers). The counts differ because the probe
sets, trigger rules, CDN targets and evidence completeness differ; they do not
rank detection accuracy or prove enforcement.

#### Named detections compared

Using the union of the three 100-worker runs, wafw00f returned 585 of the 600
targets; the other 15 are unknown, not clean misses. Of the returned targets,
156 had named matches from both wafw00f and fast mode, and 155 from both wafw00f
and full mode; wafw00f alone named
three targets against fast and four against full, while wafmeow alone named
three and five respectively. The only named product family observed by wafmeow
and not wafw00f was Reflected Networks (one full-mode target); wafw00f more often
named Instart DX. Common detections were stable: Cloudflare 53/53/53, AWS Elastic
Load Balancer 22/22/22 and CacheWall 22/22/22 (wafw00f/fast/full), with 24 named
product families observed overall. These differences are not an accuracy score:
the tools use different probe sets, product-name knowledge, TLS policies, body
limits and generic/named reporting contracts.

#### Transport and false-positive checks

Targeted checks of the named differences found:

- `centurytel.net` serves a certificate for `*.imds.tv`, not the requested host.
  Verified TLS therefore fails in wafmeow; wafw00f disables verification and
  receives a **400 “Invalid host”** response with `Server: nginx`, `X-Varnish`
  and `Via: 1.1 varnish`. Its CacheWall result is a Varnish cache-header match,
  not evidence of a WAF. wafmeow's TLS rejection is intentional.
- `unisa.ac.za` omits an intermediate certificate. wafmeow cannot build a
  verified chain; wafw00f disables verification and receives the F5 rejection
  page plus an `f5avra…` session cookie. BIG-IP is supported by that response.
  Instart DX also matches the same F5 rejection template (“requested URL was
  rejected… support ID”), so that second product is a **false positive**.
- `indianrail.gov.in` has a valid certificate, but this Go client receives
  `tls: handshake failure`; curl and Python requests negotiate TLS successfully.
  The target reports `Server: BigIP`; wafw00f's BIG-IP result is plausible, while
  its Instart DX result shares the same generic rejection-template weakness.
  wafmeow cannot classify this target without a transport-compatible path.
- `doubao.com`'s NetScaler result was intermittent: wafw00f found it in one of
  three blocks, wafmeow fast in two and full in none. Direct requests showed
  Tengine/Volc CDN headers and no NetScaler marker. Treat this as unstable and
  not a clean wafw00f-only miss pending a repeatable trigger.

These checks explain why the named differences are small: most are transport
incompatibility or an upstream signature collision, not a missing wafmeow
fingerprint.

### Build and input identity

| Component | Recorded identity |
| --- | --- |
| wafmeow | Commit `c12e7c5`, Go `1.26.10-X:nodwarf5`, `vcs.modified=true` (only `.gitignore`) |
| wafw00f | Unmodified 2.4.2, Python 3.13.5 |
| Targets | 600 live root URLs: 500 known-non-CDN plus 100 known-CDN, sampled from Tranco ZJ8PG top 10,000; seeds `20261030`/`20261031` |
| Target file | SHA-256 `fbd8a3bbdd5903b7d53ab6f2ffe95c37b900f5728abb76b38ce7508863c09cf5` |
| Binary | SHA-256 `f4cc7f61fa24f5e251688670ff6d4704eff4f8039cd3fa51d705116599db5274` |
| Host | Hetzner vServer, Helsinki, Finland (AS24940), KVM; Debian 13, kernel `6.12.101+deb13-cloud-amd64` |
| CPU / RAM | AMD EPYC-Rome, 4 vCPU at 2,495 MHz; 7.6 GiB RAM, 2 GiB swap |
| Storage / network | 76.3 GB QEMU disk; ~1.5 GB/s fdatasync write, ~8.0 GB/s cached read; ~1.17 Gbit/s down / ~392 Mbit/s up, 41.5 ms Speedtest server |

Raw captures, process logs and the target list are local measurement artifacts;
the tables and identities above are the published record.

### Reproduce the VPS comparison

Use an independently authorized target file and retain every attempted target,
process exit status, command, build identity and raw output. Clear inherited
proxy settings and keep the same CPU affinity for both tools.

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

Start the timer before launching processes and stop it after every process
exits. A watchdog-aborted configuration is not a completed timing. Account for
missing upstream records as unknown, never negative. Hold the input, timeouts,
limits, TLS policy, block count and accounting method fixed when comparing
builds.

## Historical 2,000-target live comparison

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
the full catalogue. Baseline/full modes perform exactly one/eight probes over
reused HTTP/1 connections per target. Bodies cover small HTML, 32 KiB HTML, and
gzip. Compilation and fixture setup are outside timing; acquisition,
classification, and serial result delivery are inside.

Compare revisions with the same compiler, CPU affinity, workload, and repeated
alternating runs. Retain allocation counts as well as timing. These workloads
are not Internet-throughput estimates or deployment-accuracy measurements.

## Offline comparison

The optional comparison uses pinned wafw00f 2.4.2 and Linux bubblewrap network
isolation. The current corpus contains 121 synthetic cases; synthetic-conformance
fixture links cover 29/172 native products and 38/195 schemas. It contains no
independently reviewed real captures. These figures describe synthetic
conformance, not real-world accuracy. Never derive expected labels from either
detector's output.

The pkSecurity cases pin the upstream Boolean structure: schema 1 accepts either
marker, while schema 2 requires all three warning terms. Their product truth is
unknown, and their provenance identifies assistant source inspection with
maintainer fixture review required before accepting the catalogue correction.
This corpus update does not revise any historical timings or detection counts.
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

