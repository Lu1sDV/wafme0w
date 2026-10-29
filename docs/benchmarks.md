# Benchmarks and detector validation

[Quick start](../README.md) · [Operational checks](operations.md)

## Current hardening measurements · 29 October 2026

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
