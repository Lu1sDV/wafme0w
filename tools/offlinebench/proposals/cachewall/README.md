# CacheWall catalogue proposal

**Status: pending human evidence review.** This directory prepares the proposed
rule change and its synthetic controls for a maintainer to review. The embedded
catalogue, comparison corpus, coverage identities, and reviewed status are
unchanged. These files are selected explicitly by the commands below; the normal
CLI and benchmark do not load them.

## Problem and proposed rule

The inherited CacheWall OR schema accepts `X-Varnish`, `Server: Varnish`, or the
body phrase `Varnish cache server` independently. Those signals occur in vanilla
Varnish and cannot establish the CacheWall product identity.

Official Varnish source at commit
[`0038dd19804fd92cd8bd4bfe92e5a515a57d5e8e`](https://github.com/varnishcache/varnish-cache/tree/0038dd19804fd92cd8bd4bfe92e5a515a57d5e8e)
adds `X-Varnish` during [normal delivery](https://github.com/varnishcache/varnish-cache/blob/0038dd19804fd92cd8bd4bfe92e5a515a57d5e8e/bin/varnishd/cache/cache_req_fsm.c#L157),
sets `Server: Varnish` on [synthetic responses](https://github.com/varnishcache/varnish-cache/blob/0038dd19804fd92cd8bd4bfe92e5a515a57d5e8e/bin/varnishd/cache/cache_req_fsm.c#L196),
and includes the body phrase in its [built-in error page](https://github.com/varnishcache/varnish-cache/blob/0038dd19804fd92cd8bd4bfe92e5a515a57d5e8e/bin/varnishd/builtin.vcl#L202).

[catalogue.json](catalogue.json) contains one proposed replacement product entry:
remove those three generic alternatives and retain the four existing alternatives
for the CacheWall action/reason headers and distinctive page text. Their original
definitions are present in the [upstream CacheWall plugin](https://github.com/EnableSecurity/wafw00f/blob/e81d38748109a805872ee92fd2377612bd639b3b/wafw00f/plugins/cachewall.py)
at the commit resolved from wafw00f v2.4.2. The upstream plugin has the same broad
Varnish alternatives; this proposal deliberately changes inherited behavior.

## Proposed controls

[captures.jsonl](captures.jsonl) contains synthetic complete observations created
for this proposal. It contains no collected site responses or live targets. The
expected outcomes below were chosen from the source distinction above, before
running the detector. A passing synthetic control does not establish real-world
product attribution or constitute the required human review.

| Target label | Evidence under review | Expected CacheWall match |
| --- | --- | --- |
| `cachewall-action` | `X-Cachewall-Action: deny` | Yes |
| `cachewall-reason` | `X-Cachewall-Reason: request policy` | Yes |
| `cachewall-branding` | `security by cachewall` | Yes |
| `cachewall-blockpage` | `403 naughty - not nice!` | Yes |
| `vanilla-varnish-delivery` | `X-Varnish: 1` | No |
| `vanilla-varnish-server` | `Server: Varnish` | No |
| `vanilla-varnish-error-page` | `Varnish cache server` | No |

The first four cases preserve existing product-specific alternatives. A human
reviewer should assess their specificity and supply independent product evidence
where needed. The final three are meaningful negatives grounded in the vanilla
Varnish implementation.

## Reproduce offline

Run from the repository root. Both commands classify only saved synthetic data.
The first uses the current embedded catalogue; it currently attributes all seven
observations to CacheWall. The second uses the proposed entry and should match
only the four `cachewall-*` observations.

```sh
go run ./cmd/wafmeow \
  --evidence tools/offlinebench/proposals/cachewall/captures.jsonl \
  --jsonl --silent

go run ./cmd/wafmeow \
  --fingerprints tools/offlinebench/proposals/cachewall/catalogue.json \
  --evidence tools/offlinebench/proposals/cachewall/captures.jsonl \
  --jsonl --silent --strict
```

## Acceptance work

`AGENTS.md` and the coverage-contract policy require human-reviewed positive and
negative fixture links before a catalogue change is accepted. A follow-up rule
change must record the review rationale, add the approved fixtures to the corpus,
update their identities and the changed rule identity, and review expectations
for both adapters independently. No human review or coverage approval is claimed
by this proposal. Do not mark the changed rule `baseline-untested` or generate
expected labels from detector output to satisfy the gate.
