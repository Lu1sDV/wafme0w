# Security policy

## Report a vulnerability privately

Do not put vulnerability details, exploit payloads, credentials, private targets,
or unsanitized captures in public issues or pull requests.

If GitHub displays **Report a vulnerability** in this repository's **Security**
tab, use that private form.

If the private form is unavailable, open a public issue titled **Private security
contact requested** with only a request for the maintainer's preferred private
contact channel. Include no details of the suspected vulnerability. Wait for
that channel before sharing the report.

Once a private channel is established, a useful report includes:

- The affected release or source commit, installation method, and `--version`
  output; include the binary/archive hash when available.
- OS, architecture, relevant configuration, and whether the behavior requires
  live HTTP acquisition, offline input, browser capture, or report handling.
- The impact and a minimal reproduction using synthetic data or an owned
  loopback fixture, with expected and observed behavior.
- Any known affected/fixed versions, a proposed fix if available, and whether
  the report contains information that needs further sanitization.

A routine false positive or missing fingerprint can use the public fingerprint
issue form after sanitization. A defect that exposes data, executes untrusted
content, violates an enforced boundary, or compromises users belongs in the
private reporting process above.

## Versions and fixes

Security fixes are developed on `main` and distributed in newly validated
releases. There is no blanket promise of backports to older tags; release notes
and published advisories identify affected and fixed versions. A source fix
does not repair previously downloaded binaries.

The v1.0.0 archives predate the dependency and toolchain hardening in the current
source tree. Do not treat those archives as patched artifacts. Follow the
[release and security maintenance guidance](docs/releases.md) and check the
specific release's validation evidence before deployment.

## Testing and deployment boundaries

Investigate against saved responses or systems you own or are explicitly
authorized to assess. Use synthetic reproductions wherever possible and retain
the authorization and sanitization provenance for any real captures.

Fingerprint matches are advisory evidence. A hosted service accepting arbitrary
targets needs independent egress/DNS/IP controls and job/resource isolation;
the CLI's URL checks and browser CDP interception are not that boundary.
Review [operations](docs/operations.md#deployment-boundaries) and
[browser limits](docs/browser.md#scope-and-isolation) before deployment.
