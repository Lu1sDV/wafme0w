#!/usr/bin/env python3
"""Owned-loopback httpx v1.12.0 integration and Linux network-attempt smoke.

Requires built wafme0w, a separately installed pinned httpx, strace, and GNU time.
The default 5,000/50,000-record runs compare child peak RSS, not harness memory.
No targets outside the owned loopback fixture are scanned.
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tempfile
import threading
import time


class Fixture(http.server.BaseHTTPRequestHandler):
    requests: list[str] = []

    def do_GET(self):
        Fixture.requests.append(self.path)
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/marker")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("X-Fixture", "first")
        self.send_header("X-Fixture", "second")
        self.send_header("Set-Cookie", "fixture=a; Expires=Wed, 21 Oct 2037 07:28:00 GMT; Path=/")
        self.send_header("Set-Cookie", "second=b; Path=/")
        self.end_headers()
        self.wfile.write(b"fixture-body-marker")

    def log_message(self, format, *args):
        pass


def run(command, expected=0, **kwargs):
    result = subprocess.run(command, capture_output=True, timeout=120, **kwargs)
    if result.returncode != expected:
        raise AssertionError(f"exit {result.returncode}, expected {expected}: {result.stderr!r}")
    return result


def check_volume(binary, root, count):
    capture_path = root / f"volume-{count}.jsonl"
    with capture_path.open("w") as sink:
        for index in range(count):
            sink.write(json.dumps({"url": f"https://fixture.example/{index}", "status_code": 200}) + "\n")
    rss_path = root / f"volume-{count}.rss"
    command = ["/usr/bin/time", "-o", str(rss_path), "-f", "%M", binary,
               "--evidence", str(capture_path), "--evidence-format=httpx", "--jsonl", "--silent"]
    timeout = 120
    deadline = time.monotonic() + timeout
    seen, stderr_bytes, pending = 0, 0, b""
    # Drain both pipes; keep at most 64 KiB of diagnostics on disk, never all output.
    with (root / f"volume-{count}.stderr").open("w+b") as errors, \
            selectors.DefaultSelector() as selector, \
            subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True) as process:
        try:
            selector.register(process.stdout, selectors.EVENT_READ)
            selector.register(process.stderr, selectors.EVENT_READ)
            while len(selector.get_map()) != 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, 65536)
                    if chunk == b"":
                        selector.unregister(key.fileobj)
                    elif key.fileobj is process.stderr:
                        errors.write(chunk[:max(0, 65536 - stderr_bytes)])
                        stderr_bytes += len(chunk)
                    else:
                        pending += chunk
                        while b"\n" in pending:
                            line, pending = pending.split(b"\n", 1)
                            record = json.loads(line)
                            assert seen < count, f"unexpected extra record {seen}"
                            assert record["target"] == f"https://fixture.example/{seen}"
                            assert record["outcome"]["state"] == "incomplete"
                            assert record["outcome"].get("matches", []) == []
                            seen += 1
                        # A broken child must not grow the harness with an unterminated line.
                        assert len(pending) <= 1048576, "volume output line exceeds 1 MiB"
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            code = process.wait(timeout=remaining)
            errors.seek(0)
            assert code == 0, f"exit {code}, expected 0: {errors.read()!r}"
            assert stderr_bytes == 0, f"unexpected stderr: {errors.read()!r}"
            assert pending == b"", "unterminated JSONL output"
            assert seen == count, f"received {seen} records, expected {count}"
        finally:
            # Kill the whole session so a failed assertion/timeout cannot orphan time's child.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
    peak_rss_kib = int(rss_path.read_text().strip())
    assert peak_rss_kib > 0, f"invalid peak RSS: {peak_rss_kib}"
    print(count, "status-only records preserved in input order; child peak RSS:", peak_rss_kib, "KiB")
    return peak_rss_kib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--httpx", required=True, type=Path)
    parser.add_argument("--count", type=int, default=50000)
    args = parser.parse_args()
    if args.count <= 0:
        parser.error("--count must be positive")
    binary, httpx = str(args.binary.resolve()), str(args.httpx.resolve())
    version = run([httpx, "-version", "-duc"])
    assert b"v1.12.0" in version.stdout + version.stderr, "wrong upstream version"
    print("httpx sha256:", hashlib.sha256(Path(httpx).read_bytes()).hexdigest())
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    Fixture.requests.clear()
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix="wafme0w-httpx-smoke-") as directory:
            root = Path(directory)
            catalogue = root / "catalogue.json"
            catalogue.write_text(json.dumps([
                {"name": "Headers fixture", "schemas": [{"fingerprints": [
                    {"type": "Header", "header_key": "X-Fixture", "header_value": "^first$"},
                    {"type": "Header", "header_key": "X-Fixture", "header_value": "^second$"}]}]},
                {"name": "Cookie fixture", "schemas": [{"fingerprints": [
                    {"type": "Cookie", "pattern": "^fixture=a"},
                    {"type": "Cookie", "pattern": "^second=b"}]}]},
                {"name": "Body must remain unknown", "schemas": [{"fingerprints": [
                    {"type": "Content", "pattern": "fixture-body-marker"}]}]},
            ]))
            url = f"http://127.0.0.1:{server.server_port}/redirect"
            final_url = f"http://127.0.0.1:{server.server_port}/marker"
            for encoding, export, save_cap in [
                    ("text", ["-irr"], "1048576"),
                    ("base64", ["-irrb", "-no-decode"], "1398104")]:
                capture = run([httpx, "-u", url, "-silent", "-json", "-duc", "-probe",
                               "-follow-redirects", "-timeout", "2", "-retries", "0",
                               "-rstr", "1048576", "-rsts", save_cap, *export]).stdout
                upstream_lines = capture.splitlines()
                assert len(upstream_lines) == 1
                upstream = json.loads(upstream_lines[0])
                assert upstream["final_url"] == final_url
                trace = root / f"{encoding}.trace"
                requests_before = len(Fixture.requests)
                output = run(["strace", "-f", "-e", "trace=network", "-o", str(trace), binary,
                              "--evidence=-", "--evidence-format=httpx", "--httpx-response-encoding", encoding,
                              "--fingerprints", str(catalogue), "--jsonl", "--silent", "--strict"],
                             expected=2, input=capture)
                output_lines = output.stdout.splitlines()
                assert len(output_lines) == 1
                imported = json.loads(output_lines[0])
                assert {m["product"] for m in imported["outcome"].get("matches", [])} == {"Headers fixture", "Cookie fixture"}
                assert imported["outcome"]["state"] == "incomplete"
                assert imported["evidence"][0]["availability"]["body"] == "unknown"
                assert imported["evidence"][0]["effective_url"] == upstream["final_url"]
                assert imported["provenance"]["scan_mode"] == "passive"
                assert len(Fixture.requests) == requests_before, "import reacquired fixture"
                assert re.search(r"AF_INET6?\b", trace.read_text()) is None, "import attempted Internet networking"
                print(encoding, "producer -> importer: headers/cookies, attribution, unknown body, strict2; no Internet syscalls")
            # Exercise every occurrence without retaining decoded records in this harness.
            small_count = max(1, args.count // 10)
            small_rss = check_volume(binary, root, small_count)
            large_rss = check_volume(binary, root, args.count)
            # ponytail: allow 16 MiB of Go runtime/GC RSS variation, not a timing gate.
            # At the default 5k/50k volumes, the budget targets tens-of-MiB linear
            # result retention; fixed catalogue/runtime overhead is shared by both runs.
            growth_limit_kib = 16 * 1024
            growth_kib = large_rss - small_rss
            print("child peak RSS growth:", growth_kib, "KiB; allowance:", growth_limit_kib, "KiB")
            assert growth_kib <= growth_limit_kib, (
                f"child RSS grew {growth_kib} KiB from {small_count} to {args.count} records; "
                f"bounded-memory allowance is {growth_limit_kib} KiB")
    finally:
        server.shutdown()
        worker.join()
        server.server_close()


if __name__ == "__main__":
    main()
