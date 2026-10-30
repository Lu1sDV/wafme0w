#!/usr/bin/env python3
"""Exercise a built CLI and each supplied httpx using owned loopback only.

Python 3.12+, standard library only; Linux is required for bounded pipe controls.
No build, public targets, browser, strace, or volume benchmark is performed.

    python3 tools/httpx_usage_matrix.py --binary /path/to/wafmeow \
        --httpx /path/to/httpx --httpx /path/to/another/httpx \
        --output /new/artifact/directory

Every case retains commands, stdin, stdout, stderr, assertions, and its outcome.
report.json is updated after each case; failures do not discard earlier evidence.
Exit 0 means every enumerated case passed; exit 1 means at least one failed.
Upstream omissions are observations, not negative detections or invented records.
The separate httpx_smoke.py owns the 5k/50k memory/throughput checks.
"""

import argparse
import array
from contextlib import contextmanager
import csv
import fcntl
import hashlib
import http.server
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import termios
import threading
import time
import traceback


TIMEOUT = 30
SENTINEL = b"previous published report\n"
BODY = "private-fixture-body-marker"
RAW_HEADER = ("HTTP/1.1 200 OK\r\nX-Fixture: first\r\nX-Fixture: second\r\n"
              "Set-Cookie: fixture=a; Path=/\r\nSet-Cookie: second=b; Path=/\r\n\r\n")
HEADER_PRODUCTS = {"Header fixture", "Cookie fixture"}


def jsonl(records):
    return b"".join((json.dumps(record, ensure_ascii=True) + "\n").encode() for record in records)


def encoded(value):
    import base64
    return base64.b64encode(value.encode()).decode()


def records(data):
    return [json.loads(line) for line in data.splitlines() if line.strip()]


def products(record):
    return {match["product"] for match in record["outcome"].get("matches", [])}


def compact(value):
    text = repr(value)
    return text if len(text) <= 1200 else text[:1200] + " ... [see artifacts]"


def wait_until(predicate, description, timeout=TIMEOUT):
    deadline = time.monotonic() + timeout
    pause = threading.Event()
    while not predicate():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(description)
        # Readiness is the predicate, not elapsed time. This only bounds polling.
        pause.wait(min(.01, remaining))


class FixtureServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self):
        super().__init__(("127.0.0.1", 0), FixtureHandler)
        self.events = []
        self.lock = threading.Lock()

    def snapshot(self):
        with self.lock:
            return list(self.events)


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        with self.server.lock:
            self.server.events.append({"method": "GET", "path": self.path})
        if self.path.startswith("/drop"):
            self.close_connection = True
            return
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "/marker/redirect-final")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        empty_chunk = self.path.startswith("/empty-chunk")
        body = b"" if empty_chunk else BODY.encode()
        chunked = self.path.startswith(("/chunked", "/empty-chunk"))
        if chunked:
            self.protocol_version = "HTTP/1.1"
        status = 304 if empty_chunk else (403 if self.path.startswith("/status-omitted") else 200)
        self.send_response(status)
        self.send_header("X-Fixture", "first")
        self.send_header("X-Fixture", "second")
        self.send_header("Set-Cookie", "fixture=a; Path=/")
        self.send_header("Set-Cookie", "second=b; Path=/")
        self.send_header("Transfer-Encoding" if chunked else "Content-Length",
                         "chunked" if chunked else str(len(body)))
        self.end_headers()
        try:
            if chunked:
                chunk = f"{len(body):x}\r\n".encode() + body + b"\r\n" if body else b""
                self.wfile.write(chunk + b"0\r\n\r\n")
            else:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


class Child:
    """One owned process, with disk logs even if a case times out mid-protocol."""

    def __init__(self, case, command, stdin=None, pipe=False, stdout_fd=None,
                 stdout_destination=None, timeout=TIMEOUT):
        self.case, self.timeout = case, timeout
        self.index = len(case.row["commands"]) + 1
        self.stdout_path = case.path / f"command-{self.index}.stdout"
        self.stderr_path = case.path / f"command-{self.index}.stderr"
        self.pending = b""
        self.started = time.monotonic()
        self.input_file = None
        self.input_data = stdin if isinstance(stdin, bytes) else None
        if isinstance(stdin, bytes):
            stdin_path = case.put(f"command-{self.index}.stdin", stdin)
            source, stdin_description = subprocess.PIPE, f"pipe from {stdin_path}"
        elif isinstance(stdin, Path):
            self.input_file = stdin.open("rb")
            source, stdin_description = self.input_file, str(stdin)
        else:
            source = subprocess.DEVNULL if stdin is None else stdin
            if stdin == subprocess.PIPE:
                stdin_description = "open pipe"
            elif stdin is None:
                stdin_description = "DEVNULL"
            else:
                stdin_description = f"inherited fd {stdin.fileno()}"
        self.stdout_log = self.stdout_path.open("wb")
        self.stderr_log = self.stderr_path.open("wb")
        self.command_row = {
            "argv": [str(item) for item in command], "cwd": str(case.path),
            "stdin": stdin_description, "stdout": str(self.stdout_path),
            "stderr": str(self.stderr_path), "timeout_seconds": timeout,
            "stdout_destination": stdout_destination or ("captured pipe" if pipe else "file"),
        }
        case.row["commands"].append(self.command_row)
        environment = dict(case.matrix.environment, TMPDIR=str(case.tmp), HOME=str(case.home),
                           XDG_CONFIG_HOME=str(case.home / "config"),
                           XDG_CACHE_HOME=str(case.home / "cache"))
        self.command_row["environment_overrides"] = {
            key: environment[key] for key in ("TMPDIR", "HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "NO_PROXY")
        }
        read_fd, write_fd = None, None
        self.process = None
        try:
            if pipe:
                read_fd, write_fd = os.pipe()
                self.command_row["stdout_pipe_capacity"] = fcntl.fcntl(read_fd, fcntl.F_SETPIPE_SZ, 4096)
            self.process = subprocess.Popen(
                self.command_row["argv"], cwd=case.path, env=environment,
                stdin=source,
                stdout=stdout_fd if stdout_fd is not None else (write_fd if pipe else self.stdout_log),
                stderr=self.stderr_log, start_new_session=True, bufsize=0,
            )
            if pipe:
                self.process.stdout = os.fdopen(read_fd, "rb", buffering=0)
                read_fd = None
        except BaseException:
            if self.process is not None:
                self.kill()
            if read_fd is not None:
                os.close(read_fd)
            self.close_files()
            raise
        finally:
            if write_fd is not None:
                os.close(write_fd)
        self.command_row["pid"] = self.process.pid
        self.finished = False

    def close_files(self):
        if self.input_file is not None:
            self.input_file.close()
        self.stdout_log.close()
        self.stderr_log.close()

    def read_ready(self, timeout=None, size=65536):
        stream = self.process.stdout
        if stream is None:
            raise RuntimeError("this command has no captured stdout pipe")
        timeout = self.timeout if timeout is None else timeout
        if timeout <= 0:
            raise TimeoutError("child stdout deadline expired")
        with selectors.DefaultSelector() as selector:
            selector.register(stream, selectors.EVENT_READ)
            if not selector.select(timeout):
                raise TimeoutError("waiting for child stdout readiness")
            chunk = os.read(stream.fileno(), size)
        self.stdout_log.write(chunk)
        self.stdout_log.flush()
        return chunk

    def first_line(self):
        deadline = time.monotonic() + self.timeout
        while b"\n" not in self.pending:
            chunk = self.read_ready(deadline - time.monotonic())
            if not chunk:
                raise AssertionError("child stdout ended before a complete result")
            self.pending += chunk
            if len(self.pending) > 2 * 1024 * 1024:
                raise AssertionError("unterminated readiness line exceeds 2 MiB")
        line, self.pending = self.pending.split(b"\n", 1)
        return line

    def feed(self, data):
        if len(data) > 4096:
            raise ValueError("open-input readiness feed must fit one atomic pipe write")
        path = self.case.put(f"command-{self.index}.stdin", data)
        self.command_row["stdin"] = f"open pipe from {path}, EOF withheld"
        written = self.process.stdin.write(data)
        self.case.equal(written, len(data), "readiness input is fully delivered")

    def close_input(self):
        if self.process.stdin is not None and not self.process.stdin.closed:
            self.process.stdin.close()

    def kill(self):
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.process.wait(timeout=5)

    def finish(self, expected=0):
        try:
            code = self.process.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            self.command_row["timed_out"] = True
            self.kill()
            raise
        self.finished = True
        if self.process.stdout is not None:
            deadline = time.monotonic() + 5
            while self.read_ready(deadline - time.monotonic()):
                pass
        self.stdout_log.flush()
        self.stderr_log.flush()
        self.command_row.update(returncode=code, seconds=time.monotonic() - self.started)
        self.case.equal(code, expected, "process exit status")
        return self.stdout_path.read_bytes(), self.stderr_path.read_bytes()

    def cleanup(self):
        try:
            self.kill()
            self.close_input()
            if not self.finished and self.process.stdout is not None:
                deadline = time.monotonic() + 5
                while self.read_ready(deadline - time.monotonic()):
                    pass
        finally:
            self.command_row.update(returncode=self.process.returncode,
                                    seconds=time.monotonic() - self.started)
            if self.process.stdout is not None:
                self.process.stdout.close()
            self.close_files()
            self.command_row["stdout_bytes"] = self.stdout_path.stat().st_size
            self.command_row["stderr_bytes"] = self.stderr_path.stat().st_size


class Case:
    def __init__(self, matrix, name):
        self.matrix = matrix
        self.path = matrix.output / name
        self.path.mkdir()
        self.tmp = self.path / "tmp"
        self.tmp.mkdir()
        self.home = self.path / "home"
        self.home.mkdir()
        self.row = {"name": name, "commands": [], "assertions": [], "observations": {}}

    def put(self, name, value):
        path = self.path / name
        path.write_bytes(value.encode() if isinstance(value, str) else value)
        return path

    def check(self, condition, description, **details):
        self.row["assertions"].append({"description": description, "passed": bool(condition), **details})
        if not condition:
            raise AssertionError(description + (": " + compact(details) if details else ""))

    def equal(self, actual, expected, description):
        self.check(actual == expected, description, actual=compact(actual), expected=compact(expected))

    @contextmanager
    def child(self, command, **kwargs):
        child = Child(self, command, **kwargs)
        try:
            yield child
        finally:
            child.cleanup()

    def run(self, args, data=None, expected=0, raw_command=False):
        command = args if raw_command else [str(self.matrix.binary), *args]
        with self.child(command, stdin=data) as child:
            if child.input_data is not None:
                try:
                    child.process.communicate(input=child.input_data, timeout=child.timeout)
                except subprocess.TimeoutExpired:
                    child.command_row["timed_out"] = True
                    raise
            stdout, stderr = child.finish(expected)
        if expected == 1:
            self.check(bool(stderr.strip()), "operational failure reports diagnostics on stderr")
        return stdout, stderr

    def import_run(self, args, data=None, expected=0):
        before = self.matrix.server.snapshot()
        output = self.run(args, data, expected)
        self.equal(self.matrix.server.snapshot(), before, "offline importer makes no second fixture requests")
        return output

    def results(self, data, targets=None):
        rows = records(data)
        self.check(all(isinstance(row, dict) and "target" in row and "outcome" in row for row in rows),
                   "every nonblank stdout line is a result object")
        if targets is not None:
            self.equal([row["target"] for row in rows], targets, "result occurrences and input order")
        return rows

    def clean(self):
        self.equal(list(self.tmp.iterdir()), [], "private human report spool is removed")
        self.equal([str(path) for path in self.path.glob(".report.*")], [],
                   "atomic report temporary files are removed")


class Matrix:
    def __init__(self, binary, httpx_paths, output):
        self.binary, self.httpx_paths, self.output = binary, httpx_paths, output
        self.environment = {key: value for key, value in os.environ.items()
                            if key.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
        self.environment.pop("NO_COLOR", None)
        self.environment["NO_PROXY"] = "127.0.0.1,localhost"
        self.server = FixtureServer()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.worker = threading.Thread(target=self.server.serve_forever, name="httpx-matrix-loopback")
        self.report = {
            "schema_version": 1, "complete": False,
            "scope": "Owned loopback and synthetic offline evidence only; no public network, browser, accuracy or volume claims.",
            "binary": self.identity(binary), "httpx": [self.identity(path) for path in httpx_paths],
            "cases": [], "limitations": [
                "Fixture request counts detect reacquisition of this fixture, not all possible network syscalls; use httpx_smoke.py for strace isolation evidence.",
                "No actual producer version is inferred from the importer compatibility-profile label.",
                "Missing upstream records cannot be recovered or counted as negative detections.",
            ],
        }
        self.catalogue = output / "fingerprints.json"
        self.catalogue.write_text(json.dumps([
            {"name": "Header fixture", "schemas": [{"fingerprints": [
                {"type": "Header", "header_key": "X-Fixture", "header_value": "^first$"},
                {"type": "Header", "header_key": "X-Fixture", "header_value": "^second$"}]}]},
            {"name": "Cookie fixture", "schemas": [{"fingerprints": [
                {"type": "Cookie", "pattern": "^fixture=a"}, {"type": "Cookie", "pattern": "^second=b"}]}]},
            {"name": "Body fixture", "schemas": [{"fingerprints": [{"type": "Content", "pattern": BODY}]}]},
            {"name": "Status fixture", "schemas": [{"fingerprints": [{"type": "Status", "pattern": "403"}]}]},
            {"name": "Reason fixture", "schemas": [{"fingerprints": [{"type": "Reason", "pattern": "Forbidden"}]}]},
        ], indent=2) + "\n")
        self.base = ["--jsonl", "--silent", "--no-colors", "--no-generic", "--fingerprints", str(self.catalogue)]
        self.offline = [*self.base, "--evidence=-", "--evidence-format=httpx"]

    @staticmethod
    def identity(path):
        with path.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        return {"path": str(path), "sha256": digest}

    def save(self, complete=False):
        rows = self.report["cases"]
        self.report.update(complete=complete, total=len(rows),
                           passed=sum(row["outcome"] == "passed" for row in rows),
                           failed=sum(row["outcome"] == "failed" for row in rows),
                           fixture_requests=self.server.snapshot())
        temporary = self.output / ".report.json.tmp"
        temporary.write_text(json.dumps(self.report, indent=2) + "\n")
        temporary.replace(self.output / "report.json")

    def case(self, name, function):
        case = Case(self, name)
        before = self.server.snapshot()
        started = time.monotonic()
        try:
            function(case)
            if not name.startswith(("urls-", "producer-")):
                case.equal(self.server.snapshot(), before, "non-acquisition case makes no fixture requests")
            case.clean()
            case.row["outcome"] = "passed"
        except Exception as error:
            case.row.update(outcome="failed", error=f"{type(error).__name__}: {error}")
            case.put("failure.txt", traceback.format_exc())
        case.row.update(seconds=time.monotonic() - started,
                        fixture_requests=self.server.snapshot()[len(before):])
        self.report["cases"].append(case.row)
        (case.path / "case.json").write_text(json.dumps(case.row, indent=2) + "\n")
        self.save()
        print(f'{case.row["outcome"]}: {name}', flush=True)

    def httpx_record(self, **extra):
        return {"url": self.origin + "/offline", "status_code": 200, **extra}

    def native_record(self, target="native-match", body=BODY, **extra):
        return {"target": target, "evidence": [{"role": "Normal", "status_code": 200,
                "body": encoded(body), **extra}]}

    def assert_httpx(self, case, row, source, occurrence=1, line=1, encoding="text"):
        metadata = row["provenance"]["import"]
        target = source.get("url") or source["input"]
        case.equal(row["target"], target, "requested url or failed original label is attributed")
        case.equal(row["provenance"]["scan_mode"], "passive", "import is marked passive")
        case.equal(metadata["format"], "httpx", "source format is explicit")
        case.equal(metadata["profile"], "httpx-v1.12.0", "profile is not substituted with actual producer version")
        case.equal(metadata["response_encoding"], encoding, "declared encoding survives")
        case.equal(metadata["occurrence"], occurrence, "one provenance occurrence per source object")
        case.equal(metadata["input_line"], line, "physical source line survives blank lines")
        case.equal(metadata.get("original_input", ""), source.get("input") or "", "original input remains separate")
        if source.get("timestamp"):
            case.equal(metadata["source_timestamp"], source["timestamp"], "producer timestamp survives")
            case.equal(metadata["timestamp_meaning"], "result_construction", "timestamp meaning is not request start")
        evidence = row["evidence"]
        case.equal(len(evidence), 1, "each source row is an independent single observation")
        case.equal(evidence[0].get("request_url", ""), source.get("url") or "", "requested URL is not invented")
        case.equal(evidence[0].get("effective_url", ""), source.get("final_url") or "", "effective URL comes only from final_url")
        case.equal(evidence[0]["availability"]["reason"], "unavailable", "reconstructed reason cannot support matches")
        case.check(bool(row["outcome"].get("diagnostics")), "import limitations remain machine-readable")
        case.check("Body fixture" not in products(row) and "Reason fixture" not in products(row),
                   "unknown bodies and reconstructed reasons never match")
        case.equal(row["outcome"]["state"], "incomplete", "missing body/reason channels prevent complete classification")
        case.check({"Body fixture", "Reason fixture"} <= set(row["outcome"].get("incomplete_products", [])),
                   "body/reason rules remain explicitly unresolved, not negative")
        case.check(BODY.encode() not in json.dumps(row).encode(), "result does not retain private body bytes")

    def url_cases(self):
        for mode in ("stdin", "file", "dash", "explicit-precedence", "file-precedence", "literal-dash"):
            def exercise(case, mode=mode):
                first, second = self.origin + "/marker/" + mode, self.origin + "/marker/second-" + mode
                data = (first + "\n" + second + "\n").encode()
                args = [*self.base, "--baseline", "--rate=0", "--concurrency=1", "--request-timeout=2s"]
                wanted = [first, second]
                if mode in ("file", "file-precedence"):
                    source = case.put("targets.txt", data)
                    args += ["--input", str(source)]
                    data = b"invalid://ignored-stdin\n" if mode == "file-precedence" else b""
                elif mode == "dash":
                    args += ["--input", "-"]
                elif mode == "explicit-precedence":
                    args += ["--target", first]
                    data, wanted = b"invalid://ignored-stdin\n", [first]
                elif mode == "literal-dash":
                    case.put("-", data)
                    args += ["--input", "./-"]
                    data = b"invalid://ignored-stdin\n"
                before = len(self.server.snapshot())
                out, err = case.run(args, data)
                rows = case.results(out, wanted)
                case.equal(len(self.server.snapshot()) - before, len(wanted), "baseline acquires exactly the selected URLs")
                case.check(all(row["outcome"]["state"] == "complete" for row in rows), "owned URL acquisitions complete")
                case.check(all(products(row) == HEADER_PRODUCTS | {"Body fixture"} for row in rows), "live acquisition includes complete body and repeated headers")
                case.equal(err, b"", "silent URL mode has no human output")
            self.case("urls-" + mode, exercise)

    def capture_cases(self):
        native = [self.native_record(), self.native_record("native-clean", "ordinary"),
                  self.native_record("native-truncated", "ordinary", body_truncated=True)]
        for location in ("file", "stdin"):
            def exercise(case, location=location):
                data = jsonl(native)
                args = [*self.base, "--evidence-format=native"]
                if location == "file":
                    source = case.put("native.jsonl", data)
                    args += ["--evidence", str(source)]
                    data = b"not JSON; explicit file must win\n"
                else:
                    args += ["--evidence=-"]
                out, _ = case.import_run(args, data)
                rows = case.results(out, [record["target"] for record in native])
                case.equal([row["outcome"]["state"] for row in rows], ["complete", "complete", "incomplete"], "native completeness is not reinterpreted")
                case.equal([products(row) for row in rows], [{"Body fixture"}, set(), set()], "native complete bodies still classify")
            self.case("native-" + location, exercise)
        for encoding in ("text", "base64"):
            for location in ("file", "stdin"):
                def exercise(case, encoding=encoding, location=location):
                    raw, body = RAW_HEADER, BODY
                    if encoding == "base64":
                        raw, body = encoded(raw), encoded(body)
                    source = self.httpx_record(raw_header=raw, body=body, input="original producer input",
                                              final_url=self.origin + "/supplied-final", timestamp="2026-10-29T00:00:00Z")
                    args = [*self.base, "--evidence-format=httpx", "--httpx-response-encoding", encoding, "--strict"]
                    data = jsonl([source])
                    if location == "file":
                        path = case.put("httpx.jsonl", data)
                        args += ["--evidence", str(path)]
                        data = b"ignored unrelated stdin\n"
                    else:
                        args += ["--evidence=-"]
                    out, _ = case.import_run(args, data, expected=2)
                    row = case.results(out, [source["url"]])[0]
                    self.assert_httpx(case, row, source, encoding=encoding)
                    case.equal(products(row), HEADER_PRODUCTS, "repeated header and cookie positives survive")
                    case.equal(row["evidence"][0]["availability"], {"status": "complete", "headers": "incomplete", "reason": "unavailable", "body": "unknown"}, "httpx channel uncertainty is explicit")
                self.case(f"httpx-{encoding}-{location}", exercise)

        def shapes(case):
            sources = [
                self.httpx_record(),
                self.httpx_record(header={"x_fixture": "first, second"}, tech=["Body fixture"], cdn_name="Cloudflare"),
                {"input": "opaque failed label", "failed": True, "error": "producer failed"},
                self.httpx_record(input=None, final_url=None, timestamp=None, raw_header=None,
                                  header=None, body=None, status_code=None, failed=None, error=None),
                self.httpx_record(raw_header=RAW_HEADER, body=BODY, body_preview=BODY,
                                  unknown={"deep": [None, True, 1, {"secret": "not retained"}]},
                                  stored_response_path="/must-not-open", request="private-request-dump"),
                self.httpx_record(raw_header=RAW_HEADER, body=BODY),
                self.httpx_record(raw_header=RAW_HEADER, body=BODY),
            ]
            data = b"\n" + b"\n \n".join(jsonl([source]).rstrip(b"\n") for source in sources) + b"\n"
            out, _ = case.import_run(self.offline, data)
            rows = case.results(out, [source.get("url") or source["input"] for source in sources])
            for index, (row, source) in enumerate(zip(rows, sources)):
                self.assert_httpx(case, row, source, index + 1, 2 + 2 * index)
            case.equal([products(row) for row in rows], [set(), set(), set(), set(), HEADER_PRODUCTS, HEADER_PRODUCTS, HEADER_PRODUCTS], "summary, normalized-only and enrichment never invent named matches")
            case.check(rows[2]["provenance"]["import"]["upstream_failed"], "upstream failed label is retained without invented URL")
            for index in (0, 1, 2, 3):
                case.equal(rows[index]["evidence"][0]["availability"]["headers"], "unavailable", "missing or normalized headers remain unavailable")
            case.check(b"private-request-dump" not in out and b"/must-not-open" not in out and b"not retained" not in out, "unrelated source fields are not exported")
        self.case("httpx-shapes-order-and-duplicates", shapes)

        def complete_strict(case):
            status_catalogue = case.put("status-catalogue.json", json.dumps([
                {"name": "Status fixture", "schemas": [{"fingerprints": [{"type": "Status", "pattern": "403"}]}]},
            ]))
            args = ["--jsonl", "--silent", "--no-colors", "--no-generic", "--fingerprints", str(status_catalogue),
                    "--evidence=-", "--evidence-format=httpx", "--strict"]
            out, _ = case.import_run(args, jsonl([self.httpx_record()]), expected=2)
            row = case.results(out)[0]
            case.equal(row["outcome"]["state"], "complete", "catalogue-relative classification may resolve")
            case.check(bool(row["outcome"]["diagnostics"]), "strict still rejects import limitations after complete classification")
        self.case("strict-complete-classification-with-import-diagnostics", complete_strict)

        for name, source, options, header_state, body_state, wanted in [
            ("text-declared-base64", self.httpx_record(raw_header=RAW_HEADER, body=BODY), ["--httpx-response-encoding=base64"], "unavailable", "unavailable", set()),
            ("base64-declared-text", self.httpx_record(raw_header=encoded(RAW_HEADER), body=encoded(BODY)), [], "unavailable", "unknown", set()),
            ("cut-base64-body", self.httpx_record(raw_header=encoded(RAW_HEADER), body="YWJjZ"), ["--httpx-response-encoding=base64"], "incomplete", "unavailable", HEADER_PRODUCTS),
            ("decoded-body-overflow", self.httpx_record(raw_header=RAW_HEADER, body=BODY), ["--max-body-bytes=3"], "incomplete", "incomplete", HEADER_PRODUCTS),
            ("decoded-header-overflow", self.httpx_record(raw_header=RAW_HEADER, body=BODY), ["--max-response-header-bytes=24"], "unavailable", "unknown", set()),
            ("status-conflict", self.httpx_record(status_code=403, raw_header=RAW_HEADER), [], "incomplete", "unavailable", HEADER_PRODUCTS),
            ("independent-status", self.httpx_record(status_code=403, raw_header="invalid header block"), [], "unavailable", "unavailable", {"Status fixture"}),
        ]:
            def exercise(case, source=source, options=options, header_state=header_state, body_state=body_state, wanted=wanted, name=name):
                out, _ = case.import_run([*self.offline, *options, "--strict"], jsonl([source]), expected=2)
                row = case.results(out, [source["url"]])[0]
                availability = row["evidence"][0]["availability"]
                case.equal(availability["headers"], header_state, "unusable header channel is not salvaged")
                case.equal(availability["body"], body_state, "body availability honors declared encoding and limits")
                case.equal(products(row), wanted, "only independently usable channels support positives")
                if name == "status-conflict":
                    case.equal(availability["status"], "unavailable", "conflicting statuses are both discarded")
                else:
                    case.equal(availability["status"], "complete", "independent explicit status survives channel failure")
            self.case("httpx-" + name, exercise)

    def malformed_cases(self):
        first = self.httpx_record()
        rejected = {
            "malformed-tail": b"{invalid}\n",
            "truncated-json": b'{"url":"unfinished',
            "top-null": b"null\n",
            "top-array": b"[]\n",
            "duplicate-consumed": b'{"url":"' + (self.origin + "/offline").encode() + b'","status_code":200,"status_code":403}\n',
            "wrong-consumed-type": jsonl([self.httpx_record(body=[])]),
            "trailing-document": jsonl([first]).rstrip(b"\n") + b" {}\n",
            "missing-identity": b'{}\n',
        }
        for name, tail in rejected.items():
            def exercise(case, tail=tail):
                report = case.put("report.json", SENTINEL)
                journal = case.path / "journal.jsonl"
                out, _ = case.import_run([*self.offline, "--output", str(report), "--diagnostics-journal", str(journal)], jsonl([first]) + tail, expected=1)
                case.results(out, [first["url"]])
                case.equal(report.read_bytes(), SENTINEL, "bad tail does not replace the published report")
                saved = records(journal.read_bytes())
                case.equal([row["type"] for row in saved], ["result", "diagnostic"], "journal preserves completed results followed by failure")
                case.equal(saved[0]["result"]["target"], first["url"], "journal retains the prior occurrence")
                case.equal(saved[1]["diagnostic"]["code"], "run_error", "journal records input failure")
            self.case("reject-" + name, exercise)

        def oversized(case):
            source = case.path / "oversized.jsonl"
            with source.open("wb") as output:
                output.write(jsonl([first]))
                output.write(b'{"url":"' + (self.origin + "/too-big").encode() + b'","extra":"')
                for _ in range(17):
                    output.write(b"x" * (1 << 20))
                output.write(b'"}\n')
            report = case.put("report.json", SENTINEL)
            out, _ = case.import_run([*self.base, "--evidence", str(source), "--evidence-format=httpx", "--output", str(report)], expected=1)
            case.results(out, [first["url"]])
            case.equal(report.read_bytes(), SENTINEL, "serialized record overflow preserves the old report")
        self.case("reject-oversized-serialized-record", oversized)

        def unterminated(case):
            out, _ = case.import_run(self.offline, jsonl([first]).rstrip(b"\n"))
            case.results(out, [first["url"]])
        self.case("httpx-valid-final-line-without-newline", unterminated)

        for name, args in [
            ("format-without-evidence", ["--input=-", "--evidence-format=httpx"]),
            ("unknown-format", ["--evidence=-", "--evidence-format=guess"]),
            ("encoding-with-native", ["--evidence=-", "--httpx-response-encoding=text"]),
            ("unknown-encoding", ["--evidence=-", "--evidence-format=httpx", "--httpx-response-encoding=guess"]),
            ("target-conflict", ["--evidence=-", "--evidence-format=httpx", "--target=" + self.origin]),
            ("input-conflict", ["--evidence=-", "--evidence-format=httpx", "--input=-"]),
            ("baseline-conflict", ["--evidence=-", "--evidence-format=httpx", "--baseline"]),
        ]:
            def exercise(case, args=args):
                out, _ = case.run([*self.base, *args], jsonl([first]), expected=1)
                case.equal(out, b"", "invalid options reject before emitting results")
            self.case("reject-options-" + name, exercise)

    @staticmethod
    def flattened(row):
        result = {key: value for key, value in row.items() if key != "outcome"}
        result.update(row["outcome"])
        for key in ("matches", "incomplete_products", "diagnostics", "browser"):
            result.setdefault(key, None)
        return result

    def output_cases(self):
        source = self.httpx_record(raw_header=RAW_HEADER, body=BODY)
        data = jsonl([source, self.httpx_record(url=self.origin + "/summary")])
        for extension in ("json", "JSONL", "CsV", "txt"):
            def exercise(case, extension=extension):
                report = case.put("report." + extension, SENTINEL)
                out, err = case.import_run([*self.offline, "--strict", "--output", str(report)], data, expected=2)
                rows = case.results(out, [source["url"], self.origin + "/summary"])
                case.equal(err, b"", "silent JSONL leaves diagnostics in records, not human stdout/stderr")
                suffix = extension.lower()
                if suffix == "json":
                    published = json.loads(report.read_bytes())
                elif suffix == "jsonl":
                    published = records(report.read_bytes())
                elif suffix == "csv":
                    with report.open(newline="") as file:
                        table = list(csv.DictReader(file))
                    published = [{key: value if key in ("target", "state") else json.loads(value)
                                  for key, value in row.items()} for row in table]
                else:
                    published = []
                    for line in report.read_text().splitlines():
                        cells = line.split("\t")
                        parsed = {"target": json.loads(cells[0])}
                        parsed.update({key: json.loads(value) for key, value in
                                       (cell.split("=", 1) for cell in cells[1:])})
                        case.equal(parsed.pop("browser_state"), "off", "TXT records disabled browser separately")
                        published.append(parsed)
                expected = rows if suffix in ("json", "jsonl") else [self.flattened(row) for row in rows]
                case.equal(published, expected, "published report preserves every field and occurrence from JSONL stdout")
            self.case("report-" + extension.lower(), exercise)

        for mode in ("human", "human-no-warning", "jsonl-with-summary"):
            def exercise(case, mode=mode):
                args = ["--evidence=-", "--evidence-format=httpx", "--no-colors", "--no-generic", "--fingerprints", str(self.catalogue)]
                if mode == "human-no-warning":
                    args += ["--no-warning"]
                elif mode == "jsonl-with-summary":
                    args += ["--jsonl"]
                human_sources = [source, self.httpx_record(url=self.origin + "/human-summary"), source]
                targets = [record["url"] for record in human_sources]
                out, err = case.import_run(args, jsonl(human_sources))
                case.check(b"\x1b" not in out + err, "no-colors disables ANSI on both channels")
                if mode == "jsonl-with-summary":
                    case.results(out, targets)
                    case.check(bool(err.strip()), "human summary remains on stderr, never JSONL stdout")
                else:
                    for channel, text in (("stdout", out), ("stderr", err)):
                        case.check(all(target.encode() in text for target in targets), channel + " retains every full target")
                        case.check(b"classification" in text.lower() and b"unknown" in text.lower(), channel + " distinguishes classification and unavailable body")
                        case.check(b"Header fixture" in text, channel + " retains named positive despite incompleteness")
                    table_targets = [
                        line.rsplit(b"|", 1)[-1].strip().decode()
                        for line in err.splitlines()
                        if b"|" in line and line.rsplit(b"|", 1)[-1].strip().decode() in targets
                    ]
                    case.equal(table_targets, targets, "stderr final table preserves full URLs, order and duplicate occurrences")
                    case.check(b"Cookie fixture" in err, "stderr final table retains positive product names")
                    if mode == "human-no-warning":
                        case.check(not any(line.lstrip().startswith(b"WARN ") for line in (out + err).splitlines()), "no-warning suppresses warning records, not uncertainty")
            self.case("output-" + mode, exercise)

        for name, native, expected in [
            ("clean", self.native_record("native-clean", "ordinary"), 0),
            ("truncated", self.native_record("native-truncated", "ordinary", body_truncated=True), 2),
        ]:
            def exercise(case, native=native, expected=expected):
                report = case.path / "report.json"
                out, _ = case.import_run([*self.base, "--evidence=-", "--strict", "--output", str(report)], jsonl([native]), expected)
                case.equal(json.loads(report.read_bytes()), case.results(out, [native["target"]]), "native strict exit publishes the entire report first")
            self.case("strict-native-" + name, exercise)

    def journal_cases(self):
        source = self.httpx_record(raw_header=RAW_HEADER, body=BODY)
        data = jsonl([source])

        def append(case):
            journal = case.path / "journal.jsonl"
            for _ in range(2):
                case.import_run([*self.offline, "--diagnostics-journal", str(journal)], data)
            saved = records(journal.read_bytes())
            case.equal([row["type"] for row in saved], ["result", "result"], "journal appends, does not overwrite duplicates")
            case.equal([row["result"]["target"] for row in saved], [source["url"]] * 2, "journal retains both repeated runs")
            case.check(BODY.encode() not in journal.read_bytes(), "journal is body-free")
        self.case("journal-append", append)

        def partial(case):
            journal = case.put("journal.jsonl", b'{"type":')
            report = case.put("report.json", SENTINEL)
            out, _ = case.import_run([*self.offline, "--diagnostics-journal", str(journal), "--output", str(report)], data, expected=1)
            case.equal(out, b"", "unfinished journal rejects before scan")
            case.equal(journal.read_bytes(), b'{"type":', "unfinished journal is not repaired or overwritten")
            case.equal(report.read_bytes(), SENTINEL, "journal failure leaves published report unchanged")
        self.case("journal-unfinished-record", partial)

        def publication(case):
            report = case.path / "report.json"
            report.mkdir()
            keep = report / "keep"
            keep.write_bytes(SENTINEL)
            journal = case.path / "journal.jsonl"
            out, _ = case.import_run([*self.offline, "--output", str(report), "--diagnostics-journal", str(journal)], data, expected=1)
            case.results(out, [source["url"]])
            case.equal(keep.read_bytes(), SENTINEL, "failed atomic rename leaves prior destination intact")
            saved = records(journal.read_bytes())
            case.equal([row["type"] for row in saved], ["result", "diagnostic"], "journal survives final report publication failure")
            case.equal(saved[0]["result"]["target"], source["url"], "recoverable result precedes failed publication")
        self.case("atomic-publication-failure", publication)

        for kind in ("same", "hardlink", "symlink", "stdin-alias", "journal-report", "stdout-report"):
            def exercise(case, kind=kind):
                capture = case.put("source.jsonl", data)
                alias = case.path / "alias.jsonl"
                args = [*self.base, "--evidence", str(capture), "--evidence-format=httpx"]
                stdin = None
                if kind == "same":
                    args += ["--output", str(capture)]
                elif kind in ("hardlink", "symlink"):
                    if kind == "hardlink":
                        os.link(capture, alias)
                    else:
                        alias.symlink_to(capture)
                    args += ["--diagnostics-journal", str(alias)]
                elif kind == "stdin-alias":
                    args = [*self.offline, "--diagnostics-journal", str(capture)]
                    stdin = capture
                elif kind == "journal-report":
                    args += ["--output", str(alias), "--diagnostics-journal", str(alias)]
                else:
                    alias.write_bytes(SENTINEL)
                    args += ["--output", str(alias)]
                    with alias.open("ab") as sink, case.child([str(self.binary), *args], stdout_fd=sink.fileno(), stdout_destination=str(alias)) as child:
                        _, err = child.finish(expected=1)
                    case.check(bool(err.strip()), "stdout alias collision is diagnosed")
                    case.equal(alias.read_bytes(), SENTINEL, "stdout/report collision does not mutate the file")
                    case.equal(capture.read_bytes(), data, "collision never mutates evidence source")
                    return
                out, _ = case.import_run(args, stdin, expected=1)
                case.equal(out, b"", "file aliases reject before producing output")
                case.equal(capture.read_bytes(), data, "collision never mutates evidence source")
            self.case("collision-" + kind, exercise)

    def streaming_cases(self):
        source = self.httpx_record(raw_header=RAW_HEADER, body=BODY)

        def pre_eof(case):
            before = self.server.snapshot()
            with case.child([str(self.binary), *self.offline], stdin=subprocess.PIPE, pipe=True) as child:
                child.feed(jsonl([source]))
                line = child.first_line()
                case.results(line, [source["url"]])
                case.check(child.process.poll() is None and not child.process.stdin.closed, "first result is observable before producer EOF")
                child.close_input()
                out, _ = child.finish()
                case.results(out, [source["url"]])
            case.equal(self.server.snapshot(), before, "streaming import does not reacquire")
        self.case("stream-before-eof", pre_eof)

        for signame in ("SIGINT", "SIGTERM"):
            for mode in ("urls", "native", "httpx"):
                def exercise(case, signame=signame, mode=mode):
                    report = case.put("report.json", SENTINEL)
                    journal = case.path / "journal.jsonl"
                    args = [*self.base, "--output", str(report), "--diagnostics-journal", str(journal)]
                    if mode == "urls":
                        args += ["--input=-"]
                        data, target = b"invalid://completed\n", "invalid://completed"
                    elif mode == "native":
                        args += ["--evidence=-"]
                        native = self.native_record()
                        data, target = jsonl([native]), native["target"]
                    else:
                        args += ["--evidence=-", "--evidence-format=httpx"]
                        data, target = jsonl([source]), source["url"]
                    with case.child([str(self.binary), *args], stdin=subprocess.PIPE, pipe=True) as child:
                        child.feed(data)
                        case.results(child.first_line(), [target])
                        case.check(not child.process.stdin.closed, "producer remains open at cancellation")
                        child.process.send_signal(getattr(signal, signame))
                        out, _ = child.finish(expected=130)
                        case.results(out, [target])
                    case.equal(report.read_bytes(), SENTINEL, "cancellation does not publish a partial report")
                    saved = records(journal.read_bytes())
                    case.equal([row["type"] for row in saved], ["result", "diagnostic"], "cancellation closes a recoverable journal")
                    case.equal(saved[-1]["diagnostic"]["code"], "run_error", "cancellation is journaled")
                self.case(f"cancel-open-{mode}-{signame.lower()}", exercise)

        def fill_stdout(case, child):
            descriptor = child.process.stdout.fileno()
            size = fcntl.fcntl(descriptor, fcntl.F_GETPIPE_SZ)
            available = array.array("i", [0])

            def full():
                if child.process.poll() is not None:
                    raise AssertionError("child exited before filling stdout")
                fcntl.ioctl(descriptor, termios.FIONREAD, available, True)
                return available[0] >= size

            wait_until(full, "child never filled the deliberately undrained stdout pipe")
            case.row["observations"]["stdout_pipe_capacity"] = size
            case.row["observations"]["stdout_unread_at_readiness"] = available[0]
            case.check(available[0] == size, "kernel stdout pipe is full with no consumer")

        for signame in ("SIGINT", "SIGTERM"):
            def exercise(case, signame=signame):
                report = case.put("report.json", SENTINEL)
                # This single result is much larger than the pipe. No consumer can
                # let the first emit finish or the atomic report publish.
                source = self.httpx_record(url=self.origin + "/" + "long-path/" * 2500)
                capture = case.put("source.jsonl", jsonl([source]))
                journal = case.path / "journal.jsonl"
                args = [*self.base, "--evidence", str(capture), "--evidence-format=httpx", "--output", str(report), "--diagnostics-journal", str(journal)]
                with case.child([str(self.binary), *args], pipe=True) as child:
                    fill_stdout(case, child)
                    case.equal(report.read_bytes(), SENTINEL, "report is unpublished while stdout is blocked")
                    child.process.send_signal(getattr(signal, signame))
                    out, _ = child.finish(expected=130)
                case.check(bool(out), "blocked stdout retains its emitted prefix artifact")
                case.equal(report.read_bytes(), SENTINEL, "blocked output cancellation preserves previous report")
                saved = records(journal.read_bytes())
                case.equal([row["type"] for row in saved], ["result", "diagnostic"], "blocked stdout cancellation retains journal before the fallible sink")
            self.case("cancel-blocked-stdout-" + signame.lower(), exercise)

        for mode in ("jsonl", "human"):
            def exercise(case, mode=mode):
                sources = [self.httpx_record(url=self.origin + f"/row-{index}/" + "p" * 1024, raw_header=RAW_HEADER) for index in range(64)]
                capture = case.put("source.jsonl", jsonl(sources))
                report = case.put("report.json", SENTINEL)
                journal = case.path / "journal.jsonl"
                args = ["--evidence", str(capture), "--evidence-format=httpx", "--no-colors", "--no-generic", "--fingerprints", str(self.catalogue), "--output", str(report), "--diagnostics-journal", str(journal)]
                if mode == "jsonl":
                    args += ["--jsonl", "--silent"]
                read_fd, write_fd = os.pipe()
                try:
                    fcntl.fcntl(read_fd, fcntl.F_SETPIPE_SZ, 4096)
                    consumer_command = [sys.executable, "-c", "import sys; line=sys.stdin.buffer.readline(); sys.stdout.buffer.write(line); sys.stdout.buffer.flush()"]
                    with os.fdopen(read_fd, "rb", buffering=0) as source_pipe:
                        read_fd = None
                        with case.child(consumer_command, stdin=source_pipe) as consumer:
                            with case.child([str(self.binary), *args], stdout_fd=write_fd,
                                            stdout_destination="pipe to command-1 (one-line consumer)") as child:
                                os.close(write_fd)
                                write_fd = None
                                # Parent must not retain a read end: only the real
                                # downstream process decides when the pipe closes.
                                source_pipe.close()
                                first, _ = consumer.finish()
                                case.check(bool(first), "real downstream receives a line then exits early")
                                child.finish(expected=1)
                    if mode == "jsonl":
                        case.results(first, [sources[0]["url"]])
                        saved = records(journal.read_bytes())
                        case.check(saved[0]["type"] == "result" and saved[-1]["type"] == "diagnostic", "SIGPIPE returns through journal cleanup rather than killing the process")
                    case.equal(report.read_bytes(), SENTINEL, "early downstream close does not publish partial report")
                finally:
                    if read_fd is not None:
                        os.close(read_fd)
                    if write_fd is not None:
                        os.close(write_fd)
            self.case("actual-early-downstream-close-" + mode, exercise)

        def slow_consumer(case):
            sources = [self.httpx_record(url=self.origin + f"/slow-{index}/" + "p" * 2048) for index in range(128)]
            capture = case.put("source.jsonl", jsonl(sources))
            report = case.path / "report.json"
            journal = case.path / "journal.jsonl"
            args = [*self.base, "--evidence", str(capture), "--evidence-format=httpx", "--output", str(report), "--diagnostics-journal", str(journal)]
            with case.child([str(self.binary), *args], pipe=True) as child:
                fill_stdout(case, child)
                saved = records(journal.read_bytes())
                case.check(0 < len(saved) < len(sources), "full stdout backpressures classification and journal admission")
                case.check(not report.exists(), "blocked output cannot prematurely publish a final report")
                deadline = time.monotonic() + TIMEOUT
                pace = threading.Event()
                while child.read_ready(deadline - time.monotonic(), size=2048):
                    # Intentional consumer pacing, not a readiness heuristic.
                    pace.wait(.002)
                out, _ = child.finish()
            rows = case.results(out, [source["url"] for source in sources])
            case.equal(json.loads(report.read_bytes()), rows, "slow consumer loses or duplicates no report records")
            case.equal([row["result"]["target"] for row in records(journal.read_bytes())], [source["url"] for source in sources], "backpressure preserves complete journal ordering")
        self.case("slow-consumer-backpressure", slow_consumer)

    def producer_cases(self):
        for index, httpx in enumerate(self.httpx_paths, 1):
            prefix = f"producer-{index:02d}"

            def version(case, httpx=httpx, index=index):
                out, err = case.run([str(httpx), "-version", "-duc"], raw_command=True)
                text = (out + err).decode(errors="replace").strip()
                case.check(bool(text), "actual supplied producer reports its version")
                self.report["httpx"][index - 1]["version_output"] = text
            self.case(prefix + "-version", version)

            modes = [
                ("summary", "/marker/summary", [], "text", True),
                ("text", "/marker/text", ["-irr"], "text", True),
                ("base64", "/marker/base64", ["-irrb", "-no-decode"], "base64", True),
                ("headers-only", "/marker/headers", ["-irh"], "text", True),
                ("redirect", "/redirect", ["-irr", "-follow-redirects"], "text", True),
                ("status-omitted", "/status-omitted", ["-irr", "-eof", "StatusCode"], "text", True),
                ("fragment", "/marker/fragment#section", ["-irr"], "text", True),
                ("chunked", "/chunked", ["-irr"], "text", True),
                ("empty-chunk-text", "/empty-chunk", ["-irr"], "text", True),
                ("empty-chunk-base64", "/empty-chunk", ["-irrb", "-no-decode"], "base64", True),
                ("failure-probe", "/drop/probe", [], "text", True),
                ("failure-without-probe", "/drop/no-probe", [], "text", False),
            ]
            for mode, route, export, encoding, probe in modes:
                def exercise(case, httpx=httpx, mode=mode, route=route, export=export, encoding=encoding, probe=probe):
                    url = self.origin + route
                    command = [str(httpx), "-u", url, "-silent", "-json", "-duc", "-timeout", "2", "-retries", "0", "-rstr", "4096", "-rsts", "8192", *export]
                    if probe:
                        command.append("-probe")
                    before = len(self.server.snapshot())
                    capture, _ = case.run(command, raw_command=True)
                    sources = records(capture)
                    case.row["observations"].update(upstream_records=len(sources), producer_fixture_requests=len(self.server.snapshot()) - before)
                    if mode.startswith("failure"):
                        attempts = self.server.snapshot()[before:]
                        case.check(any(event["path"] == route for event in attempts),
                                   "producer actually attempts the owned failure endpoint")
                        case.check(all(source.get("failed") or source.get("error") for source in sources), "failure exports never become successful source observations")
                        if not sources:
                            case.row["observations"]["upstream_omission"] = "No source record: importer must not invent a result or negative detection."
                    else:
                        case.equal(len(sources), 1, "producer emits one owned successful target")
                        case.check(not sources[0].get("failed"), "owned successful producer record is not marked failed")
                    before_import = self.server.snapshot()
                    importer = [*self.offline, "--httpx-response-encoding", encoding, "--strict"]
                    out, _ = case.import_run(importer, capture, expected=2 if sources else 0)
                    rows = case.results(out, [source.get("url") or source["input"] for source in sources])
                    case.equal(len(rows), len(sources), "importer preserves every actual upstream occurrence, including failures")
                    for occurrence, (row, source) in enumerate(zip(rows, sources), 1):
                        self.assert_httpx(case, row, source, occurrence, occurrence, encoding)
                        availability = row["evidence"][0]["availability"]
                        if mode in ("text", "base64", "redirect", "status-omitted", "fragment", "chunked", "empty-chunk-text", "empty-chunk-base64"):
                            wanted = HEADER_PRODUCTS | ({"Status fixture"} if mode == "status-omitted" else set())
                            case.equal(products(row), wanted, "actual raw export retains usable status/headers/cookies, never body matches")
                            case.equal(availability["headers"], "incomplete", "actual reconstructed headers remain positive-only")
                            expected_body = "unavailable" if mode.startswith("empty-chunk") else "unknown"
                            case.equal(availability["body"], expected_body, "producer body presence does not imply completeness")
                        elif mode in ("summary", "headers-only"):
                            expected_products = HEADER_PRODUCTS if source.get("raw_header") else set()
                            case.equal(products(row), expected_products, "summary/normalized fields cannot masquerade as complete raw evidence")
                        if mode == "redirect":
                            case.equal(source.get("final_url"), self.origin + "/marker/redirect-final", "producer reports the actually reached redirect URL")
                        if mode == "status-omitted":
                            case.equal(source["status_code"], 0, "producer field exclusion removes top-level status")
                            case.equal(row["evidence"][0]["status_code"], 403, "valid reconstructed dump recovers status")
                        if mode == "fragment":
                            case.equal(source["url"], url, "producer fragment attribution survives without reacquisition")
                        if mode.startswith("failure"):
                            case.check(row["provenance"]["import"].get("upstream_failed"), "actual upstream failure is explicit in import provenance")
                    case.equal(self.server.snapshot(), before_import, "actual producer capture import makes zero second fixture requests")
                self.case(prefix + "-" + mode, exercise)

    def run(self):
        self.worker.start()
        try:
            self.case("binary-version", lambda case: case.check(bool(case.run(["--version"])[0].strip()), "built binary reports its version"))
            self.url_cases()
            self.capture_cases()
            self.malformed_cases()
            self.output_cases()
            self.journal_cases()
            self.streaming_cases()
            self.producer_cases()
        finally:
            self.server.shutdown()
            self.worker.join(timeout=5)
            self.server.server_close()
            if self.worker.is_alive():
                raise RuntimeError("loopback server worker did not join")
        self.save(complete=True)
        summary = {key: self.report[key] for key in ("complete", "total", "passed", "failed")}
        summary["report"] = str(self.output / "report.json")
        print(json.dumps(summary, sort_keys=True), flush=True)
        return 1 if self.report["failed"] else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True, type=Path, help="existing built wafmeow executable")
    parser.add_argument("--httpx", required=True, action="append", type=Path, help="existing httpx executable; repeat for each actual version")
    parser.add_argument("--output", required=True, type=Path, help="new artifact directory; existing paths are never overwritten")
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("Linux is required for real signal and bounded kernel-pipe cases")
    paths = [args.binary, *args.httpx]
    resolved = []
    for path in paths:
        try:
            executable = path.resolve(strict=True)
        except OSError as error:
            parser.error(str(error))
        if not executable.is_file() or not os.access(executable, os.X_OK):
            parser.error(f"not an executable file: {executable}")
        resolved.append(executable)
    output = args.output.absolute()
    try:
        output.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        parser.error(str(error))
    matrix = Matrix(resolved[0], resolved[1:], output)
    try:
        return matrix.run()
    except BaseException:
        # Keep incomplete evidence on interruption or a harness setup failure too.
        matrix.report["harness_error"] = traceback.format_exc()
        matrix.save()
        raise


if __name__ == "__main__":
    sys.exit(main())
