#!/usr/bin/env python3
"""Schema v3, selected named-plugin replay, never live detection.

Normal/Attack select wafw00f's original response roles (unlike native cross-response
rules). Repeated header values retain order and use requests-style comma joining.
Missing metadata raises only when status/reason/headers are accessed. A truncated
or errored body raises only when content/text is accessed: headers remain usable.
An unavailable access or attempted request makes that plugin unknown. Imperative
plugin evaluation stops there; it does not claim native three-valued OR/AND logic.
Generic detection is not run and is never included in classification timings.
"""
# pyright: reportMissingImports=false

import base64
import hashlib
import importlib.metadata
import json
import logging
from pathlib import Path
import platform
import socket
import sys
import time


class IsolationViolation(RuntimeError):
    pass


class ReplayViolation(RuntimeError):
    pass


class HeaderMap:
    def __init__(self, pairs):
        values = {}
        for pair in pairs:
            values.setdefault(pair["name"].lower(), []).append(pair["value"])
        self._values = {name: ", ".join(items) for name, items in values.items()}

    def get(self, name, default=None):
        return self._values.get(name.lower(), default)

    def __getitem__(self, name):
        return self._values[name.lower()]

    def __contains__(self, name):
        return name.lower() in self._values

    def items(self):
        return self._values.items()


class ReplayResponse:
    def __init__(self, evidence):
        self._evidence = evidence
        self._headers = HeaderMap(evidence.get("headers", [])) if evidence else None
        self._content = base64.b64decode(evidence.get("body", ""), validate=True) if evidence else b""
        self._text = self._content.decode("utf-8", errors="replace")

    def _metadata(self, field):
        if not self._evidence or self._evidence.get("status_code", 0) == 0:
            raise ReplayViolation("unavailable response metadata: " + field)

    @property
    def status_code(self):
        self._metadata("status")
        return self._evidence["status_code"]

    @property
    def reason(self):
        self._metadata("reason")
        return self._evidence["reason"]

    @property
    def headers(self):
        self._metadata("headers")
        return self._headers

    def _body(self):
        self._metadata("body")
        if self._evidence.get("body_truncated") or self._evidence.get("transport_error"):
            raise ReplayViolation("unavailable complete body")

    @property
    def content(self):
        self._body()
        return self._content

    @property
    def text(self):
        self._body()
        return self._text


def classify(engine, plugins):
    detected, incomplete = [], []
    failed = ""
    for name, plugin in plugins:
        try:
            matched = bool(plugin(engine))
        except ReplayViolation:
            incomplete.append(name)
            continue
        except IsolationViolation:
            raise
        except Exception as error:
            failed = f"{name}: {type(error).__name__}: {error}"
            break
        if matched:
            detected.append(name)
    state = "failed" if failed else ("incomplete" if incomplete else "complete")
    return state, failed, tuple(detected), tuple(incomplete)


def python_provenance(wafw00f):
    """Observe the invoked interpreter and installed source; never infer from requirements."""
    packages = {}
    search_paths = sorted({str(Path(path).resolve()) for path in sys.path})
    for distribution in importlib.metadata.distributions(path=search_paths):
        name = distribution.metadata["Name"]
        version = distribution.version
        if not name or not version:
            raise ValueError("installed distribution lacks name or version")
        name = name.lower().replace("_", "-").replace(".", "-")
        if name in packages:
            raise ValueError("duplicate installed distribution: " + name)
        packages[name] = version
    if packages.get("wafw00f") != "2.4.2" or wafw00f.__version__ != "2.4.2":
        raise ValueError("observed wafw00f must match pinned version 2.4.2")
    root = Path(wafw00f.__file__).resolve().parent
    sources = {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*.py")) if path.is_file()
    }
    if "__init__.py" not in sources or "main.py" not in sources:
        raise ValueError("upstream Python source is unavailable")
    canonical_sources = json.dumps(sources, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    canonical_sources = canonical_sources.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return {
        "executable": sys.executable,
        "executable_real_path": str(Path(sys.executable).resolve()),
        "executable_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        "runtime": sys.version, "implementation": platform.python_implementation(),
        "platform": platform.platform(), "packages": packages,
        "pinned_wafw00f_version": "2.4.2", "upstream_root": str(root),
        "sources": sources,
        "source_tree_sha256": hashlib.sha256(canonical_sources.encode("utf-8")).hexdigest(),
        "worker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def main():
    request = json.load(sys.stdin)
    if request.get("schema_version") != 3 or request.get("iterations", 0) < 1 or request.get("profile") != "shared-products":
        raise ValueError("invalid worker schema, profile, or iteration count")

    initialized = time.perf_counter_ns()
    import wafw00f
    from wafw00f.main import WAFW00F

    class ReplayWAF(WAFW00F):
        def __init__(self, responses):
            self.rq = responses.get("Normal", ReplayResponse(None))
            self.attackres = responses.get("Attack", ReplayResponse(None))
            self.headers = {}
            self.knowledge = {"generic": {"found": False, "reason": ""}, "wafname": []}
            self.log = logging.getLogger("offlinebench.wafw00f")

        def Request(self, *_args, **_kwargs):
            raise ReplayViolation("network request attempted by plugin")

    selected = [product["names"]["wafw00f"] for product in request["products"]]
    missing_plugins = sorted(set(selected) - set(WAFW00F.wafdetections))
    if missing_plugins:
        raise ValueError("missing requested plugins: " + ", ".join(missing_plugins))
    plugins = [(name, WAFW00F.wafdetections[name]) for name in sorted(selected)]
    init_ns = time.perf_counter_ns() - initialized
    provenance = python_provenance(wafw00f)

    original_socket = socket.socket

    class DeniedSocket:
        def __init__(self, *_args, **_kwargs):
            raise IsolationViolation("adapter attempted to create a socket")

    socket.socket = DeniedSocket
    results = []
    try:
        for case in request["cases"]:
            started = time.perf_counter_ns()
            responses = {item["role"]: ReplayResponse(item) for item in case["responses"]}
            preparation_ns = time.perf_counter_ns() - started
            first = classify(ReplayWAF(responses), plugins)  # Untimed warm-up.
            elapsed = setup_ns = 0
            for _ in range(request["iterations"]):
                started = time.perf_counter_ns()
                engine = ReplayWAF(responses)
                setup_ns += time.perf_counter_ns() - started
                started = time.perf_counter_ns()
                observation = classify(engine, plugins)
                elapsed += time.perf_counter_ns() - started
                if observation != first:
                    raise RuntimeError(f"case {case['id']} produced nondeterministic output")
            state, reason, detected, incomplete = first
            results.append({
                "case_id": case["id"], "state": state, "reason": reason,
                "raw_products": sorted(detected), "incomplete_products": sorted(incomplete),
                "preparation_ns": preparation_ns + setup_ns // request["iterations"],
                "elapsed_ns": elapsed // request["iterations"],
            })
    finally:
        socket.socket = original_socket

    json.dump({
        "schema_version": 3, "profile": "shared-products", "tool": "wafw00f",
        "version": wafw00f.__version__, "adapter_mode": "selected-plugin-evidence-replay",
        "semantics": __doc__, "preparation_ns": 0, "init_ns": init_ns,
        "catalogue_size": len(plugins), "results": results,
        "python": provenance,
    }, sys.stdout, separators=(",", ":"), sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"offline wafw00f adapter: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1)
