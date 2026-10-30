import base64
import builtins
import hashlib
import io
import json
from pathlib import Path
import sys
import sysconfig
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import wafw00f_adapter
from wafw00f_adapter import ReplayResponse, ReplayViolation, classify, python_provenance


class EvidenceReplayTest(unittest.TestCase):
    def test_oversized_worker_input_is_rejected_before_loading_detector(self):
        request = json.dumps({"schema_version": 3, "profile": "shared-products",
                              "iterations": 1, "products": [], "cases": []}).encode()
        request += b" " * ((8 << 20) + 1 - len(request))
        original_import = builtins.__import__

        def guarded_import(name, *args, **kwargs):
            if name == "wafw00f":
                raise AssertionError("detector imported before input-size rejection")
            return original_import(name, *args, **kwargs)

        with patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(request))), \
                patch.object(builtins, "__import__", guarded_import):
            with self.assertRaisesRegex(ValueError, "worker input exceeds"):
                wafw00f_adapter.main()

    def test_worker_input_limit_counts_utf8_bytes_and_trailing_whitespace(self):
        value = {"marker": "\u00e9"}
        data = json.dumps(value, ensure_ascii=False).encode("utf-8")
        limit = 64
        with patch.object(wafw00f_adapter, "MAX_WORKER_INPUT_BYTES", limit):
            for size in (len(data), limit, limit + 1, limit + 2):
                with self.subTest(size=size):
                    stream = io.BytesIO(data + b" " * (size - len(data)))
                    if size <= limit:
                        self.assertEqual(wafw00f_adapter.read_worker_input(stream), value)
                    else:
                        with self.assertRaisesRegex(ValueError, "worker input exceeds 64 bytes"):
                            wafw00f_adapter.read_worker_input(stream)
                    self.assertLessEqual(stream.tell(), limit + 1)
                    self.assertFalse(stream.closed)

    def test_worker_input_rejects_trailing_json_and_invalid_utf8(self):
        for data in (b"{}\n{}", b'"\xff"'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                wafw00f_adapter.read_worker_input(io.BytesIO(data))

    def test_incomplete_body_preserves_metadata_but_never_matches_content(self):
        for uncertainty in ({"body_truncated": True}, {"transport_error": "unexpected EOF"}):
            with self.subTest(uncertainty=uncertainty):
                response = ReplayResponse({
                    "status_code": 403, "reason": "ModSecurity Action",
                    "headers": [{"name": "Server", "value": "origin"}, {"name": "server", "value": "cloudflare"}],
                    "body": base64.b64encode(b"marker").decode(), **uncertainty,
                })
                engine = SimpleNamespace(response=response)
                plugins = [
                    ("body", lambda item: "marker" in item.response.text),
                    ("metadata", lambda item: item.response.status_code == 403 and item.response.reason == "ModSecurity Action" and "cloudflare" in item.response.headers.get("SERVER")),
                ]
                state, reason, products, incomplete = classify(engine, plugins)
                self.assertEqual((state, reason, products, incomplete), ("incomplete", "", ("metadata",), ("body",)))
                with self.assertRaises(ReplayViolation):
                    _ = response.content

    def test_missing_response_and_zero_status_are_unknown_not_clean_negatives(self):
        for evidence in (None, {"status_code": 0, "reason": "", "transport_error": "connection unavailable"}):
            with self.subTest(evidence=evidence):
                response = ReplayResponse(evidence)
                state, _, products, incomplete = classify(response, [("header", lambda item: item.headers.get("server") == "cloudflare"), ("status", lambda item: item.status_code == 403)])
                self.assertEqual((state, products, incomplete), ("incomplete", (), ("header", "status")))

    def test_complete_negative_body_is_evaluable(self):
        response = ReplayResponse({"status_code": 200, "reason": "OK", "body": base64.b64encode(b"ordinary").decode()})
        self.assertEqual(classify(response, [("body", lambda item: "marker" in item.text)]), ("complete", "", (), ()))

    def test_provenance_observes_runtime_packages_and_source_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "__init__.py").write_text("# inert unit source\n", encoding="utf-8")
            (root / "main.py").write_text("# first inert unit source\n", encoding="utf-8")
            package = SimpleNamespace(__file__=str(root / "__init__.py"), __version__="2.4.2")
            distributions = [
                SimpleNamespace(metadata={"Name": "wafw00f"}, version="2.4.2"),
                SimpleNamespace(metadata={"Name": "Unit_Dependency"}, version="7.8.9"),
            ]
            with patch("wafw00f_adapter.importlib.metadata.distributions", return_value=distributions):
                first = python_provenance(package)
                self.assertEqual(first["executable"], sys.executable)
                self.assertEqual(first["runtime"], sys.version)
                self.assertEqual(first["executable_sha256"], hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest())
                self.assertEqual(first["packages"]["unit-dependency"], "7.8.9")
                (root / "main.py").write_text("# changed inert unit source\n", encoding="utf-8")
                second = python_provenance(package)
            self.assertNotEqual(first["source_tree_sha256"], second["source_tree_sha256"])
            self.assertNotEqual(first["sources"]["main.py"], second["sources"]["main.py"])
            canonical = json.dumps(second["sources"], sort_keys=True, separators=(",", ":")).encode()
            self.assertEqual(second["source_tree_sha256"], hashlib.sha256(canonical).hexdigest())

    def test_provenance_distinguishes_path_aliases_from_distinct_installations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("__init__.py", "main.py"):
                (root / name).write_text("# inert unit source\n", encoding="utf-8")
            package = SimpleNamespace(__file__=str(root / "__init__.py"), __version__="2.4.2")
            for name in ("site", "other"):
                metadata = root / name / "wafw00f-2.4.2.dist-info"
                metadata.mkdir(parents=True)
                (metadata / "METADATA").write_text("Name: wafw00f\nVersion: 2.4.2\n", encoding="utf-8")
            alias = root / "site-alias"
            alias.symlink_to(root / "site", target_is_directory=True)
            paths = [str(root / "site"), str(alias), sysconfig.get_path("stdlib")]
            with patch("wafw00f_adapter.sys.path", paths):
                provenance = python_provenance(package)
            self.assertEqual(provenance["packages"], {"wafw00f": "2.4.2"})
            with patch("wafw00f_adapter.sys.path", [*paths, str(root / "other")]):
                with self.assertRaises(ValueError):
                    python_provenance(package)

    def test_missing_or_wrong_installed_provenance_fails_closed(self):
        package = SimpleNamespace(__version__="2.4.2")
        for distributions in ([], [SimpleNamespace(metadata={"Name": "wafw00f"}, version="0.0")]):
            with self.subTest(distributions=distributions):
                with patch("wafw00f_adapter.importlib.metadata.distributions", return_value=distributions):
                    with self.assertRaises(ValueError):
                        python_provenance(package)


if __name__ == "__main__":
    unittest.main()
