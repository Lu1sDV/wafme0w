import base64
import hashlib
import json
from pathlib import Path
import sys
import sysconfig
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from wafw00f_adapter import ReplayResponse, ReplayViolation, classify, python_provenance


class EvidenceReplayTest(unittest.TestCase):
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
