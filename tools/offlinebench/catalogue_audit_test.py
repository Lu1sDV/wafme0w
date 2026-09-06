import json
from pathlib import Path
import tempfile
import unittest

from catalogue_audit import audit, exit_code


HELPERS = """class WAFW00F:
    def matchHeader(self, headermatch, attack=False):
        header, match = headermatch
        headerval = r.headers.get(header)
        return re.search(match, headerval, re.I)
    def matchCookie(self, match, attack=False):
        return self.matchHeader(('Set-Cookie', match), attack=attack)
    def matchContent(self, regex, attack=True):
        return re.search(regex, r.text, re.I)
    def matchStatus(self, statuscode, attack=True):
        return r.status_code == statuscode
    def matchReason(self, reasoncode, attack=True):
        return str(r.reason) == reasoncode
"""


class CatalogueAuditTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.plugins = self.root / "plugins"
        self.plugins.mkdir()
        (self.root / "__init__.py").write_text("__version__ = '2.4.2'\n", encoding="utf-8")
        (self.root / "main.py").write_text(HELPERS, encoding="utf-8")
        self.catalogue = self.root / "catalogue.json"

    def catalogue_with(self, fingerprints, name="Demo"):
        value = [{"name": name, "schemas": [{"fingerprints": fingerprints}]}]
        self.catalogue.write_text(json.dumps(value), encoding="utf-8")
        return value

    def plugin(self, source, filename="demo.py"):
        (self.plugins / filename).write_text(source, encoding="utf-8")

    def report(self):
        return audit(self.catalogue, self.plugins, "2.4.2")

    def test_literal_header_status_cookie_and_default_attack_are_distinct(self):
        self.plugin("""NAME = 'Demo'
raise AssertionError  # AST analysis must not execute this module.
def is_waf(self):
    self.matchHeader(headermatch=('sErVeR', 'Edge'), attack=True)
    self.matchStatus(403, False)
    self.matchCookie(r'^edge=')
    self.matchContent('blocked')
    self.matchReason('Exact Reason')
""")
        self.catalogue_with([
            {"type": "Header", "header_key": "Server", "header_value": "(?i)Edge", "attack": True},
            {"type": "Status", "pattern": "403"},
            {"type": "Cookie", "pattern": "(?i)^edge="},
            {"type": "Content", "pattern": "(?i)blocked"},
            {"type": "Reason", "pattern": "Exact Reason", "attack": True},
        ])
        report = self.report()
        self.assertTrue(report["structural_validity"]["valid"])
        atoms = report["products"][0]["catalogue_atoms"]
        self.assertEqual([a["status"] for a in atoms], ["matched", "matched", "matched", "changed", "matched"])
        self.assertEqual(atoms[3]["differences"][0]["fields"], ["attack"])
        self.assertTrue(report["parity"]["all_catalogue_literal_payloads_represented"])
        self.assertFalse(report["parity"]["all_catalogue_signatures_match"])
        self.assertFalse(report["parity"]["equivalence_established"])
        self.assertEqual((exit_code(report), exit_code(report, True)), (0, 1))

    def test_reason_metacharacters_and_flags_remain_literal(self):
        self.plugin("NAME = 'Demo'\ndef is_waf(self):\n    return self.matchReason('(?i)Denied [policy].')\n")
        self.catalogue_with([{"type": "Reason", "pattern": "(?i)Denied [policy].", "attack": True}])
        self.assertEqual(exit_code(self.report(), True), 0)
        self.catalogue_with([{"type": "Reason", "pattern": "Denied [policy].", "attack": True}])
        self.assertEqual(exit_code(self.report(), True), 1)

    def test_stale_atoms_and_upstream_only_products_are_reported_in_both_directions(self):
        self.plugin("NAME = 'Demo'\ndef is_waf(self):\n    return self.matchHeader(('Server', 'new'))\n")
        self.plugin("NAME = 'New Product'\ndef is_waf(self):\n    return self.matchStatus(404)\n", "new.py")
        self.catalogue_with([{"type": "Header", "header_key": "Server", "header_value": "(?i)old"}])
        report = self.report()
        product = report["products"][0]
        self.assertEqual(product["catalogue_atoms"][0]["status"], "unmatched")
        self.assertEqual(product["upstream_atoms"][0]["status"], "missing")
        self.assertEqual([p["name"] for p in report["upstream_only"]], ["New Product"])
        self.assertEqual(report["parity"]["status"], "differences")
        self.assertFalse(report["parity"]["all_catalogue_literal_payloads_represented"])
        self.assertEqual((exit_code(report), exit_code(report, True)), (0, 1))
        self.catalogue_with([{"type": "Status", "pattern": "403"}], name="Retired Product")
        report = self.report()
        self.assertEqual(report["parity"]["catalogue_only_products"], ["Retired Product"])
        self.assertIsNone(report["products"][0]["source_path"])

    def test_dynamic_unknown_and_indirect_calls_prevent_strict_parity(self):
        self.plugin("""NAME = 'Demo'
def is_waf(self):
    self.matchHeader(('Server', 'known'))
    self.matchContent(pattern)
    self.matchCookie('cookie', attack=dynamic)
    self.matchUnknown('unknown')
    alias = self.matchStatus
    alias(403)
    getattr(self, 'matchReason')('reason')
""")
        self.catalogue_with([{"type": "Header", "header_key": "Server", "header_value": "(?i)known"}])
        report = self.report()
        self.assertEqual(report, self.report())  # No AST object addresses or run timestamps.
        self.assertTrue(report["structural_validity"]["valid"])
        self.assertTrue(report["parity"]["all_catalogue_signatures_match"])
        self.assertEqual(report["parity"]["status"], "unresolved")
        self.assertEqual(exit_code(report, True), 1)
        messages = "\n".join(i["message"] for i in report["products"][0]["unsupported"])
        for detail in ("matchUnknown", "alias(403)", "getattr"):
            with self.subTest(detail=detail):
                self.assertIn(detail, messages)

    def test_inline_flags_are_normalized_but_raw_escaping_and_scoped_flags_are_preserved(self):
        self.plugin(r"""NAME = 'Demo'
def is_waf(self):
    self.matchContent(r'(?m)^block\.[a-z]+$')
    self.matchContent(r'a\.')
    self.matchContent(r'(?-i:Exact)')
""")
        self.catalogue_with([
            {"type": "Content", "pattern": r"(?im)^block\.[a-z]+$", "attack": True},
            {"type": "Content", "pattern": r"(?i)a\\.", "attack": True},
            {"type": "Content", "pattern": r"(?i)(?-i:Exact)", "attack": True},
        ])
        report = self.report()
        product = report["products"][0]
        self.assertTrue(report["structural_validity"]["valid"])
        self.assertEqual([a["status"] for a in product["catalogue_atoms"]], ["matched", "unmatched", "matched"])
        self.assertEqual(product["upstream_atoms"][1]["signature"]["pattern"], r"a\.")
        self.assertEqual(product["catalogue_atoms"][1]["signature"]["pattern"], r"a\\.")
        self.assertEqual(product["catalogue_atoms"][2]["signature"]["pattern"], r"(?-i:Exact)")

    def test_duplicate_names_keys_and_malformed_fields_are_structural_errors(self):
        self.plugin("NAME = 'Demo'\ndef is_waf(self):\n    return self.matchStatus(403)\n")
        valid = {"name": "Demo", "schemas": [{"fingerprints": [{"type": "Status", "pattern": "403"}]}]}
        cases = [
            ([valid, valid], "duplicate product name"),
            ([{"name": "Demo", "schemas": [{"any": 1, "fingerprints": [{"type": "Status", "pattern": "403"}]}]}], "any"),
            ([{"name": "Demo", "schemas": [{"fingerprints": [{"type": "Content", "pattern": "x", "attack": 1}]}]}], "attack"),
            ([{"name": "Demo", "schemas": [{"fingerprints": [{"type": "Header", "header_key": "Server"}]}]}], "header_value"),
            ([{"name": "Demo", "schemas": [{"fingerprints": [{"type": "Cookie", "pattern": True}]}]}], "pattern"),
            ([{"name": "Demo", "schemas": [{"fingerprints": [{"type": "Content", "pattern": "x", "header_key": "Server"}]}]}], "unsupported field"),
            ([{"name": "Demo", "schemas": [{"fingerprints": [{"type": "Unknown", "pattern": "x"}]}]}], "unsupported fingerprint type"),
            ({"name": "Demo"}, "JSON array"),
        ]
        for definitions, detail in cases:
            with self.subTest(detail=detail):
                self.catalogue.write_text(json.dumps(definitions), encoding="utf-8")
                report = self.report()
                self.assertEqual((exit_code(report), report["parity"]["status"]), (2, "invalid"))
        self.catalogue.write_text('[{"name":"Demo","name":"Other","schemas":[]}]', encoding="utf-8")
        self.assertEqual(exit_code(self.report()), 2)
        self.catalogue.write_text('[{"name":', encoding="utf-8")
        self.assertEqual(exit_code(self.report()), 2)

    def test_invalid_source_regex_syntax_version_and_duplicate_upstream_names_fail(self):
        self.catalogue_with([{"type": "Content", "pattern": "(?i)valid", "attack": True}])
        for source in ("NAME = 'Demo'\ndef is_waf(self):\n    return self.matchContent('[')\n",
                       "NAME = 'Demo'\ndef is_waf(:\n", "def is_waf(self):\n    return False\n"):
            with self.subTest(source=source):
                self.plugin(source)
                self.assertEqual(exit_code(self.report()), 2)
        source = "NAME = 'Demo'\ndef is_waf(self):\n    return self.matchContent('valid')\n"
        self.plugin(source)
        self.assertEqual(exit_code(audit(self.catalogue, self.plugins, "wrong-version")), 2)
        self.plugin(source, "duplicate.py")
        self.assertEqual(exit_code(self.report()), 2)

    def test_unknown_helper_contract_and_go_only_regex_are_unresolved_not_blessed(self):
        self.plugin("NAME = 'Demo'\ndef is_waf(self):\n    return self.matchContent('valid')\n")
        self.catalogue_with([{"type": "Content", "pattern": r"(?i)\p{Greek}", "attack": True}])
        report = self.report()
        self.assertTrue(report["structural_validity"]["valid"])
        self.assertEqual(report["products"][0]["catalogue_atoms"][0]["status"], "unsupported")
        self.assertEqual(exit_code(report, True), 1)
        self.catalogue_with([{"type": "Content", "pattern": "(?i)valid", "attack": True}])
        report = self.report()
        self.assertEqual((exit_code(report, True), report["parity"]["status"]), (0, "atom_inventory_match"))
        self.assertFalse(report["parity"]["equivalence_established"])
        (self.root / "main.py").write_text(HELPERS.replace("re.I", "0"), encoding="utf-8")
        report = self.report()
        self.assertTrue(report["structural_validity"]["valid"])
        self.assertEqual(report["products"][0]["upstream_atoms"][0]["status"], "unsupported")
        self.assertEqual(exit_code(report, True), 1)


if __name__ == "__main__":
    unittest.main()
