#!/usr/bin/env python3
"""Audit literal signature inventory without importing or executing wafw00f.

Exit 0 means structurally valid input, NOT parity. Exit 2 means malformed input.
--strict-parity additionally exits 1 for differences or unresolved expressions.
Even an atom_inventory_match does not establish plugin/matcher equivalence.
"""

import argparse
import ast
from collections import Counter
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import tokenize


TYPES = ("Content", "Cookie", "Header", "Status", "Reason")
PARAMETERS = dict(zip(TYPES, ("regex", "match", "headermatch", "statuscode", "reasoncode")))
FLAGS = {"a": re.A, "i": re.I, "L": re.L, "m": re.M, "s": re.S, "u": re.U, "x": re.X}
LIMITATIONS = [
    "Comparison is syntactic literal atom inventory, not plugin or schema equivalence.",
    "Repeated atoms are compared by presence, not multiplicity; every catalogue fingerprint and direct upstream match call remains a separate record.",
    "All direct self.match* calls are inventoried, including helper functions and unreachable code; control flow, negation, AND/OR grouping and reachability are not evaluated.",
    "Attack defaults come from upstream helper parameters; catalogue omission means false. Native Attack is metadata, not an enforced response role.",
    "Header names are compared case-insensitively. Cookie parsing, repeated-header handling and response roles are not compared.",
    "Only leading global Python regex flags are normalized. Pattern spelling and escaping are otherwise preserved; no regex language equivalence is inferred.",
    "Python regex compilation is not Go regexp validation or cross-engine equivalence. Go-only syntax is reported unresolved; validate the catalogue with the Go engine separately.",
    "Reason matching is exact, case-sensitive literal equality in both engines; regex flags and metacharacters remain literal text.",
    "Helper defaults and matching primitives are inspected with AST, not symbolically executed. Source hashes identify the exact inputs; a version label is not package authenticity verification.",
]


def issue(items, path, location, message):
    items.append({"path": str(path), "location": location, "message": message})


def read_source(path, provenance, errors):
    try:
        data = path.read_bytes()
        provenance.append({"path": str(path), "sha256": hashlib.sha256(data).hexdigest()})
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        text = data.decode(encoding)
        return text, ast.parse(text, filename=str(path))
    except (OSError, UnicodeError, SyntaxError, LookupError) as exc:
        issue(errors, path, "source", str(exc))
        return None, None


def literal_value(node):
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        # ast.literal_eval's exception embeds an object's nondeterministic address.
        raise ValueError(f"nonliteral expression ({type(node).__name__})") from None


def literal_assignment(tree, name):
    values = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            values.append(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            values.append(node.value)
    if len(values) != 1:
        raise ValueError(f"expected exactly one top-level {name} assignment")
    value = literal_value(values[0])
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty literal string")
    return value


def same_ast(node, expression):
    return ast.dump(node) == ast.dump(ast.parse(expression, mode="eval").body)


def helper_contracts(tree, path, unresolved):
    """Recognize only the installed helpers' small, explicit matching primitives."""
    contracts = {}
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "WAFW00F"]
    methods = [n for c in classes for n in c.body if isinstance(n, ast.FunctionDef)]
    for kind in ("Header", "Content", "Status", "Reason", "Cookie"):
        name = "match" + kind
        found = [n for n in methods if n.name == name]
        try:
            if len(found) != 1:
                raise ValueError("expected exactly one WAFW00F helper definition")
            node = found[0]
            args = node.args
            if (args.posonlyargs or args.kwonlyargs or args.vararg or args.kwarg
                    or [a.arg for a in args.args] != ["self", PARAMETERS[kind], "attack"]
                    or len(args.defaults) != 1):
                raise ValueError("unsupported helper parameter contract")
            attack = literal_value(args.defaults[0])
            if type(attack) is not bool:
                raise ValueError("attack default is not a literal boolean")
            flags = 0
            operator = "regex_search"
            if kind == "Cookie":
                body = [n for n in node.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str))]
                if (len(body) != 1 or not isinstance(body[0], ast.Return)
                        or not same_ast(body[0].value, "self.matchHeader(('Set-Cookie', match), attack=attack)")
                        or "Header" not in contracts):
                    raise ValueError("unsupported cookie delegation")
                flags = contracts["Header"]["flags"]
            elif kind in ("Content", "Header"):
                calls = [n for n in ast.walk(node) if isinstance(n, ast.Call)
                         and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
                         and n.func.value.id == "re"]
                expected = "re.search(regex, r.text, re.I)" if kind == "Content" else "re.search(match, headerval, re.I)"
                alternate = expected.replace("re.I)", "re.IGNORECASE)")
                if len(calls) != 1 or not (same_ast(calls[0], expected) or same_ast(calls[0], alternate)):
                    raise ValueError("unsupported regex matching primitive/flags")
                flags = int(re.I)
            else:
                expression = "r.status_code == statuscode" if kind == "Status" else "str(r.reason) == reasoncode"
                if not any(isinstance(n, ast.Compare) and same_ast(n, expression) for n in ast.walk(node)):
                    raise ValueError("unsupported equality matching primitive")
                operator = "integer_equality" if kind == "Status" else "literal_equality"
            contracts[kind] = {"attack_default": attack, "flags": flags, "operator": operator, "line": node.lineno}
        except (ValueError, TypeError) as exc:
            issue(unresolved, path, name, str(exc))
    return contracts


def regex_signature(pattern, flags=0):
    """Strip only leading global flags, never escapes, scoped flags or anchors."""
    compiled = re.compile(pattern, flags)
    rest = pattern
    while (match := re.match(r"^\(\?([aiLmsux]+)\)", rest)) is not None:
        rest = rest[match.end():]
    effective = compiled.flags & ~int(re.U)  # Unicode is the implicit Python str default.
    return rest, [name for name, bit in FLAGS.items() if effective & bit]


def go_only_syntax(pattern):
    # Recognize dialect-related compile failures without rewriting the pattern.
    return (re.search(r"(?<!\\)(?:\\\\)*\\(?:[pP]\{|[QEz])", pattern) is not None
            or re.search(r"\(\?[imsU-]*U|\(\?[imsU]*-[imsU]+\)", pattern) is not None)


def normalize(kind, pattern, header, attack, operator, flags, path, location, errors, unresolved, catalogue=False):
    signature = {"type": kind, "header_key": header.lower(), "pattern": pattern,
                 "flags": [], "attack": attack, "operator": operator}
    if operator == "regex_search":
        try:
            signature["pattern"], signature["flags"] = regex_signature(pattern, flags)
        except (re.error, ValueError, OverflowError) as exc:
            if catalogue and go_only_syntax(pattern):
                issue(unresolved, path, location, "Go-specific regex syntax: Python comparison unavailable; pattern preserved")
            else:
                issue(errors, path, location, f"invalid Python-comparable regex: {exc}")
            return None
    return signature


def load_catalogue(path, errors, unresolved):
    provenance = {"path": str(path)}

    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON field {key!r}")
            result[key] = value
        return result

    def shape(value, allowed, required, location):
        if not isinstance(value, dict):
            issue(errors, path, location, "expected an object")
            return False
        for key in sorted(value.keys() - allowed):
            issue(errors, path, location, f"unsupported field {key!r}")
        for key in sorted(required - value.keys()):
            issue(errors, path, location, f"missing field {key!r}")
        return True

    def reject_constant(value):
        raise ValueError(f"invalid JSON constant {value}")

    try:
        data = path.read_bytes()
        provenance["sha256"] = hashlib.sha256(data).hexdigest()
        definitions = json.loads(data, object_pairs_hook=object_pairs, parse_constant=reject_constant)
    except (OSError, UnicodeError, ValueError) as exc:
        issue(errors, path, "catalogue", str(exc))
        return [], provenance, {"products": 0, "schemas": 0, "fingerprints": 0, "by_type": {}}
    inventory = {"products": 0, "schemas": 0, "fingerprints": 0, "by_type": Counter()}
    if not isinstance(definitions, list):
        issue(errors, path, "catalogue", "expected a JSON array")
        return [], provenance, inventory
    inventory["products"] = len(definitions)
    products, names = [], set()
    for wi, waf in enumerate(definitions):
        location = f"products[{wi}]"
        if not shape(waf, {"name", "schemas"}, {"name", "schemas"}, location):
            continue
        name = waf.get("name")
        if not isinstance(name, str) or not name.strip():
            issue(errors, path, location, "name must be a nonempty string")
            continue
        if name in names:
            issue(errors, path, location, f"duplicate product name {name!r}")
        names.add(name)
        product = {"name": name, "catalogue_index": wi, "schemas": [], "atoms": []}
        products.append(product)
        schemas = waf.get("schemas")
        if not isinstance(schemas, list) or not schemas:
            issue(errors, path, location, "schemas must be a nonempty array")
            continue
        inventory["schemas"] += len(schemas)
        for si, schema in enumerate(schemas):
            sloc = f"{location}.schemas[{si}]"
            if not shape(schema, {"any", "fingerprints"}, {"fingerprints"}, sloc):
                continue
            if "any" in schema and type(schema["any"]) is not bool:
                issue(errors, path, sloc, "any must be a boolean")
            product["schemas"].append({"index": si, "any": schema.get("any", False)})
            fps = schema.get("fingerprints")
            if not isinstance(fps, list) or not fps:
                issue(errors, path, sloc, "fingerprints must be a nonempty array")
                continue
            inventory["fingerprints"] += len(fps)
            for fi, fp in enumerate(fps):
                floc = f"{sloc}.fingerprints[{fi}]"
                start_errors = len(errors)
                atom = {"schema_index": si, "fingerprint_index": fi, "definition": fp, "signature": None}
                product["atoms"].append(atom)
                if not shape(fp, {"type", "pattern", "header_key", "header_value", "attack"}, {"type"}, floc):
                    continue
                kind = fp.get("type")
                if not isinstance(kind, str) or kind not in TYPES:
                    issue(errors, path, floc, "unsupported fingerprint type")
                    continue
                inventory["by_type"][kind] += 1
                allowed = {"type", "attack", "header_key", "header_value"} if kind == "Header" else {"type", "attack", "pattern"}
                shape(fp, allowed, allowed - {"attack"}, floc)
                for key in sorted(fp.keys() & {"type", "pattern", "header_key", "header_value"}):
                    if not isinstance(fp[key], str) or not fp[key]:
                        issue(errors, path, floc, f"{key} must be a nonempty string")
                if "attack" in fp and type(fp["attack"]) is not bool:
                    issue(errors, path, floc, "attack must be a boolean")
                if len(errors) != start_errors:
                    continue
                pattern = fp["header_value"] if kind == "Header" else fp["pattern"]
                if kind == "Status" and re.fullmatch(r"[1-9][0-9]{2}", pattern) is None:
                    issue(errors, path, floc, "status pattern must be a three-digit integer from 100 through 999")
                    continue
                atom["signature"] = normalize(kind, pattern, fp.get("header_key", ""), fp.get("attack", False),
                    "integer_equality" if kind == "Status" else "literal_equality" if kind == "Reason" else "regex_search",
                    0, path, floc, errors, unresolved, catalogue=True)
    inventory["by_type"] = dict(sorted(inventory["by_type"].items()))
    return products, provenance, inventory


def extract_call(call, kind, contracts):
    if len(call.args) > 2 or any(isinstance(arg, ast.Starred) for arg in call.args):
        raise ValueError("unsupported positional argument shape")
    values = dict(zip((PARAMETERS[kind], "attack"), call.args))
    for keyword in call.keywords:
        if keyword.arg not in (PARAMETERS[kind], "attack") or keyword.arg in values:
            raise ValueError("unsupported, unpacked or duplicate keyword argument")
        values[keyword.arg] = keyword.value
    if PARAMETERS[kind] not in values:
        raise ValueError("missing signature argument")
    value = literal_value(values[PARAMETERS[kind]])
    header = ""
    if kind == "Header":
        if not isinstance(value, (tuple, list)) or len(value) != 2:
            raise ValueError("header argument is not a literal pair")
        header, value = value
        if not isinstance(header, str) or not header:
            raise ValueError("header name is not a nonempty literal string")
    if kind == "Status":
        if type(value) is not int or not 100 <= value <= 999:
            raise ValueError("status argument is not a literal HTTP status integer")
        value = str(value)
    elif not isinstance(value, str) or not value:
        raise ValueError("signature argument is not a nonempty literal string")
    if kind not in contracts:
        raise ValueError("upstream helper semantics are unresolved")
    contract = contracts[kind]
    attack = literal_value(values["attack"]) if "attack" in values else contract["attack_default"]
    if type(attack) is not bool:
        raise ValueError("attack argument is not a literal boolean")
    return value, header, attack, "attack" in values


def parse_plugin(path, text, tree, contracts, errors):
    unsupported = []
    try:
        name = literal_assignment(tree, "NAME")
    except (ValueError, TypeError) as exc:
        issue(unsupported if str(exc).startswith("nonliteral expression") else errors, path, "NAME", str(exc))
        name = None
    product = {"name": name, "source_path": str(path), "atoms": [], "unsupported": unsupported}
    functions = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    if "is_waf" not in functions:
        issue(errors, path, "is_waf", "missing top-level is_waf function")
    calls = sorted((n for n in ast.walk(tree) if isinstance(n, ast.Call)), key=lambda n: (n.lineno, n.col_offset))
    direct_functions = {id(n.func) for n in calls}
    for node in ast.walk(tree):
        if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self"
                and node.attr.startswith("match") and id(node) not in direct_functions):
            issue(unsupported, path, f"{node.lineno}:{node.col_offset}", "match helper referenced indirectly; alias not resolved")
    for call in calls:
        location = f"{call.lineno}:{call.col_offset}"
        if not (isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "self" and call.func.attr.startswith("match")):
            # A local function dispatch is recorded by the all-functions inventory,
            # not interpreted as a schema or proof that its atoms are reachable.
            if not (isinstance(call.func, ast.Name) and call.func.id in functions):
                issue(unsupported, path, location, f"non-match call not evaluated: {ast.get_source_segment(text, call)}")
            continue
        atom = {"line": call.lineno, "column": call.col_offset, "expression": ast.get_source_segment(text, call), "signature": None}
        product["atoms"].append(atom)
        kind = call.func.attr[5:]
        try:
            if kind not in TYPES:
                raise ValueError("unsupported match helper " + call.func.attr)
            value, header, attack, explicit = extract_call(call, kind, contracts)
            atom["attack_explicit"] = explicit
            atom["signature"] = normalize(kind, value, header, attack, contracts[kind]["operator"],
                contracts[kind]["flags"], path, location, errors, unsupported)
        except (ValueError, TypeError) as exc:
            issue(unsupported, path, location, "unsupported/dynamic signature: " + str(exc))
    return product


def payload(signature):
    return tuple(signature[key] for key in ("type", "header_key", "pattern"))


def compare_product(catalogue, upstream):
    result = {"name": catalogue["name"], "catalogue_index": catalogue["catalogue_index"],
              "schemas": catalogue["schemas"], "source_path": upstream["source_path"] if upstream else None,
              "catalogue_atoms": catalogue["atoms"], "upstream_atoms": upstream["atoms"] if upstream else [],
              "unsupported": upstream["unsupported"] if upstream else []}
    for atom in result["upstream_atoms"]:
        atom.update(status="missing", catalogue_atom_indices=[])
        if atom["signature"] is None:
            atom["status"] = "unsupported"
    for ci, atom in enumerate(result["catalogue_atoms"]):
        signature = atom["signature"]
        atom.update(status="unmatched", upstream_atom_indices=[], differences=[])
        if signature is None:
            atom["status"] = "unsupported"
            continue
        candidates = [(ui, other) for ui, other in enumerate(result["upstream_atoms"])
                      if other["signature"] is not None and payload(signature) == payload(other["signature"])]
        exact = [(ui, other) for ui, other in candidates if signature == other["signature"]]
        atom["status"] = "matched" if exact else "changed" if candidates else "unmatched"
        for ui, other in exact or candidates:
            atom["upstream_atom_indices"].append(ui)
            other["catalogue_atom_indices"].append(ci)
            if other["status"] != "matched":
                other["status"] = atom["status"]
            differences = [key for key in signature if signature[key] != other["signature"][key]]
            if differences:
                atom["differences"].append({"upstream_atom_index": ui, "fields": differences})
    return result


def audit(catalogue_path, plugin_directory, version):
    catalogue_path, plugin_directory = Path(catalogue_path), Path(plugin_directory)
    errors, unresolved, sources = [], [], []
    catalogue, catalogue_source, inventory = load_catalogue(catalogue_path, errors, unresolved)
    version_path = plugin_directory.parent / "__init__.py"
    _, version_tree = read_source(version_path, sources, errors)
    observed_version = None
    if version_tree is not None:
        try:
            observed_version = literal_assignment(version_tree, "__version__")
            if observed_version != version:
                issue(errors, version_path, "__version__", f"declared version {version!r} differs from source {observed_version!r}")
        except (ValueError, TypeError) as exc:
            issue(errors, version_path, "__version__", str(exc))
    if not isinstance(version, str) or not version.strip():
        issue(errors, version_path, "version", "explicit version provenance is required")
    helper_path = plugin_directory.parent / "main.py"
    _, helper_tree = read_source(helper_path, sources, errors)
    contracts = helper_contracts(helper_tree, helper_path, unresolved) if helper_tree is not None else {}
    plugins = []
    if not plugin_directory.is_dir():
        issue(errors, plugin_directory, "plugins", "plugin directory does not exist")
    paths = sorted(plugin_directory.glob("*.py"))
    if not any(p.name != "__init__.py" for p in paths):
        issue(errors, plugin_directory, "plugins", "no plugin source files")
    for path in paths:
        text, tree = read_source(path, sources, errors)
        if tree is not None and path.name != "__init__.py":
            plugins.append(parse_plugin(path, text, tree, contracts, errors))
    by_name = {}
    for plugin in plugins:
        name = plugin["name"]
        if name is None:
            continue
        if name in by_name:
            issue(errors, plugin["source_path"], "NAME", f"duplicate upstream product name {name!r}")
        else:
            by_name[name] = plugin
    products = [compare_product(p, by_name.get(p["name"])) for p in sorted(catalogue, key=lambda p: (p["name"], p["catalogue_index"]))]
    catalogue_names = {p["name"] for p in catalogue}
    upstream_only = [p for p in plugins if p["name"] not in catalogue_names]
    catalogue_counts = Counter(a["status"] for p in products for a in p["catalogue_atoms"])
    upstream_counts = Counter(a["status"] for p in products for a in p["upstream_atoms"])
    missing_products = [p["name"] for p in products if p["source_path"] is None]
    unsupported_count = len(unresolved) + sum(len(p["unsupported"]) for p in plugins)
    differences = bool(missing_products or upstream_only or catalogue_counts["changed"] or catalogue_counts["unmatched"]
                       or upstream_counts["missing"] or upstream_counts["changed"])
    unresolved_parity = bool(unsupported_count or catalogue_counts["unsupported"] or upstream_counts["unsupported"])
    status = "invalid" if errors else "differences" if differences else "unresolved" if unresolved_parity else "atom_inventory_match"
    return {
        "schema_version": 1,
        "provenance": {"catalogue": catalogue_source, "plugin_directory": str(plugin_directory),
                       "declared_wafw00f_version": version, "source_wafw00f_version": observed_version,
                       "python_regex_version": sys.version.split()[0], "sources": sorted(sources, key=lambda p: p["path"])},
        "structural_validity": {"valid": not errors, "errors": errors},
        "parity": {"status": status, "equivalence_established": False,
                   "all_catalogue_products_found": not errors and not missing_products,
                   "all_catalogue_literal_payloads_represented": not errors and not (catalogue_counts["unmatched"] or catalogue_counts["unsupported"]),
                   "all_catalogue_signatures_match": not errors and not (catalogue_counts["changed"] or catalogue_counts["unmatched"] or catalogue_counts["unsupported"]),
                   "catalogue_only_products": missing_products, "catalogue_atom_status_counts": dict(sorted(catalogue_counts.items())),
                   "shared_product_upstream_atom_status_counts": dict(sorted(upstream_counts.items())),
                   "unresolved_expression_count": unsupported_count},
        "inventory": {"catalogue": inventory, "upstream": {"products": len(by_name), "plugin_files": len(plugins),
                      "match_calls": sum(len(p["atoms"]) for p in plugins),
                      "literal_signatures": sum(a["signature"] is not None for p in plugins for a in p["atoms"])},
                      "shared_products": sum(p["source_path"] is not None for p in products), "upstream_only_products": len(upstream_only)},
        "helper_contracts": contracts, "unresolved": unresolved,
        "products": products, "upstream_only": upstream_only, "limitations": LIMITATIONS,
    }


def exit_code(report, strict_parity=False):
    if not report["structural_validity"]["valid"]:
        return 2
    return int(strict_parity and report["parity"]["status"] != "atom_inventory_match")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalogue", type=Path)
    parser.add_argument("plugin_directory", type=Path, help="installed wafw00f/plugins; sibling main.py and __init__.py are also read")
    parser.add_argument("--wafw00f-version", required=True, help="explicit provenance, checked against the package's literal __version__")
    parser.add_argument("--strict-parity", action="store_true", help="exit 1 for atom differences or unresolved analysis (never an equivalence claim)")
    args = parser.parse_args(argv)
    report = audit(args.catalogue, args.plugin_directory, args.wafw00f_version)
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True))
    return exit_code(report, args.strict_parity)


if __name__ == "__main__":
    raise SystemExit(main())
