"""Offline release-policy checks: python3 -m unittest discover -s tools -p '*_test.py'."""

import hashlib
import copy
import gzip
import io
import json
import os
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

import release
import smoke


class ReleasePolicyTests(unittest.TestCase):
    def test_tag_major_must_match_the_candidate_module(self):
        for tag, module in (("v0.9.0", "example.test/tool"), ("v1.2.0", "example.test/tool"),
                            ("v2.0.0-rc.1", "example.test/tool/v2"), ("v12.1.0", "example.test/tool/v12")):
            release.require_module_version(tag, module)
        for tag, module in (("v1.1.0", "example.test/tool/v2"), ("v3.0.0", "example.test/tool/v2"),
                            ("v2.0.0", "example.test/tool"), ("v1.0.0", "example.test/tool/v1")):
            with self.subTest(tag=tag, module=module), self.assertRaises(ValueError):
                release.require_module_version(tag, module)

    def test_candidate_module_is_read_from_commit_not_dispatch_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            git = ("git", "-C", str(root), "-c", "user.name=Release Test",
                   "-c", "user.email=release-test@example.invalid")
            release.command(*git, "init")
            (root / "go.mod").write_text("module example.test/tool/v2\n\ngo 1.26.0\n")
            release.command(*git, "add", "go.mod")
            release.command(*git, "commit", "-m", "candidate")
            candidate = release.command(*git, "rev-parse", "HEAD")
            (root / "go.mod").write_text("module example.test/tool/v3\n\ngo 1.26.0\n")
            release.command(*git, "commit", "-am", "different dispatch checkout")
            previous = Path.cwd()
            try:
                os.chdir(root)
                self.assertEqual(release.validate_candidate("v2.0.0", candidate), "example.test/tool/v2")
                with self.assertRaisesRegex(ValueError, "major"):
                    release.validate_candidate("v3.0.0", candidate)
            finally:
                os.chdir(previous)

    def test_semver_and_prerelease_policy(self):
        for tag in ("v0.0.0", "v1.2.3", "v2.0.0-rc.1", "v2.0.0-alpha-beta.0"):
            self.assertIsNotNone(release.version_key(tag))
        for tag in ("1.2.3", "v01.2.3", "v1.2", "v1.2.3-01", "v1.2.3+build", "v1.2.3;exit", "v1.2.3\n"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.version_key(tag)
        self.assertLess(release.version_key("v2.0.0-rc.2"), release.version_key("v2.0.0-rc.10"))
        self.assertLess(release.version_key("v2.0.0-rc.10"), release.version_key("v2.0.0"))

    def test_latest_never_promotes_prerelease_or_old_stable(self):
        releases = [{"tag_name": "v2.0.0", "draft": False, "prerelease": False}]
        self.assertTrue(release.make_latest("v2.0.1", releases))
        self.assertFalse(release.make_latest("v1.9.9", releases))
        self.assertFalse(release.make_latest("v3.0.0-rc.1", releases))

    def test_security_keeps_current_stable_when_newer_candidate_exists(self):
        releases = [
            {"tag_name": "v1.9.0", "draft": False, "prerelease": False},
            {"tag_name": "v2.0.0", "draft": False, "prerelease": False},
            {"tag_name": "v2.1.0-rc.1", "draft": False, "prerelease": True},
            {"tag_name": "v3.0.0", "draft": True, "prerelease": False},
        ]
        self.assertEqual([item["tag_name"] for item in release.supported_releases(releases)],
                         ["v2.0.0", "v2.1.0-rc.1"])

    def test_tag_resolution_prefers_peeled_annotated_commit(self):
        tag_object, commit = "a" * 40, "b" * 40
        with patch.object(release, "command", return_value=(
            f"{tag_object}\trefs/tags/v1.0.0\n{commit}\trefs/tags/v1.0.0^{{}}\n"
        )) as command:
            self.assertEqual(release.remote_revision("origin", "v1.0.0"), commit)
            self.assertEqual(command.call_count, 1)
        with patch.object(release, "command", return_value=""):
            with self.assertRaises(ValueError):
                release.remote_revision("origin", "v1.0.0")

    def test_local_git_tags_resolve_supplied_version_not_head(self):
        with tempfile.TemporaryDirectory() as temporary:
            git = ("git", "-C", temporary, "-c", "user.name=Release Test",
                   "-c", "user.email=release-test@example.invalid")
            release.command(*git, "init")
            release.command(*git, "commit", "--allow-empty", "-m", "tagged source")
            tagged = release.command(*git, "rev-parse", "HEAD")
            release.command(*git, "tag", "-a", "v1.2.3", "-m", "annotated release")
            release.command(*git, "tag", "v1.2.4")
            release.command(*git, "commit", "--allow-empty", "-m", "triggering ref differs")
            self.assertNotEqual(release.command(*git, "rev-parse", "HEAD"), tagged)
            for tag in ("v1.2.3", "v1.2.4"):
                self.assertEqual(release.remote_revision(temporary, tag), tagged)

    def test_prepare_records_supplied_tag_once_and_refuses_existing_draft(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "outputs"
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}), \
                    patch.object(release, "remote_revision", return_value="b" * 40) as resolve, \
                    patch.object(release, "repository_releases", return_value=[]), \
                    patch.object(release, "validate_candidate") as validate:
                release.prepare("v2.0.0-rc.1")
                resolve.assert_called_once_with("origin", "v2.0.0-rc.1")
                validate.assert_called_once_with("v2.0.0-rc.1", "b" * 40, fetch=True)
            self.assertEqual(output.read_text(),
                             f"tag=v2.0.0-rc.1\nrevision={'b' * 40}\nprerelease=true\n")
            with patch.object(release, "remote_revision", return_value="b" * 40), \
                    patch.object(release, "repository_releases",
                                 return_value=[{"tag_name": "v2.0.0", "draft": True}]):
                with self.assertRaisesRegex(ValueError, "already exists"):
                    release.prepare("v2.0.0")

    def test_build_identity_rejects_dirty_wrong_revision_and_toolchain(self):
        revision = "b" * 40
        info = (f"binary: {release.GO_VERSION}\n"
                "\tbuild\tGOOS=linux\n\tbuild\tGOARCH=amd64\n"
                f"\tbuild\tvcs.revision={revision}\n\tbuild\tvcs.modified=false\n")
        with patch.object(release, "command", return_value=info):
            self.assertEqual(release.binary_identity(Path("binary"), revision, "linux", "amd64")["revision"], revision)
        for invalid in (info.replace("modified=false", "modified=true"),
                        info.replace(revision, "c" * 40),
                        info.replace(release.GO_VERSION, "go1.26.0"),
                        info.replace("GOARCH=amd64", "GOARCH=arm64")):
            with self.subTest(info=invalid), patch.object(release, "command", return_value=invalid):
                with self.assertRaises(ValueError):
                    release.binary_identity(Path("binary"), revision, "linux", "amd64")

    def test_manifest_rejects_missing_extra_and_changed_archives(self):
        with tempfile.TemporaryDirectory() as temporary:
            dist = Path(temporary)
            archives = {}
            for name, (target_os, arch) in release.archive_names("v1.0.0").items():
                (dist / name).write_bytes(name.encode())
                archives[name] = {"archive_sha256": hashlib.sha256(name.encode()).hexdigest(),
                                  "binary_sha256": "d" * 64, "tag": "v1.0.0",
                                  "os": target_os, "arch": arch,
                                  "revision": "b" * 40, "go_version": release.GO_VERSION,
                                  "modified": False}
            manifest = {"schema_version": 1, "scanner": release.SCANNER,
                        "tag": "v1.0.0", "revision": "b" * 40, "archives": archives,
                        "module": "example.test/tool", "repository": "example/repo"}
            formula = release.homebrew_formula("v1.0.0", "b" * 40, archives, "example/repo")
            (dist / release.FORMULA).write_text(formula)
            manifest["homebrew_formula_sha256"] = release.digest(dist / release.FORMULA)
            (dist / "manifest.json").write_text(json.dumps(manifest))
            (dist / release.FORMULA).write_text(formula.replace("https://github.com/", "https://untrusted.invalid/"))
            with self.assertRaisesRegex(ValueError, "Homebrew"):
                release.check_bundle(dist, "v1.0.0", "b" * 40)
            (dist / release.FORMULA).write_text(formula)
            release.check_bundle(dist, "v1.0.0", "b" * 40)
            mutations = (("schema_version", 2), ("scanner", "unapproved-scanner"))
            for key, value in mutations:
                invalid = copy.deepcopy(manifest)
                invalid[key] = value
                (dist / "manifest.json").write_text(json.dumps(invalid))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    release.check_bundle(dist, "v1.0.0", "b" * 40)
            for key, value in (("os", "other"), ("arch", "other"), ("tag", "v2.0.0"),
                               ("binary_sha256", "not-a-sha256")):
                invalid = copy.deepcopy(manifest)
                invalid["archives"][next(iter(archives))][key] = value
                (dist / "manifest.json").write_text(json.dumps(invalid))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    release.check_bundle(dist, "v1.0.0", "b" * 40)
            (dist / "manifest.json").write_text(json.dumps(manifest))
            name = next(iter(archives))
            (dist / name).write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                release.check_bundle(dist, "v1.0.0", "b" * 40)
            (dist / name).write_bytes(name.encode())
            (dist / "unexpected.zip").write_bytes(b"unexpected")
            with self.assertRaises(ValueError):
                release.check_bundle(dist, "v1.0.0", "b" * 40)
            (dist / "unexpected.zip").unlink()
            (dist / name).unlink()
            with self.assertRaises(ValueError):
                release.check_bundle(dist, "v1.0.0", "b" * 40)

    @unittest.skipUnless(os.name == "posix", "Scanner runs on Linux release-verification hosts")
    def test_real_scanner_timeout_retains_partial_output_and_next_scan_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scanner = root / "govulncheck"
            scanner.write_text(f"#!{sys.executable}\n"
                               "import sys, time\n"
                               "print('partial scanner diagnostic', flush=True)\n"
                               "if sys.argv[-1] == 'slow': time.sleep(30)\n"
                               "sys.exit(3 if sys.argv[-1] == 'vulnerable' else 0)\n")
            scanner.chmod(0o755)
            with patch.dict(os.environ, {"PATH": str(root) + os.pathsep + os.environ["PATH"]}):
                self.assertFalse(release.scan_binary(Path("slow"), root / "timeout.txt", timeout=1))
                self.assertIn("partial scanner diagnostic", (root / "timeout.txt").read_text())
                self.assertIn("timed out", (root / "timeout.txt").read_text())
                self.assertFalse(release.scan_binary(Path("vulnerable"), root / "finding.txt"))
                self.assertTrue(release.scan_binary(Path("next"), root / "next.txt"))

    def test_archive_resource_bounds_on_real_small_archives(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for extension, binary in (("tar.gz", "wafme0w"), ("zip", "wafme0w.exe")):
                archive = root / ("archive." + extension)
                files = [(binary, b"x" * 40), ("LICENSE.md", b"license"),
                         (smoke.CAPTURE.as_posix(), b"capture")]
                if extension == "zip":
                    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
                        for name, data in files:
                            output.writestr(name, data)
                else:
                    with tarfile.open(archive, "w:gz") as output:
                        for name, data in files:
                            member = tarfile.TarInfo(name)
                            member.size = len(data)
                            output.addfile(member, io.BytesIO(data))
                with self.subTest(extension=extension):
                    destination = root / extension
                    destination.mkdir()
                    smoke.extract_archive(archive, destination)
                    for bound, value in (("MAX_ARCHIVE_BYTES", 1), ("MAX_MEMBER_BYTES", 32),
                                         ("MAX_MEMBER_TOTAL_BYTES", 45)):
                        with patch.object(smoke, bound, value), self.assertRaises(RuntimeError):
                            smoke.extract_archive(archive, destination)
            fourth = root / "fourth.tar.gz"
            with tarfile.open(fourth, "w:gz") as output:
                for name in ("wafme0w", "LICENSE.md", smoke.CAPTURE.as_posix(), "unexpected"):
                    member = tarfile.TarInfo(name)
                    member.size = 1
                    output.addfile(member, io.BytesIO(b"x"))
            with self.assertRaisesRegex(RuntimeError, "extra|duplicate"):
                smoke.extract_archive(fourth, root)
            # A huge declared payload must be rejected from its header, without
            # allocating or attempting to read the absent payload.
            huge = root / "header.tar.gz"
            header = tarfile.TarInfo("wafme0w")
            header.size = 2**40
            huge.write_bytes(gzip.compress(header.tobuf()))
            with self.assertRaisesRegex(RuntimeError, "member size"):
                smoke.extract_archive(huge, root)
            with patch.object(smoke, "MAX_EXPANDED_BYTES", 1024), self.assertRaises(RuntimeError):
                smoke.extract_archive(fourth, root)

    def test_zip64_cannot_hide_before_maximum_archive_comment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "comment.zip"
            names = ("wafme0w.exe", "LICENSE.md", smoke.CAPTURE.as_posix())
            for comment_size in (0, 65516, 65535):
                with self.subTest(comment_size=comment_size):
                    with zipfile.ZipFile(archive, "w") as output:
                        for name in names:
                            member = zipfile.ZipInfo(name)
                            member.comment = b"c" * 6000
                            output.writestr(member, b"fixture")
                        output.comment = b"a" * comment_size
                    original = archive.read_bytes()
                    position = len(original) - 22 - comment_size
                    end = list(struct.unpack_from("<4s4H2LH", original, position))
                    # ZIP64 overrides the innocuous ordinary directory size.
                    zip64 = struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45,
                                        0, 0, 3, 3, end[5], end[6])
                    locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, position, 1)
                    end[5] = 128
                    archive.write_bytes(original[:position] + zip64 + locator +
                                        struct.pack("<4s4H2LH", *end) + original[position + 22:])
                    destination = root / str(comment_size)
                    destination.mkdir()
                    with self.assertRaises(RuntimeError):
                        smoke.extract_archive(archive, destination)
                    self.assertEqual(list(destination.iterdir()), [])
            # An ordinary ZIP with a maximum-length comment remains supported.
            with zipfile.ZipFile(archive, "w") as output:
                for name in names:
                    output.writestr(name, b"fixture")
                output.comment = b"a" * 65535
            destination = root / "ordinary"
            destination.mkdir()
            binary = smoke.extract_archive(archive, destination)
            self.assertEqual(binary.read_bytes(), b"fixture")

    def test_published_asset_metadata_rejects_oversize_before_download(self):
        item = {"tag_name": "v1.0.0", "assets": [
            {"name": name, "size": 1} for name in release.archive_names("v1.0.0")
        ]}
        self.assertEqual(set(release.published_assets(item)), set(release.archive_names("v1.0.0")))
        item["assets"][0]["size"] = smoke.MAX_ARCHIVE_BYTES + 1
        with patch.object(release, "repository_releases", return_value=[{
            **item, "draft": False, "prerelease": False,
        }]), patch.object(release, "command") as command:
            with self.assertRaisesRegex(ValueError, "size"):
                release.scan_published(SimpleNamespace(reports=Path("unused")))
            command.assert_not_called()

    def test_historical_three_platform_releases_remain_scannable(self):
        legacy = {"tag_name": "v1.0.0", "assets": [
            {"name": name, "size": 1} for name in release.archive_names("v1.0.0", release.LEGACY_TARGETS)
        ]}
        self.assertEqual(len(release.published_assets(legacy)), 3)
        current = {"tag_name": "v2.0.0", "assets": [
            {"name": name, "size": 1} for name in release.archive_names("v2.0.0", release.LEGACY_TARGETS)
        ]}
        with self.assertRaisesRegex(ValueError, "Missing"):
            release.published_assets(current)
        legacy["assets"].append(legacy["assets"][0])
        with self.assertRaisesRegex(ValueError, "Missing"):
            release.published_assets(legacy)

    def test_formula_has_exact_verified_unix_artifacts_and_rejects_interpolation(self):
        archives = {name: {"archive_sha256": hashlib.sha256(name.encode()).hexdigest()}
                    for name in release.archive_names("v2.0.0-rc.1")}
        formula = release.homebrew_formula("v2.0.0-rc.1", "b" * 40, archives, "Lu1sDV/wafme0w")
        for name, metadata in archives.items():
            if "windows" in name:
                self.assertNotIn(name, formula)
            else:
                self.assertIn(name, formula)
                self.assertIn(metadata["archive_sha256"], formula)
        self.assertEqual(formula.count('      url "'), 4)
        self.assertIn('prefix.install "LICENSE.md"', formula)
        with self.assertRaisesRegex(ValueError, "repository"):
            release.homebrew_formula("v2.0.0-rc.1", "b" * 40, archives, 'owner/#{system("false")}')

    def test_moved_tag_never_reaches_release_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            dist = Path(temporary)
            (dist / "SHA256SUMS").write_text("")
            args = SimpleNamespace(dist=dist, tag="v1.0.0", revision="b" * 40)
            with patch.dict(os.environ, {"RUNNER_TEMP": temporary, "GH_REPO": "example/repo"}), \
                    patch.object(release, "check_bundle", return_value={"repository": "example/repo"}), \
                    patch.object(release, "repository_releases", return_value=[]), \
                    patch.object(release, "remote_revision", return_value="c" * 40), \
                    patch.object(release, "command") as command:
                with self.assertRaisesRegex(ValueError, "Remote tag moved"):
                    release.publish(args)
                command.assert_not_called()

    def test_tag_move_after_upload_retains_draft_without_publishing(self):
        with tempfile.TemporaryDirectory() as temporary:
            dist = Path(temporary)
            (dist / "SHA256SUMS").write_text("")
            args = SimpleNamespace(dist=dist, tag="v1.0.0", revision="b" * 40)
            with patch.dict(os.environ, {"RUNNER_TEMP": temporary, "GH_REPO": "example/repo"}), \
                    patch.object(release, "check_bundle", return_value={"repository": "example/repo"}), \
                    patch.object(release, "repository_releases", return_value=[]), \
                    patch.object(release, "remote_revision", side_effect=["b" * 40, "c" * 40]), \
                    patch.object(release, "command") as command:
                with self.assertRaisesRegex(ValueError, "draft retained"):
                    release.publish(args)
                self.assertEqual(command.call_count, 1)
                self.assertEqual(command.call_args.args[:3], ("gh", "release", "create"))


if __name__ == "__main__":
    unittest.main()
