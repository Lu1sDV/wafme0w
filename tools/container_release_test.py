"""Offline checks for native image integrity and publication failure boundaries."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import container_release as images
import release


class ContainerReleaseTests(unittest.TestCase):
    def test_registry_errors_are_not_mistaken_for_absent_tags(self):
        for code, error, accepted in ((1, "no such manifest: ghcr.io/example/repo:v2.0.0", True),
                                     (1, "manifest unknown", True), (0, "", False),
                                     (1, "unauthorized: authentication required", False),
                                     (1, "connection refused", False)):
            result = subprocess.CompletedProcess([], code, "", error)
            with self.subTest(error=error), patch.object(images.subprocess, "run", return_value=result):
                if accepted:
                    images.require_absent("ghcr.io/example/repo:v2.0.0")
                else:
                    with self.assertRaises(ValueError):
                        images.require_absent("ghcr.io/example/repo:v2.0.0")

    def test_runtime_metadata_must_match_the_native_candidate(self):
        metadata = {"Id": "sha256:" + "a" * 64, "Os": "linux", "Architecture": "arm64",
                    "Config": {"User": "65532:65532", "WorkingDir": "/work",
                               "Entrypoint": ["/usr/local/bin/wafme0w"], "Cmd": None,
                               "Labels": {"org.opencontainers.image.source": "https://github.com/Owner/repo",
                                          "org.opencontainers.image.revision": "b" * 40,
                                          "org.opencontainers.image.version": "v2.0.0"}}}
        with patch.object(release, "command", return_value=json.dumps([metadata])):
            self.assertEqual(images.inspect_image("local", "v2.0.0", "b" * 40, "arm64", "Owner/repo"), metadata["Id"])
        for key, value in (("User", "0:0"), ("WorkingDir", "/"), ("Entrypoint", ["/bin/sh"]), ("Cmd", ["unexpected"])):
            invalid = json.loads(json.dumps(metadata))
            invalid["Config"][key] = value
            with self.subTest(key=key), patch.object(release, "command", return_value=json.dumps([invalid])):
                with self.assertRaises(ValueError):
                    images.inspect_image("local", "v2.0.0", "b" * 40, "arm64", "Owner/repo")
        with patch.object(release, "command", return_value=json.dumps([metadata])):
            with self.assertRaises(ValueError):
                images.inspect_image("local", "v2.0.0", "b" * 40, "amd64", "Owner/repo")

    def test_changed_image_artifact_stops_before_docker_load(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = SimpleNamespace(images=root, tag="v2.0.0", revision="b" * 40, repository="Owner/repo")
            manifest = {"archives": {}}
            for arch in images.ARCHES:
                archive = root / f"linux-{arch}.tar"
                archive.write_bytes(b"native image")
                native = {"archive_sha256": "c" * 64, "binary_sha256": "d" * 64}
                manifest["archives"][f"wafme0w_v2.0.0_linux_{arch}.tar.gz"] = native
                record = {"schema_version": 1, "tag": args.tag, "revision": args.revision, "arch": arch,
                          "repository": args.repository, **native, "image_archive_sha256": "0" * 64}
                (root / f"linux-{arch}.json").write_text(json.dumps(record))
            with patch.object(release, "command") as command, self.assertRaisesRegex(ValueError, "artifact changed"):
                images.verify_images(args, manifest)
            command.assert_not_called()

    def test_moved_source_or_existing_image_never_reaches_a_push(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = SimpleNamespace(tag="v2.0.0", revision="b" * 40, repository="Owner/repo",
                                   output=Path(temporary) / "container.json", dist=Path("unused"))
            for moved in (True, False):
                with self.subTest(moved=moved), \
                        patch.object(release, "check_bundle", return_value={"repository": args.repository}), \
                        patch.object(images, "verify_images", return_value={"amd64": "sha256:" + "a" * 64}), \
                        patch.object(release, "remote_revision", return_value=("c" if moved else "b") * 40), \
                        patch.object(images, "require_absent", side_effect=ValueError("Container tag already exists")), \
                        patch.object(release, "command") as command:
                    with self.assertRaises(ValueError):
                        images.publish(args)
                    command.assert_not_called()
            self.assertFalse(args.output.exists())

    def test_registry_and_local_names_are_validated(self):
        self.assertEqual(images.image_name("Lu1sDV/wafme0w"), "ghcr.io/lu1sdv/wafme0w")
        self.assertEqual(images.local_image("v2.0.0-rc.1", "arm64"), "wafme0w-release:v2.0.0-rc.1-arm64")
        for repository in ("owner/repo;command", "owner/../repo", "other.registry/owner/repo"):
            with self.subTest(repository=repository), self.assertRaises(ValueError):
                images.image_name(repository)
        with self.assertRaises(ValueError):
            images.local_image("v2.0.0", "unreviewed")
        with self.assertRaises(ValueError):
            images.local_image("v2.0.0-" + "a" * 112, "amd64")

    def test_multiplatform_publication_uses_pushed_digests_not_mutable_child_tags(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = SimpleNamespace(tag="v2.0.0-rc.1", revision="b" * 40, repository="Owner/repo",
                                   output=root / "container.json", dist=Path("unused"))
            child_digests = {"amd64": "sha256:" + "c" * 64, "arm64": "sha256:" + "d" * 64}

            def command(*arguments):
                if arguments[:3] == ("docker", "image", "push"):
                    arch = arguments[3].rsplit("-", 1)[-1]
                    return "pushed: digest: " + child_digests[arch] + " size: 1234"
                if arguments[:3] == ("docker", "manifest", "push"):
                    return "sha256:" + "e" * 64
                return ""

            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(root / "outputs")}), \
                    patch.object(release, "check_bundle", return_value={"repository": args.repository}), \
                    patch.object(images, "verify_images", return_value={arch: "sha256:" + "a" * 64 for arch in images.ARCHES}), \
                    patch.object(release, "remote_revision", return_value=args.revision), \
                    patch.object(images, "require_absent") as absent, \
                    patch.object(release, "command", side_effect=command) as commands:
                images.publish(args)
                commands.assert_any_call("docker", "manifest", "create", "ghcr.io/owner/repo:v2.0.0-rc.1",
                                         "ghcr.io/owner/repo@" + child_digests["amd64"],
                                         "ghcr.io/owner/repo@" + child_digests["arm64"])
                self.assertEqual(absent.call_count, 4)
            record = json.loads(args.output.read_text())
            self.assertEqual(record["digest"], "sha256:" + "e" * 64)
            self.assertEqual(record["revision"], args.revision)
            self.assertEqual(record["platforms"], {"linux/" + arch: value for arch, value in child_digests.items()})


if __name__ == "__main__":
    unittest.main()
