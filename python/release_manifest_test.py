# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Exercise release assembly with real synthetic archives and producing-job records."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "tasks/scripts/release.py"
SPEC = importlib.util.spec_from_file_location("release_manifest_tooling", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
release = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release
SPEC.loader.exec_module(release)
SOURCE = "a" * 40
VERSION = "0.0.117-dev.177+gaaaaaaaaa"


def executable(component: str, target: str) -> bytes:
    """Create distinct executable identities with genuine architecture headers."""
    header = bytearray(64)
    if "linux" in target:
        header[:6] = b"\x7fELF\x02\x01"
        header[18:20] = (62 if target.startswith("x86_64") else 183).to_bytes(
            2, "little"
        )
    else:
        header[:4] = b"\xcf\xfa\xed\xfe"
        header[4:8] = (0x0100000C).to_bytes(4, "little")
    return bytes(header) + f"{component}/{target}".encode()


def write_archive(path: Path, binary: str, content: bytes, *, extra=False) -> None:
    """Package a synthetic executable through the real tar archive boundary."""
    with tarfile.open(path, "w:gz") as archive:
        member = tarfile.TarInfo(binary)
        member.size = len(content)
        member.mode = 0o755
        archive.addfile(member, io.BytesIO(content))
        if extra:
            archive.addfile(tarfile.TarInfo("../unexpected"), io.BytesIO())


class ReleaseManifestTests(unittest.TestCase):
    """Prove producing-job records and archive bytes agree before publication."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.assets = self.root / "release"
        self.identities = self.root / "identities"
        self.assets.mkdir()
        self.identities.mkdir()
        self.output = self.assets / "openshell-release-manifest.json"
        for component, (binary, libc, darwin) in release.CORE_ARCHIVES.items():
            targets = [f"x86_64-unknown-linux-{libc}", f"aarch64-unknown-linux-{libc}"]
            if darwin:
                targets.append("aarch64-apple-darwin")
            for target in targets:
                write_archive(
                    self.assets / f"{binary}-{target}.tar.gz",
                    binary,
                    executable(component, target),
                )
            self.rehash(component)
            if component in release.IMAGE_COMPONENTS:
                staged = self.root / component / "staged"
                for arch, triple_arch in (("amd64", "x86_64"), ("arm64", "aarch64")):
                    target = f"{triple_arch}-unknown-linux-{libc}"
                    path = staged / arch / binary
                    path.parent.mkdir(parents=True)
                    path.write_bytes(executable(component, target))
                self.write_image(component)

    def rehash(self, component: str) -> None:
        binary = release.CORE_ARCHIVES[component][0]
        lines = [
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in sorted(self.assets.glob(f"{binary}-*.tar.gz"))
        ]
        (self.assets / f"{binary}-checksums-sha256.txt").write_text("".join(lines))

    def write_image(
        self, component: str, *, mutate=None, trailing_newline=False
    ) -> None:
        folder = self.root / component
        descriptors = [
            {
                "mediaType": release.OCI_MANIFEST,
                "digest": "sha256:"
                + hashlib.sha256(f"{component}/{arch}".encode()).hexdigest(),
                "size": 123,
                "platform": {"os": "linux", "architecture": arch},
            }
            for arch in ("amd64", "arm64")
        ]
        descriptors.append(
            {
                "mediaType": release.OCI_MANIFEST,
                "digest": "sha256:" + "f" * 64,
                "platform": {"os": "unknown", "architecture": "unknown"},
                "annotations": {"vnd.docker.reference.type": "attestation-manifest"},
            }
        )
        index = {
            "schemaVersion": 2,
            "mediaType": release.OCI_INDEX,
            "manifests": descriptors,
        }
        if mutate is not None:
            mutate(index)
        raw = json.dumps(index, separators=(",", ":")).encode()
        (folder / "index.json").write_bytes(raw + (b"\n" if trailing_newline else b""))
        (folder / "metadata.json").write_text(
            json.dumps(
                {
                    "containerimage.digest": "sha256:"
                    + hashlib.sha256(raw).hexdigest(),
                    "containerimage.config.digest": "sha256:" + "e" * 64,
                }
            )
        )
        release.record_image_identity(
            component=component,
            source_sha=SOURCE,
            run_id="123",
            run_attempt="1",
            metadata_file=folder / "metadata.json",
            index_file=folder / "index.json",
            binary_dir=folder / "staged",
            output=self.identities / f"{component}.json",
        )

    def generate(self, **changes) -> dict:
        args = {
            "source_sha": SOURCE,
            "run_id": "123",
            "run_attempt": "1",
            "cargo_version": VERSION,
            "release_dir": self.assets,
            "image_dir": self.identities,
            "output": self.output,
        }
        args.update(changes)
        release.generate_release_manifest(**args)
        return json.loads(self.output.read_text())

    def mutate_identity(self, component: str, change) -> None:
        path = self.identities / f"{component}.json"
        record = json.loads(path.read_text())
        change(record)
        path.write_text(json.dumps(record))

    def test_complete_manifest_preserves_exact_artifact_and_platform_identity(
        self,
    ) -> None:
        manifest = self.generate()
        self.assertEqual(manifest["source_sha"], SOURCE)
        self.assertEqual(manifest["cargo_version"], VERSION)
        self.assertEqual(manifest["inventory_scope"], "core-runtime")
        self.assertEqual(len(manifest["archives"]), 10)
        self.assertEqual(len(manifest["images"]), 3)
        for image in manifest["images"]:
            self.assertEqual(len(image["platforms"]), 2)
            for platform in image["platforms"]:
                self.assertRegex(platform["digest"], r"^sha256:[0-9a-f]{64}$")
        original = self.output.read_bytes()
        self.generate()
        self.assertEqual(self.output.read_bytes(), original)

    def test_same_run_retry_can_reuse_completed_producing_jobs(self) -> None:
        result = self.generate(run_attempt="2")
        self.assertEqual(result["run_attempt"], "2")
        self.assertTrue(all(image["run_attempt"] == "1" for image in result["images"]))

    def test_altered_archive_rejected_before_manifest_creation(self) -> None:
        next(self.assets.glob("openshell-x86_64-*.tar.gz")).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            self.generate()
        self.assertFalse(self.output.exists())

    def test_exact_stable_tag_accepts_actual_development_version_producer(self) -> None:
        responses = {
            ("rev-parse", "--short=9", "HEAD"): SOURCE[:9],
            ("rev-list", "v0.0.116..HEAD", "--count"): "0",
        }
        with (
            patch.object(release, "_latest_stable_tag", return_value="v0.0.116"),
            patch.object(
                release, "_git", side_effect=lambda args: responses[tuple(args)]
            ),
        ):
            produced = release._compute_dev_versions()
        self.assertEqual(produced.cargo, "0.0.116")
        result = self.generate(cargo_version=produced.cargo)
        self.assertEqual(result["cargo_version"], produced.cargo)
        self.assertEqual(result["source_sha"], SOURCE)

    def test_extended_git_prefix_accepts_only_the_matching_full_source(self) -> None:
        produced = release._versions_from_parts(
            (0, 0, 116), 177, SOURCE[:12], "v0.0.116"
        )
        self.assertEqual(
            self.generate(cargo_version=produced.cargo)["source_sha"], SOURCE
        )
        wrong = release._versions_from_parts(
            (0, 0, 116), 177, "a" * 11 + "b", "v0.0.116"
        )
        with self.assertRaisesRegex(ValueError, "version/source"):
            self.generate(cargo_version=wrong.cargo)

    def test_missing_archive_rejected(self) -> None:
        next(self.assets.glob("openshell-supervisor-aarch64-*.tar.gz")).unlink()
        with self.assertRaises(FileNotFoundError):
            self.generate()

    def test_checksum_duplicate_rejected(self) -> None:
        path = self.assets / "openshell-checksums-sha256.txt"
        path.write_text(path.read_text() * 2)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.generate()

    def test_source_run_and_version_mismatch_are_independent_guards(self) -> None:
        for field, value in (("source_sha", "b" * 40), ("run_id", "456")):
            with self.subTest(field=field):
                path = self.identities / "gateway.json"
                original = path.read_text()
                self.mutate_identity(
                    "gateway",
                    lambda record, key=field, item=value: record.update({key: item}),
                )
                with self.assertRaisesRegex(ValueError, "another build"):
                    self.generate()
                path.write_text(original)
        with self.assertRaisesRegex(ValueError, "version/source"):
            self.generate(cargo_version="0.0.117-dev.177+gbbbbbbbbb")

    def test_extra_or_missing_image_record_rejected(self) -> None:
        (self.identities / "extra.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "exactly one identity"):
            self.generate()
        (self.identities / "extra.json").unlink()
        (self.identities / "gateway.json").unlink()
        with self.assertRaisesRegex(ValueError, "exactly one identity"):
            self.generate()

    def test_image_binary_mismatch_rejected_even_with_valid_archive_checksum(
        self,
    ) -> None:
        path = self.assets / "openshell-gateway-x86_64-unknown-linux-gnu.tar.gz"
        write_archive(
            path, "openshell-gateway", executable("other", "x86_64-unknown-linux-gnu")
        )
        self.rehash("gateway")
        with self.assertRaisesRegex(ValueError, "staged image binary"):
            self.generate()

    def test_wrong_architecture_and_extra_archive_member_rejected(self) -> None:
        path = self.assets / "openshell-x86_64-unknown-linux-musl.tar.gz"
        write_archive(
            path, "openshell", executable("cli", "aarch64-unknown-linux-musl")
        )
        self.rehash("cli")
        with self.assertRaisesRegex(ValueError, "architecture"):
            self.generate()
        write_archive(
            path,
            "openshell",
            executable("cli", "x86_64-unknown-linux-musl"),
            extra=True,
        )
        self.rehash("cli")
        with self.assertRaisesRegex(ValueError, "additional archive member"):
            self.generate()

    def test_index_digest_mismatch_and_duplicate_platform_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.write_image(
                "gateway",
                mutate=lambda index: index["manifests"].append(index["manifests"][0]),
            )
        self.write_image("gateway", trailing_newline=True)
        path = self.root / "gateway" / "index.json"
        path.write_bytes(path.read_bytes().replace(b'"size":123', b'"size":124'))
        with self.assertRaisesRegex(ValueError, "index bytes"):
            release.record_image_identity(
                component="gateway",
                source_sha=SOURCE,
                run_id="123",
                run_attempt="1",
                metadata_file=self.root / "gateway" / "metadata.json",
                index_file=path,
                binary_dir=self.root / "gateway" / "staged",
                output=self.root / "bad.json",
            )

    def test_image_platform_and_digest_revalidated_at_assembly(self) -> None:
        self.mutate_identity(
            "gateway",
            lambda record: record["platforms"][1].update(architecture="amd64"),
        )
        with self.assertRaisesRegex(ValueError, "duplicate platform"):
            self.generate()
        self.write_image("gateway")
        self.mutate_identity(
            "gateway", lambda record: record.update(index_digest="dev")
        )
        with self.assertRaisesRegex(ValueError, "OCI digest"):
            self.generate()

    def test_archive_symlink_and_json_duplicate_key_rejected(self) -> None:
        path = self.assets / "openshell-x86_64-unknown-linux-musl.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            member = tarfile.TarInfo("openshell")
            member.type = tarfile.SYMTYPE
            member.linkname = "/outside"
            archive.addfile(member)
        self.rehash("cli")
        with self.assertRaisesRegex(ValueError, "expected one executable"):
            self.generate()
        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"source_sha":"one","source_sha":"two"}')
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            release._read_json(duplicate)

    def test_missing_and_unidentified_image_platform_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "both|amd64 and arm64"):
            self.write_image("gateway", mutate=lambda index: index["manifests"].pop(1))
        with self.assertRaisesRegex(ValueError, "unexpected"):
            self.write_image(
                "gateway", mutate=lambda index: index["manifests"][2].pop("annotations")
            )

    def test_assembly_rejects_unknown_schema_fields_and_wrong_variant(self) -> None:
        self.mutate_identity("gateway", lambda record: record.update(qualified=True))
        with self.assertRaisesRegex(ValueError, "another build"):
            self.generate()
        self.write_image("gateway")
        self.mutate_identity(
            "gateway", lambda record: record["platforms"][0].update(variant="v8")
        )
        with self.assertRaisesRegex(ValueError, "unexpected"):
            self.generate()

    def test_real_cli_assembles_and_fails_without_emitting_partial_manifest(
        self,
    ) -> None:
        command = [
            sys.executable,
            str(SCRIPT),
            "generate-release-manifest",
            "--source-sha",
            SOURCE,
            "--run-id",
            "123",
            "--run-attempt",
            "1",
            "--cargo-version",
            VERSION,
            "--release-dir",
            str(self.assets),
            "--image-dir",
            str(self.identities),
            "--output",
            str(self.output),
        ]
        success = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual(json.loads(self.output.read_text())["source_sha"], SOURCE)
        self.output.unlink()
        (self.identities / "supervisor.json").unlink()
        failure = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(failure.returncode, 0)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
