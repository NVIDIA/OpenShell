# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import unittest

from open_shell.main import (
    _rust_build_spec,
    _validate_deb_version,
    _validate_inputs,
)


class RustNativeBuildTest(unittest.TestCase):
    def test_amd64_cli_spec(self) -> None:
        spec = _rust_build_spec("cli", "amd64")

        self.assertEqual(spec.binary, "openshell")
        self.assertEqual(spec.rust_target, "x86_64-unknown-linux-musl")
        self.assertEqual(spec.zig_target, "x86_64-linux-musl")

    def test_arm64_cli_spec(self) -> None:
        spec = _rust_build_spec("cli", "arm64")

        self.assertEqual(spec.rust_target, "aarch64-unknown-linux-musl")
        self.assertEqual(spec.zig_target, "aarch64-linux-musl")

    def test_rejects_unimplemented_component(self) -> None:
        with self.assertRaisesRegex(ValueError, "added incrementally"):
            _rust_build_spec("gateway", "amd64")

    def test_validates_version_and_features(self) -> None:
        _validate_inputs("0.12.3-rc.1", "feature-a,feature_b")

        with self.assertRaisesRegex(ValueError, "cargo-version"):
            _validate_inputs("not a version", "")
        with self.assertRaisesRegex(ValueError, "features"):
            _validate_inputs("0.12.3", "feature; echo unsafe")

    def test_validates_debian_version(self) -> None:
        _validate_deb_version("1:0.12.3~rc.1-2")

        with self.assertRaisesRegex(ValueError, "deb-version"):
            _validate_deb_version("0.12.3; echo unsafe")


if __name__ == "__main__":
    unittest.main()
