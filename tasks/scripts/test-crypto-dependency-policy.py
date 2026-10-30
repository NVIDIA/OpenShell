# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Exercise the real cargo-deny policy with tiny, offline Cargo package graphs.

No crypto code is built or downloaded. Package names and dependency edges are
enough to check that an approved wrapper cannot mask an application bypass.
This standalone runner needs no pytest environment in the Rust policy job.
Graph failures are collected so every case runs before the command fails.
"""

import json
import subprocess
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "deny.toml"


def check_graph(
    directory: Path,
    edges: list[tuple[str, str, str, str]],
    banned: tuple[str, ...] = (),
) -> None:
    """Each edge is (parent, package, manifest section, dependency alias)."""
    packages = {name for parent, child, _, _ in edges for name in (parent, child)}
    members = {
        name
        for name in packages
        if name.startswith("openshell-") or name == "policy-test-app"
    }
    directory.mkdir()
    (directory / "Cargo.toml").write_text(
        '[workspace]\nresolver = "2"\nmembers = '
        + json.dumps(sorted(members))
        + "\nexclude = "
        + json.dumps(sorted(packages - members))
        + "\n",
        encoding="utf-8",
    )
    for package in packages:
        source = directory / package / "src"
        source.mkdir(parents=True)
        (source / "lib.rs").write_text("", encoding="utf-8")
        manifest = (
            f'[package]\nname = "{package}"\nversion = "0.0.0"\nedition = "2021"\n'
        )
        sections: dict[str, list[str]] = {}
        for parent, child, section, alias in edges:
            if parent == package:
                sections.setdefault(section, []).append(
                    f'{alias} = {{ package = "{child}", path = "../{child}" }}'
                )
        for section, dependencies in sections.items():
            manifest += f"\n[{section}]\n" + "\n".join(dependencies) + "\n"
        (source.parent / "Cargo.toml").write_text(manifest, encoding="utf-8")

    result = subprocess.run(
        [
            "cargo",
            "deny",
            "--offline",
            "--color",
            "never",
            "--manifest-path",
            str(directory / "Cargo.toml"),
            "--config",
            str(POLICY),
            "check",
            "bans",
        ],
        cwd=directory,
        capture_output=True,
        text=True,
        check=False,
    )
    output = result.stdout + result.stderr
    if not banned:
        passed = result.returncode == 0
    else:
        # A metadata/configuration failure must not count as a successful ban.
        passed = result.returncode != 0 and all(
            f"error[banned]: crate '{package} =" in output for package in banned
        )
    if not passed:
        raise AssertionError(f"{directory.name}: unexpected policy result\n{output}")
    print(f"PASS {directory.name}")


def edge(
    parent: str, child: str, section: str = "dependencies", alias: str = ""
) -> tuple[str, str, str, str]:
    return parent, child, section, alias or child


def main() -> None:
    tools = tomllib.loads((ROOT / "mise.toml").read_text(encoding="utf-8"))["tools"]
    expected = tools["github:EmbarkStudios/cargo-deny"]["version"]
    version = subprocess.run(
        ["cargo", "deny", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    if version.returncode != 0 or version.stdout.strip() != f"cargo-deny {expected}":
        actual = (version.stdout + version.stderr).strip()
        raise RuntimeError(
            f"Crypto policy fixtures require cargo-deny {expected} from mise.toml; "
            f"found: {actual}. Run mise install, then mise run rust:deny:policy."
        )
    facade = [
        edge("policy-test-app", "openshell-crypto"),
        edge("openshell-crypto", "aws-lc-rs"),
        edge("aws-lc-rs", "aws-lc-sys"),
        edge("aws-lc-rs", "aws-lc-fips-sys"),
        edge("openshell-crypto", "openssl"),
        edge("openssl", "openssl-sys"),
        edge("openshell-crypto", "rustls-openssl"),
        edge("rustls-openssl", "openssl"),
        edge("rustls-openssl", "openssl-sys"),
        edge("openshell-crypto", "jsonwebtoken-openssl"),
        edge("jsonwebtoken-openssl", "openssl"),
    ]
    failures: list[AssertionError] = []

    def run_graph(
        directory: Path,
        edges: list[tuple[str, str, str, str]],
        banned: tuple[str, ...] = (),
    ) -> None:
        try:
            check_graph(directory, edges, banned)
        except AssertionError as error:
            failures.append(error)
            print(f"FAIL {directory.name}")

    with tempfile.TemporaryDirectory(prefix="openshell-crypto-policy-") as temp:
        root = Path(temp)
        run_graph(root / "facade-backends", facade)
        run_graph(
            root / "vendored-openssl",
            [*facade, edge("openssl-sys", "openssl-src", "build-dependencies")],
            ("openssl-src",),
        )
        run_graph(
            root / "documented-exceptions",
            [
                edge("openshell-server", "rsa", "dev-dependencies"),
                edge("openshell-driver-vault", "sha2"),
                edge("policy-test-app", "russh"),
                edge("russh", "aes"),
                edge("policy-test-app", "rustls"),
                edge("rustls", "ring"),
            ],
        )
        # Keep the valid facade path present in every negative case. A shared
        # implementation must still reject each unapproved direct parent.
        direct_packages = (
            "aws-lc-rs",
            "aws-lc-sys",
            "aws-lc-fips-sys",
            "openssl",
            "openssl-sys",
            "openssl-src",
            "rustls-openssl",
            "jsonwebtoken-openssl",
            "ring",
            "sha2",
            "hmac",
            "aes-gcm",
            "rsa",
            "ed25519-dalek",
            "blake3",
            "ecdsa",
            "ml-kem",
        )
        # cargo-deny reports every violation; require each diagnostic so one
        # working ban cannot hide another missing or weakened rule.
        run_graph(
            root / "direct-dependencies",
            [
                *facade,
                *(edge("policy-test-app", package) for package in direct_packages),
            ],
            direct_packages,
        )
        for name, section in (
            ("renamed", "dependencies"),
            ("build", "build-dependencies"),
            ("dev", "dev-dependencies"),
            ("windows-only", "target.'cfg(windows)'.dependencies"),
        ):
            run_graph(
                root / name,
                [*facade, edge("policy-test-app", "openssl", section, "crypto_alias")],
                ("openssl",),
            )
        run_graph(
            root / "unapproved-wrapper",
            [
                *facade,
                edge("policy-test-app", "another-crypto-wrapper"),
                edge("another-crypto-wrapper", "openssl"),
            ],
            ("openssl",),
        )

    if failures:
        raise ExceptionGroup("Crypto dependency policy fixtures failed", failures)


if __name__ == "__main__":
    main()
