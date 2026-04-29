#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Render Homebrew formulae from GitHub release checksums."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO = "NVIDIA/OpenShell"
API_BASE = f"https://api.github.com/repos/{REPO}"
DOWNLOAD_BASE = f"https://github.com/{REPO}/releases/download"

CLI_CHECKSUMS = "openshell-checksums-sha256.txt"
GATEWAY_CHECKSUMS = "openshell-gateway-checksums-sha256.txt"
VM_CHECKSUMS = "vm-binary-checksums-sha256.txt"

TARGETS = {
    "macos_arm64": {
        "cli": "openshell-aarch64-apple-darwin.tar.gz",
        "gateway": "openshell-gateway-aarch64-apple-darwin.tar.gz",
        "driver": "openshell-driver-vm-aarch64-apple-darwin.tar.gz",
    },
    "linux_x86_64": {
        "cli": "openshell-x86_64-unknown-linux-musl.tar.gz",
        "gateway": "openshell-gateway-x86_64-unknown-linux-gnu.tar.gz",
        "driver": "openshell-driver-vm-x86_64-unknown-linux-gnu.tar.gz",
    },
    "linux_arm64": {
        "cli": "openshell-aarch64-unknown-linux-musl.tar.gz",
        "gateway": "openshell-gateway-aarch64-unknown-linux-gnu.tar.gz",
        "driver": "openshell-driver-vm-aarch64-unknown-linux-gnu.tar.gz",
    },
}


@dataclass(frozen=True)
class Release:
    tag: str
    target_commitish: str
    published_at: str
    html_url: str
    assets: dict[str, str]


@dataclass(frozen=True)
class FormulaSource:
    tag: str
    version: str
    cli: dict[str, str]
    gateway: dict[str, str]
    driver_tag: str
    driver: dict[str, str]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def request_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "openshell-homebrew-formula-updater",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def truncate_error_body(body: str) -> str:
    if len(body) <= 500:
        return body
    return body[:500] + "... [truncated]"


def fetch_url(url: str, *, accept: str | None = None) -> bytes:
    headers = request_headers()
    if accept is not None:
        headers["Accept"] = accept
    request = urllib.request.Request(url, headers=headers)
    retry_statuses = {502, 503, 504}

    for attempt in range(1, 4):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            if exc.code in retry_statuses and attempt < 3:
                time.sleep(attempt)
                continue
            raise RuntimeError(
                f"failed to fetch {url}: HTTP {exc.code}: {truncate_error_body(body)}"
            ) from exc
        except urllib.error.URLError as exc:
            if attempt < 3:
                time.sleep(attempt)
                continue
            raise RuntimeError(f"failed to fetch {url}: {exc.reason}") from exc

    raise RuntimeError(f"failed to fetch {url}")


def fetch_json(url: str) -> dict[str, Any]:
    return json.loads(fetch_url(url).decode("utf-8"))


def release_from_json(data: dict[str, Any]) -> Release:
    assets = {}
    for asset in data.get("assets", []):
        name = asset["name"]
        assets[name] = asset["url"]
    return Release(
        tag=data["tag_name"],
        target_commitish=data.get("target_commitish", ""),
        published_at=data.get("published_at", ""),
        html_url=data.get("html_url", ""),
        assets=assets,
    )


def fetch_latest_stable() -> Release:
    return release_from_json(fetch_json(f"{API_BASE}/releases/latest"))


def fetch_release(tag: str) -> Release:
    return release_from_json(fetch_json(f"{API_BASE}/releases/tags/{tag}"))


def fetch_release_asset(release: Release, name: str) -> str:
    try:
        url = release.assets[name]
    except KeyError as exc:
        available = ", ".join(sorted(release.assets))
        raise RuntimeError(
            f"release {release.tag} is missing asset {name}; available: {available}"
        ) from exc
    return fetch_url(url, accept="application/octet-stream").decode("utf-8")


def parse_checksums(text: str) -> dict[str, str]:
    checksums = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            raise RuntimeError(f"invalid checksum line: {line!r}")
        sha, filename = parts
        filename = filename.removeprefix("*")
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise RuntimeError(f"invalid sha256 for {filename}: {sha}")
        checksums[filename] = sha
    return checksums


def selected_checksums(checksums: dict[str, str], kind: str) -> dict[str, str]:
    result = {}
    for target, assets in TARGETS.items():
        name = assets[kind]
        try:
            result[target] = checksums[name]
        except KeyError as exc:
            raise RuntimeError(f"checksum file is missing {name}") from exc
    return result


def ensure_release_assets(release: Release, kind: str) -> None:
    missing = []
    for assets in TARGETS.values():
        name = assets[kind]
        if name not in release.assets:
            missing.append(name)
    if missing:
        missing_text = ", ".join(missing)
        raise RuntimeError(f"release {release.tag} is missing assets: {missing_text}")


def release_version(tag: str) -> str:
    return tag.removeprefix("v")


def short_ref(ref: str) -> str:
    value = re.sub(r"[^0-9A-Za-z]+", ".", ref).strip(".")
    return value[:12] or "unknown"


def existing_formula_metadata(path: Path) -> tuple[str | None, int]:
    if not path.exists():
        return None, 0

    text = path.read_text()
    version_match = re.search(r'^\s*version "([^"]+)"$', text, re.MULTILINE)
    url_version_match = re.search(
        r"releases/download/v([^/]+)/openshell-", text, re.MULTILINE
    )
    revision_match = re.search(r"^\s*revision (\d+)$", text, re.MULTILINE)
    version = (
        version_match.group(1)
        if version_match
        else url_version_match.group(1)
        if url_version_match
        else None
    )
    revision = int(revision_match.group(1)) if revision_match else 0
    return version, revision


def is_git_tracked(path: Path) -> bool:
    root = repo_root()
    try:
        rel_path = path.relative_to(root)
    except ValueError:
        return False

    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--error-unmatch", str(rel_path)],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def with_revision_bump(path: Path, version: str, render: Any) -> str:
    existing_version, existing_revision = existing_formula_metadata(path)
    revision = existing_revision if existing_version == version else 0
    rendered = render(revision)

    if (
        path.exists()
        and is_git_tracked(path)
        and existing_version == version
        and rendered != path.read_text()
    ):
        rendered = render(revision + 1)

    return rendered


def formula_url(tag: str, asset: str) -> str:
    return f"{DOWNLOAD_BASE}/{tag}/{asset}"


def resource_block(name: str, url: str, sha: str, indent: str = "    ") -> str:
    return (
        f'{indent}resource "{name}" do\n'
        f'{indent}  url "{url}"\n'
        f'{indent}  sha256 "{sha}"\n'
        f"{indent}end\n"
    )


def render_platform_blocks(source: FormulaSource) -> str:
    macos = TARGETS["macos_arm64"]
    linux_x86 = TARGETS["linux_x86_64"]
    linux_arm = TARGETS["linux_arm64"]

    return f"""  on_macos do
    depends_on arch: :arm64

    on_arm do
      url "{formula_url(source.tag, macos["cli"])}"
      sha256 "{source.cli["macos_arm64"]}"

{resource_block("openshell-gateway", formula_url(source.tag, macos["gateway"]), source.gateway["macos_arm64"], "      ")}
{resource_block("openshell-driver-vm", formula_url(source.driver_tag, macos["driver"]), source.driver["macos_arm64"], "      ")}    end
  end

  on_linux do
    on_intel do
      url "{formula_url(source.tag, linux_x86["cli"])}"
      sha256 "{source.cli["linux_x86_64"]}"

{resource_block("openshell-gateway", formula_url(source.tag, linux_x86["gateway"]), source.gateway["linux_x86_64"], "      ")}
{resource_block("openshell-driver-vm", formula_url(source.driver_tag, linux_x86["driver"]), source.driver["linux_x86_64"], "      ")}    end

    on_arm do
      url "{formula_url(source.tag, linux_arm["cli"])}"
      sha256 "{source.cli["linux_arm64"]}"

{resource_block("openshell-gateway", formula_url(source.tag, linux_arm["gateway"]), source.gateway["linux_arm64"], "      ")}
{resource_block("openshell-driver-vm", formula_url(source.driver_tag, linux_arm["driver"]), source.driver["linux_arm64"], "      ")}    end
  end
"""


def install_and_test_block() -> str:
    return r"""  def install
    bin.install "openshell"

    resource("openshell-gateway").stage do
      libexec.install "openshell-gateway"
    end

    driver_dir = libexec/"openshell"
    driver_dir.mkpath
    resource("openshell-driver-vm").stage do
      driver_dir.install "openshell-driver-vm"
    end

    if OS.mac?
      entitlements = buildpath/"openshell-driver-vm-entitlements.plist"
      entitlements.write <<~XML
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.apple.security.hypervisor</key>
            <true/>
        </dict>
        </plist>
      XML
      system "codesign", "--entitlements", entitlements, "--force", "-s", "-", driver_dir/"openshell-driver-vm"
    end

    gateway_wrapper = bin/"openshell-gateway"
    gateway_wrapper.write <<~SH
      #!/bin/sh
      export OPENSHELL_DRIVER_DIR="#{opt_libexec}/openshell"
      exec "#{opt_libexec}/openshell-gateway" "$@"
    SH
    chmod 0555, gateway_wrapper

    ln_s "../libexec/openshell/openshell-driver-vm", bin/"openshell-driver-vm"
  end

  test do
    assert_match(/^openshell \S+/, shell_output("#{bin}/openshell --version"))
    assert_match(/^openshell-gateway \S+/, shell_output("#{bin}/openshell-gateway --version"))
    assert_match(/^openshell-driver-vm \S+/, shell_output("#{bin}/openshell-driver-vm --version"))

    driver = libexec/"openshell/openshell-driver-vm"
    assert_path_exists driver
    assert_match(
      "OPENSHELL_DRIVER_DIR=\"#{opt_libexec}/openshell\"",
      (bin/"openshell-gateway").read,
    )

    if OS.mac?
      entitlements = shell_output("codesign -d --entitlements :- #{driver} 2>&1")
      assert_match "com.apple.security.hypervisor", entitlements
    end
  end
"""


def render_formula(
    *,
    class_name: str,
    desc: str,
    source: FormulaSource,
    conflicts_with: str,
    include_version: bool = True,
    revision: int = 0,
) -> str:
    version_line = f'  version "{source.version}"\n' if include_version else ""
    revision_line = f"  revision {revision}\n" if revision else ""
    return f'''# This file is generated by tasks/scripts/homebrew/update_formulae.py.

class {class_name} < Formula
  desc "{desc}"
  homepage "https://github.com/NVIDIA/OpenShell"
{version_line}  license "Apache-2.0"
{revision_line}
{render_platform_blocks(source)}
  conflicts_with "{conflicts_with}", because: "both install OpenShell command names"

{install_and_test_block()}end
'''


def build_formula_source(
    release: Release,
    driver_release: Release,
    *,
    version: str,
) -> FormulaSource:
    ensure_release_assets(release, "cli")
    ensure_release_assets(release, "gateway")
    ensure_release_assets(driver_release, "driver")

    cli_checksums = parse_checksums(fetch_release_asset(release, CLI_CHECKSUMS))
    gateway_checksums = parse_checksums(fetch_release_asset(release, GATEWAY_CHECKSUMS))
    driver_checksums = parse_checksums(
        fetch_release_asset(driver_release, VM_CHECKSUMS)
    )

    return FormulaSource(
        tag=release.tag,
        version=version,
        cli=selected_checksums(cli_checksums, "cli"),
        gateway=selected_checksums(gateway_checksums, "gateway"),
        driver_tag=driver_release.tag,
        driver=selected_checksums(driver_checksums, "driver"),
    )


def write_file(path: Path, content: str, *, check: bool) -> bool:
    if path.exists() and path.read_text() == content:
        return False
    if check:
        print(f"{path} is not up to date", file=sys.stderr)
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    print(f"wrote {path}")
    return True


def render_all(*, check: bool) -> bool:
    root = repo_root()
    formula_dir = root / "Formula"

    stable_release = fetch_latest_stable()
    dev_release = fetch_release("dev")
    vm_release = fetch_release("vm-dev")

    stable_version = release_version(stable_release.tag)
    stable_source = build_formula_source(
        stable_release,
        vm_release,
        version=stable_version,
    )
    dev_source = build_formula_source(
        dev_release,
        vm_release,
        version=(
            f"0.0.0-dev.{short_ref(dev_release.target_commitish)}"
            f".vm.{short_ref(vm_release.target_commitish)}"
        ),
    )

    stable_path = formula_dir / "openshell.rb"
    stable_formula = with_revision_bump(
        stable_path,
        stable_version,
        lambda revision: render_formula(
            class_name="Openshell",
            desc="Safe private runtime for autonomous AI agents",
            source=stable_source,
            conflicts_with="openshell-dev",
            include_version=False,
            revision=revision,
        ),
    )

    dev_formula = render_formula(
        class_name="OpenshellDev",
        desc="Development build of the safe private runtime for autonomous AI agents",
        source=dev_source,
        conflicts_with="openshell",
    )

    changed = False
    changed |= write_file(stable_path, stable_formula, check=check)
    changed |= write_file(formula_dir / "openshell-dev.rb", dev_formula, check=check)
    return changed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if generated formulae differ from files on disk",
    )
    args = parser.parse_args()

    try:
        changed = render_all(check=args.check)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    if args.check and changed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
