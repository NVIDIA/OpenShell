#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Resolve missing and hash-based licenses in CycloneDX SBOM JSON files.

Queries public registries:
  - crates.io    (pkg:cargo/*)
  - npm          (pkg:npm/*)
  - PyPI         (pkg:pypi/*)
  - Known maps   (pkg:golang/*, pkg:deb/*, operating-system, application)

Updates the JSON files in-place, then reports what was resolved.

Usage:
    python resolve_licenses.py                      # resolve all *.cdx.json in deploy/sbom/output/
    python resolve_licenses.py file1.json ...       # resolve specific files
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ---------------------------------------------------------------------------
# Known licenses for packages that registries won't resolve
# ---------------------------------------------------------------------------
KNOWN_LICENSES: dict[str, str] = {
    # libxcrypt -- all variants
    "libcrypt-dev": "LGPL-2.1-or-later",
    "libcrypt1": "LGPL-2.1-or-later",
    # python3-defaults -- all variants
    "python3": "PSF-2.0",
    "python3-minimal": "PSF-2.0",
    "libpython3-stdlib": "PSF-2.0",
    "python3-venv": "PSF-2.0",
    # Go standard library / well-known
    "golang.org/x/crypto": "BSD-3-Clause",
    "golang.org/x/mod": "BSD-3-Clause",
    "golang.org/x/net": "BSD-3-Clause",
    "golang.org/x/sync": "BSD-3-Clause",
    "golang.org/x/sys": "BSD-3-Clause",
    "golang.org/x/term": "BSD-3-Clause",
    "golang.org/x/text": "BSD-3-Clause",
    "google.golang.org/grpc": "Apache-2.0",
    "google.golang.org/protobuf": "BSD-3-Clause",
    "google.golang.org/genproto/googleapis/api": "Apache-2.0",
    "google.golang.org/genproto/googleapis/rpc": "Apache-2.0",
    "gopkg.in/yaml.v3": "MIT",
    "go.yaml.in/yaml/v3": "MIT",
    "go.opentelemetry.io/otel": "Apache-2.0",
    "go.opentelemetry.io/otel/metric": "Apache-2.0",
    "go.opentelemetry.io/otel/trace": "Apache-2.0",
    "go.opentelemetry.io/auto/sdk": "Apache-2.0",
    "go.mongodb.org/mongo-driver": "Apache-2.0",
    # Debian / Ubuntu system packages
    "debian": "GPL-2.0-only",
    "ubuntu": "GPL-2.0-only",
    # Application entries without purl
    "Simple Launcher": "Proprietary",
    "python": "PSF-2.0",
}

# Well-known Go module licenses (GitHub-based)
GO_KNOWN: dict[str, str] = {
    "github.com/AlecAivazis/survey": "MIT",
    "github.com/MakeNowJust/heredoc": "MIT",
    "github.com/Masterminds/goutils": "Apache-2.0",
    "github.com/Masterminds/semver": "MIT",
    "github.com/Masterminds/sprig": "MIT",
    "github.com/alecthomas/chroma": "MIT",
    "github.com/asaskevich/govalidator": "MIT",
    "github.com/atotto/clipboard": "BSD-3-Clause",
    "github.com/aymanbagabas/go-osc52": "MIT",
    "github.com/aymerick/douceur": "MIT",
    "github.com/blang/semver": "MIT",
    "github.com/briandowns/spinner": "Apache-2.0",
    "github.com/catppuccin/go": "MIT",
    "github.com/cenkalti/backoff": "MIT",
    "github.com/charmbracelet/bubbles": "MIT",
    "github.com/charmbracelet/bubbletea": "MIT",
    "github.com/charmbracelet/colorprofile": "MIT",
    "github.com/charmbracelet/glamour": "MIT",
    "github.com/charmbracelet/huh": "MIT",
    "github.com/charmbracelet/lipgloss": "MIT",
    "github.com/charmbracelet/x": "MIT",
    "github.com/cli/browser": "BSD-2-Clause",
    "github.com/cli/cli": "MIT",
    "github.com/cli/go-gh": "MIT",
    "github.com/cli/oauth": "MIT",
    "github.com/cli/safeexec": "BSD-2-Clause",
    "github.com/cli/shurcooL-graphql": "MIT",
    "github.com/containerd/stargz-snapshotter": "Apache-2.0",
    "github.com/cyberphone/json-canonicalization": "Apache-2.0",
    "github.com/davecgh/go-spew": "ISC",
    "github.com/digitorus/pkcs7": "MIT",
    "github.com/digitorus/timestamp": "MIT",
    "github.com/distribution/reference": "Apache-2.0",
    "github.com/dlclark/regexp2": "MIT",
    "github.com/docker/cli": "Apache-2.0",
    "github.com/docker/distribution": "Apache-2.0",
    "github.com/docker/docker-credential-helpers": "MIT",
    "github.com/dustin/go-humanize": "MIT",
    "github.com/fatih/color": "MIT",
    "github.com/gabriel-vasile/mimetype": "MIT",
    "github.com/gdamore/encoding": "Apache-2.0",
    "github.com/gdamore/tcell": "Apache-2.0",
    "github.com/go-logr/logr": "Apache-2.0",
    "github.com/go-logr/stdr": "Apache-2.0",
    "github.com/go-openapi/analysis": "Apache-2.0",
    "github.com/go-openapi/errors": "Apache-2.0",
    "github.com/go-openapi/jsonpointer": "Apache-2.0",
    "github.com/go-openapi/jsonreference": "Apache-2.0",
    "github.com/go-openapi/loads": "Apache-2.0",
    "github.com/go-openapi/runtime": "Apache-2.0",
    "github.com/go-openapi/spec": "Apache-2.0",
    "github.com/go-openapi/strfmt": "Apache-2.0",
    "github.com/go-openapi/swag": "Apache-2.0",
    "github.com/go-openapi/validate": "Apache-2.0",
    "github.com/go-viper/mapstructure": "MIT",
    "github.com/godbus/dbus": "BSD-2-Clause",
    "github.com/golang/snappy": "BSD-3-Clause",
    "github.com/google/certificate-transparency-go": "Apache-2.0",
    "github.com/google/go-containerregistry": "Apache-2.0",
    "github.com/google/shlex": "Apache-2.0",
    "github.com/google/uuid": "BSD-3-Clause",
    "github.com/gorilla/css": "BSD-3-Clause",
    "github.com/gorilla/websocket": "BSD-2-Clause",
    "github.com/grpc-ecosystem/grpc-gateway": "BSD-3-Clause",
    "github.com/hashicorp/go-version": "MPL-2.0",
    "github.com/henvic/httpretty": "MIT",
    "github.com/huandu/xstrings": "MIT",
    "github.com/in-toto/attestation": "Apache-2.0",
    "github.com/in-toto/in-toto-golang": "Apache-2.0",
    "github.com/itchyny/gojq": "MIT",
    "github.com/itchyny/timefmt-go": "MIT",
    "github.com/joho/godotenv": "MIT",
    "github.com/kballard/go-shellquote": "MIT",
    "github.com/klauspost/compress": "Apache-2.0",
    "github.com/lucasb-eyer/go-colorful": "MIT",
    "github.com/mattn/go-colorable": "MIT",
    "github.com/mattn/go-isatty": "MIT",
    "github.com/mattn/go-runewidth": "MIT",
    "github.com/mgutz/ansi": "MIT",
    "github.com/microcosm-cc/bluemonday": "BSD-3-Clause",
    "github.com/microsoft/dev-tunnels": "MIT",
    "github.com/mitchellh/copystructure": "MIT",
    "github.com/mitchellh/go-homedir": "MIT",
    "github.com/mitchellh/hashstructure": "MIT",
    "github.com/mitchellh/reflectwalk": "MIT",
    "github.com/muesli/ansi": "MIT",
    "github.com/muesli/cancelreader": "MIT",
    "github.com/muesli/reflow": "MIT",
    "github.com/muesli/termenv": "MIT",
    "github.com/muhammadmuzzammil1998/jsonc": "MIT",
    "github.com/oklog/ulid": "Apache-2.0",
    "github.com/opencontainers/go-digest": "Apache-2.0",
    "github.com/opencontainers/image-spec": "Apache-2.0",
    "github.com/opentracing/opentracing-go": "Apache-2.0",
    "github.com/pkg/errors": "BSD-2-Clause",
    "github.com/pmezard/go-difflib": "BSD-3-Clause",
    "github.com/rivo/tview": "MIT",
    "github.com/rivo/uniseg": "MIT",
    "github.com/rodaine/table": "MIT",
    "github.com/secure-systems-lab/go-securesystemslib": "MIT",
    "github.com/shibumi/go-pathspec": "Apache-2.0",
    "github.com/shopspring/decimal": "MIT",
    "github.com/shurcooL/githubv4": "MIT",
    "github.com/shurcooL/graphql": "MIT",
    "github.com/sigstore/protobuf-specs": "Apache-2.0",
    "github.com/sigstore/rekor-tiles": "Apache-2.0",
    "github.com/sigstore/rekor": "Apache-2.0",
    "github.com/sigstore/sigstore-go": "Apache-2.0",
    "github.com/sigstore/sigstore": "Apache-2.0",
    "github.com/sigstore/timestamp-authority": "Apache-2.0",
    "github.com/sirupsen/logrus": "MIT",
    "github.com/spf13/cast": "MIT",
    "github.com/spf13/cobra": "Apache-2.0",
    "github.com/spf13/pflag": "BSD-3-Clause",
    "github.com/stretchr/objx": "MIT",
    "github.com/stretchr/testify": "MIT",
    "github.com/theupdateframework/go-tuf": "MIT",
    "github.com/thlib/go-timezone-local": "Unlicense",
    "github.com/transparency-dev/formats": "Apache-2.0",
    "github.com/transparency-dev/merkle": "Apache-2.0",
    "github.com/vbatts/tar-split": "BSD-3-Clause",
    "github.com/vmihailenco/msgpack": "BSD-2-Clause",
    "github.com/vmihailenco/tagparser": "BSD-2-Clause",
    "github.com/xo/terminfo": "MIT",
    "github.com/yuin/goldmark-emoji": "MIT",
    "github.com/yuin/goldmark": "MIT",
    "github.com/zalando/go-keyring": "MIT",
    "dario.cat/mergo": "BSD-3-Clause",
}

# Rate-limit helpers (thread-safe)
_last_request: dict[str, float] = {}
_rate_lock = threading.Lock()


def _rate_limit(domain: str, interval: float = 0.15) -> None:
    with _rate_lock:
        now = time.time()
        last = _last_request.get(domain, 0)
        wait = interval - (now - last)
        if wait > 0:
            time.sleep(wait)
        _last_request[domain] = time.time()


def _get_json(url: str, domain: str) -> dict | None:
    _rate_limit(domain)
    req = urllib.request.Request(
        url, headers={"User-Agent": "sbom-license-resolver/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        return None


# ---------------------------------------------------------------------------
# Registry lookups
# ---------------------------------------------------------------------------


def lookup_cargo(name: str, version: str) -> str | None:
    """Query crates.io for a crate's license."""
    data = _get_json(f"https://crates.io/api/v1/crates/{name}/{version}", "crates.io")
    if data and "version" in data:
        return data["version"].get("license")
    # fallback: try crate-level
    data = _get_json(f"https://crates.io/api/v1/crates/{name}", "crates.io")
    if data and "crate" in data:
        versions = data.get("versions", [])
        for v in versions:
            if v.get("num") == version:
                return v.get("license")
        # last resort: latest version license
        if versions:
            return versions[0].get("license")
    return None


def lookup_npm(name: str, version: str) -> str | None:
    """Query npm registry for a package's license."""
    encoded = urllib.parse.quote(name, safe="")
    data = _get_json(
        f"https://registry.npmjs.org/{encoded}/{version}", "registry.npmjs.org"
    )
    if data:
        lic = data.get("license")
        if isinstance(lic, dict):
            return lic.get("type")
        if isinstance(lic, str):
            return lic
    return None


def lookup_pypi(name: str, version: str) -> str | None:
    """Query PyPI for a package's license."""
    data = _get_json(f"https://pypi.org/pypi/{name}/{version}/json", "pypi.org")
    if data and "info" in data:
        lic = data["info"].get("license")
        if lic and len(lic) < 100:  # skip full license texts
            return lic
        # Try classifiers
        for c in data["info"].get("classifiers", []):
            if c.startswith("License :: OSI Approved :: "):
                return c.split(" :: ")[-1]
    return None


def resolve_go_name(full_name: str) -> str | None:
    """Resolve a Go module name to a known license via GO_KNOWN map."""
    # Try exact match first
    if full_name in GO_KNOWN:
        return GO_KNOWN[full_name]
    # Try stripping version suffix (e.g. github.com/foo/bar/v2 -> github.com/foo/bar)
    parts = full_name.split("/")
    for i in range(len(parts), 1, -1):
        candidate = "/".join(parts[:i])
        if candidate in GO_KNOWN:
            return GO_KNOWN[candidate]
    # Try just org/repo for github.com paths
    if full_name.startswith("github.com/") and len(parts) >= 3:
        base = "/".join(parts[:3])
        if base in GO_KNOWN:
            return GO_KNOWN[base]
    return None


def resolve_component(comp: dict) -> str | None:
    """Try to resolve a license for a component."""
    name = comp.get("name", "")
    version = comp.get("version", "")
    purl = comp.get("purl", "")
    comp_type = comp.get("type", "")

    # 1. Check hardcoded known licenses
    if name in KNOWN_LICENSES:
        return KNOWN_LICENSES[name]

    # 2. Route by purl type
    if purl.startswith("pkg:cargo/"):
        return lookup_cargo(name, version)
    if purl.startswith("pkg:npm/"):
        return lookup_npm(name, version)
    if purl.startswith("pkg:pypi/"):
        return lookup_pypi(name, version)
    if purl.startswith("pkg:golang/"):
        return resolve_go_name(name)
    if purl.startswith("pkg:deb/"):
        # Check known map by base package name
        base = name.split(":")[0]  # strip arch qualifier
        if base in KNOWN_LICENSES:
            return KNOWN_LICENSES[base]
        return None
    if comp_type == "operating-system":
        return KNOWN_LICENSES.get(name)
    if not purl:
        return KNOWN_LICENSES.get(name)

    return None


def set_license(comp: dict, license_id: str) -> None:
    """Set the license on a component, replacing hash or empty."""
    comp["licenses"] = [{"license": {"id": license_id}}]


def needs_fix(comp: dict) -> bool:
    """Check if component has missing or hash-based license."""
    licenses = comp.get("licenses", [])
    if not licenses:
        return True
    for entry in licenses:
        lic = entry.get("license", {})
        lid = lic.get("id", "")
        lname = lic.get("name", "")
        if lid.startswith("sha256:") or lname.startswith("sha256:"):
            return True
    return False


def _find_sbom_files() -> list[Path]:
    """Find SBOM JSON files in the default output directory."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    output_dir = repo_root / "deploy" / "sbom" / "output"
    return sorted(output_dir.glob("*.cdx.json"))


def _classify_registry(comp: dict) -> str:
    """Return the registry group for a component."""
    purl = comp.get("purl", "")
    name = comp.get("name", "")
    comp_type = comp.get("type", "")

    if name in KNOWN_LICENSES:
        return "known"
    if purl.startswith("pkg:cargo/"):
        return "crates.io"
    if purl.startswith("pkg:npm/"):
        return "npm"
    if purl.startswith("pkg:pypi/"):
        return "pypi"
    if purl.startswith("pkg:golang/"):
        return "golang"
    if purl.startswith("pkg:deb/"):
        return "deb"
    if comp_type == "operating-system" or not purl:
        return "known"
    return "other"


def _resolve_one(key: str, comp: dict) -> tuple[str, str | None]:
    """Resolve a single component, returning (key, license_id | None)."""
    return key, resolve_component(comp)


# Concurrency: different registries can run in parallel; within a domain
# the rate limiter serialises requests via the shared lock.
_MAX_WORKERS = 12


def main() -> None:
    files = [Path(p) for p in sys.argv[1:]] if len(sys.argv) > 1 else _find_sbom_files()

    if not files:
        print("No SBOM JSON files found.")
        print("Run 'mise run sbom:generate' first, or pass file paths as arguments.")
        sys.exit(1)

    print(f"Loading {len(files)} SBOM file(s)...")

    # Collect unique components needing fixes
    to_resolve: dict[str, dict] = {}  # key -> representative component
    total_components = 0
    for f in files:
        with f.open() as fh:
            sbom = json.load(fh)
        components = sbom.get("components", [])
        total_components += len(components)
        for comp in components:
            if needs_fix(comp):
                key = f"{comp.get('name', '')}@{comp.get('version', '')}"
                if key not in to_resolve:
                    to_resolve[key] = comp

    total = len(to_resolve)
    print(f"  {total_components} total components, {total} need license resolution")

    if total == 0:
        print("All licenses already resolved.")
        return

    # Classify by registry for progress reporting
    groups: dict[str, list[tuple[str, dict]]] = {}
    for key, comp in to_resolve.items():
        registry = _classify_registry(comp)
        groups.setdefault(registry, []).append((key, comp))

    print("\n  Breakdown by registry:")
    for registry in sorted(groups):
        count = len(groups[registry])
        marker = "(local)" if registry in {"known", "golang", "deb"} else "(API)"
        print(f"    {registry:<12} {count:>5}  {marker}")

    # Resolve -- local lookups first (instant), then API calls concurrently
    resolved: dict[str, str] = {}
    failed: list[str] = []
    t0 = time.monotonic()

    local_registries = {"known", "golang", "deb", "other"}
    api_registries = {"crates.io", "npm", "pypi"}

    # Phase 1: local (no network)
    local_items = [
        (key, comp) for reg in local_registries for key, comp in groups.get(reg, [])
    ]
    for key, comp in local_items:
        lic = resolve_component(comp)
        if lic:
            resolved[key] = lic
        else:
            failed.append(key)

    if local_items:
        print(
            f"\n  Local lookups: {len(resolved)} resolved, "
            f"{len(failed)} unresolved  ({time.monotonic() - t0:.1f}s)"
        )

    # Phase 2: API calls (concurrent)
    api_items = [
        (key, comp) for reg in api_registries for key, comp in groups.get(reg, [])
    ]

    if api_items:
        api_total = len(api_items)
        api_resolved = 0
        api_failed = 0
        print(
            f"\n  Resolving {api_total} packages via registry APIs "
            f"({_MAX_WORKERS} workers)..."
        )

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = {
                pool.submit(_resolve_one, key, comp): key for key, comp in api_items
            }
            for done_count, future in enumerate(as_completed(futures), 1):
                key, lic = future.result()
                if lic:
                    resolved[key] = lic
                    api_resolved += 1
                else:
                    failed.append(key)
                    api_failed += 1

                if done_count % 50 == 0 or done_count == api_total:
                    elapsed = time.monotonic() - t0
                    sys.stdout.write(
                        f"\r    [{done_count}/{api_total}] "
                        f"resolved={api_resolved} failed={api_failed}  "
                        f"({elapsed:.1f}s)"
                    )
                    sys.stdout.flush()

        print()  # newline after progress

    elapsed = time.monotonic() - t0
    print(
        f"\n  Done: {len(resolved)}/{total} resolved, "
        f"{len(failed)} unresolved  ({elapsed:.1f}s)"
    )

    # Apply to all files
    total_patched = 0
    for f in files:
        with f.open() as fh:
            sbom = json.load(fh)

        patched = 0
        for comp in sbom.get("components", []):
            if needs_fix(comp):
                key = f"{comp.get('name', '')}@{comp.get('version', '')}"
                if key in resolved:
                    set_license(comp, resolved[key])
                    patched += 1

        with f.open("w") as fh:
            json.dump(sbom, fh, indent=2)
            fh.write("\n")

        total_patched += patched
        print(f"  {f.name}: patched {patched} components")

    print(f"\n  Total patches applied: {total_patched}")

    if failed:
        print(f"\n  --- Unresolved ({len(failed)}) ---")
        for key in sorted(failed):
            comp = to_resolve[key]
            print(f"    {key}  purl={comp.get('purl', '(none)')}")


if __name__ == "__main__":
    main()
