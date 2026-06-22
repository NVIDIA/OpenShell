#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Render the OpenShell client policy for a conformance server URL.

Parses the server URL into host/port/path, substitutes them into
policy-template.yaml, writes the rendered policy, and prints the (possibly
rewritten) URL the client should connect to. Used both to seed the reusable
client sandbox with a placeholder policy and to install the per-scenario policy
in client-through-openshell.sh.

Usage: render-policy.py <server-url> <policy-file> <policy-template>
"""

import json
import os
import string
import sys
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse, urlunparse

raw_url, policy_file, policy_template = sys.argv[1:4]
parsed = urlparse(raw_url)

if parsed.scheme not in ("http", "https"):
    raise SystemExit(f"unsupported conformance server URL scheme: {parsed.scheme!r}")

host = parsed.hostname
if not host:
    raise SystemExit(f"conformance server URL is missing a host: {raw_url}")

expected_host = os.environ.get("OPENSHELL_MCP_CONFORMANCE_EXPECTED_SERVER_HOST")
if expected_host:
    try:
        actual_ip = ip_address(host)
        actual_ip = getattr(actual_ip, "ipv4_mapped", None) or actual_ip
        expected_ip = ip_address(expected_host)
        expected_ip = getattr(expected_ip, "ipv4_mapped", None) or expected_ip
    except ValueError as err:
        raise SystemExit(
            "conformance server URL host must be an IP address when "
            "OPENSHELL_MCP_CONFORMANCE_EXPECTED_SERVER_HOST is set"
        ) from err
    if actual_ip != expected_ip:
        raise SystemExit(
            f"conformance server URL host {actual_ip} does not match expected "
            f"runner host {expected_ip}"
        )

target_host = (
    "host.openshell.internal" if host in {"localhost", "127.0.0.1", "::1"} else host
)
port = parsed.port or (443 if parsed.scheme == "https" else 80)
path = parsed.path or "/"
netloc_host = (
    f"[{target_host}]"
    if ":" in target_host and not target_host.startswith("[")
    else target_host
)
netloc = f"{netloc_host}:{port}"
rewritten = urlunparse(
    (parsed.scheme, netloc, path, parsed.params, parsed.query, parsed.fragment)
)

template = string.Template(Path(policy_template).read_text(encoding="utf-8"))
policy = template.substitute(
    host_spec=f"host: {json.dumps(target_host)}",
    port_spec=f"        port: {port}",
    path=json.dumps(path),
)
Path(policy_file).write_text(policy, encoding="utf-8")

print(rewritten)
