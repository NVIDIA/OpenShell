# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Sphinx extension that generates tables from a sandbox policy YAML file.

Usage in MyST markdown::

    ```{policy-table} path/to/sandbox-policy.yaml
    ```

The directive reads the YAML relative to the repo root and emits:
  1. A "Filesystem, Landlock, and Process" table.
  2. One subsection per ``network_policies`` block with endpoint and binary tables.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from docutils import nodes
from docutils.statemachine import StringList
from sphinx.application import Sphinx
from sphinx.util.docutils import SphinxDirective


def _tls_display(ep: dict[str, Any]) -> str:
    tls = ep.get("tls")
    return tls if tls else "\u2014"


def _access_display(ep: dict[str, Any]) -> str:
    if "rules" in ep:
        rules = ep["rules"]
        parts = []
        for r in rules:
            allow = r.get("allow", {})
            parts.append(f"``{allow.get('method', '*')} {allow.get('path', '/**')}``")
        return ", ".join(parts)
    access = ep.get("access")
    if access:
        return access
    return "L4 passthrough"


def _binaries_line(binaries: list[dict[str, str]]) -> str:
    paths = [f"``{b['path']}``" for b in binaries]
    return ", ".join(paths)


BLOCK_INFO: dict[str, dict[str, str]] = {
    "claude_code": {
        "title": "Anthropic API and Telemetry",
        "description": (
            "Allows Claude Code to reach its API, feature-flagging "
            "(Statsig), error reporting (Sentry), release notes, and "
            "the Claude platform dashboard."
        ),
    },
    "github_ssh_over_https": {
        "title": "Git Clone and Fetch",
        "description": (
            "Allows ``git clone``, ``git fetch``, and ``git pull`` over "
            "HTTPS via Git Smart HTTP. Push (``git-receive-pack``) is "
            "disabled by default."
        ),
    },
    "nvidia_inference": {
        "title": "NVIDIA API Catalog",
        "description": (
            "Allows outbound calls to the NVIDIA hosted inference API. "
            "Used by agents that route LLM requests through "
            "``integrate.api.nvidia.com``."
        ),
    },
    "github_rest_api": {
        "title": "GitHub API (Read-Only)",
        "description": (
            "Grants read-only access to the GitHub REST API. Enables "
            "issue reads, PR listing, and repository metadata lookups "
            "without allowing mutations."
        ),
    },
    "pypi": {
        "title": "Python Package Installation",
        "description": (
            "Allows ``pip install`` and ``uv pip install`` to reach PyPI, "
            "python-build-standalone releases on GitHub, and "
            "``downloads.python.org``."
        ),
    },
    "vscode": {
        "title": "VS Code Remote and Marketplace",
        "description": (
            "Allows VS Code Server, Remote Containers, and extension "
            "marketplace traffic so remote development sessions can "
            "download updates and extensions."
        ),
    },
    "gitlab": {
        "title": "GitLab",
        "description": (
            "Allows the ``glab`` CLI to reach ``gitlab.com`` for "
            "repository and merge-request operations."
        ),
    },
}


def _block_title(key: str, name: str) -> str:
    info = BLOCK_INFO.get(key)
    return info["title"] if info else name


def _block_description(key: str) -> str | None:
    info = BLOCK_INFO.get(key)
    return info["description"] if info else None


class PolicyTableDirective(SphinxDirective):
    """Render sandbox policy YAML as tables."""

    required_arguments = 1
    has_content = False

    def run(self) -> list[nodes.Node]:
        repo_root = Path(self.env.srcdir).parent
        yaml_path = repo_root / self.arguments[0]

        self.env.note_dependency(str(yaml_path))

        if not yaml_path.exists():
            msg = self.state_machine.reporter.warning(
                f"Policy YAML not found: {yaml_path}",
                line=self.lineno,
            )
            return [msg]

        policy = yaml.safe_load(yaml_path.read_text())

        lines: list[str] = []

        fs = policy.get("filesystem_policy", {})
        landlock = policy.get("landlock", {})
        proc = policy.get("process", {})

        lines.append("(default-policy-fs-landlock-process)=")
        lines.append("<h2>Filesystem, Landlock, and Process</h2>")
        lines.append("")
        lines.append("| Section | Setting | Value |")
        lines.append("|---|---|---|")

        ro = fs.get("read_only", [])
        rw = fs.get("read_write", [])
        workdir = fs.get("include_workdir", False)
        lines.append(
            f"| **Filesystem** | Read-only | {', '.join(f'``{p}``' for p in ro)} |"
        )
        lines.append(f"| | Read-write | {', '.join(f'``{p}``' for p in rw)} |")
        lines.append(f"| | Workdir included | {'Yes' if workdir else 'No'} |")

        compat = landlock.get("compatibility", "best_effort")
        lines.append(
            f"| **Landlock** | Compatibility | ``{compat}`` "
            f"(uses the highest ABI the host kernel supports) |"
        )

        user = proc.get("run_as_user", "")
        group = proc.get("run_as_group", "")
        lines.append(f"| **Process** | User / Group | ``{user}`` / ``{group}`` |")
        lines.append("")

        net = policy.get("network_policies", {})
        if net:
            lines.append("(default-policy-network-policies)=")
            lines.append("<h2>Network Policy Blocks</h2>")
            lines.append("")
            lines.append(
                "Each block pairs a set of endpoints (host and port) with "
                "a set of binaries (executable paths inside the sandbox). "
                "The proxy identifies the calling binary by resolving the "
                "socket to a PID through ``/proc/net/tcp`` and reading "
                "``/proc/{pid}/exe``. A connection is allowed only when both "
                "the destination and the calling binary match an entry in the "
                "same block. All other outbound traffic is denied."
            )
            lines.append("")

            for key, block in net.items():
                name = block.get("name", key)
                endpoints = block.get("endpoints", [])
                binaries = block.get("binaries", [])

                lines.append(f"<h3>{_block_title(key, name)}</h3>")
                lines.append("")
                desc = _block_description(key)
                if desc:
                    lines.append(desc)
                    lines.append("")

                has_rules = any("rules" in ep for ep in endpoints)
                if has_rules:
                    lines.append("| Endpoint | Port | TLS | Rules |")
                else:
                    lines.append("| Endpoint | Port | TLS | Access |")
                lines.append("|---|---|---|---|")

                for ep in endpoints:
                    host = ep.get("host", "")
                    port = ep.get("port", "")
                    tls = _tls_display(ep)
                    access = _access_display(ep)
                    lines.append(f"| ``{host}`` | {port} | {tls} | {access} |")

                lines.append("")
                lines.append(
                    f"Only the following binaries can use these endpoints: "
                    f"{_binaries_line(binaries)}."
                )
                lines.append("")

        rst = StringList(lines, source=str(yaml_path))
        container = nodes.container()
        self.state.nested_parse(rst, self.content_offset, container)
        return container.children


def setup(app: Sphinx) -> dict[str, Any]:
    app.add_directive("policy-table", PolicyTableDirective)
    return {
        "version": "0.1",
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }
