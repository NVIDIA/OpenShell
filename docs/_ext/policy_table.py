# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Sphinx extension that generates tables from a sandbox policy YAML file.

Usage in MyST markdown::

    ```{policy-table} deploy/docker/sandbox/dev-sandbox-policy.yaml
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


def _block_subtitle(key: str, name: str) -> str:
    label_map = {
        "claude_code": "Anthropic API and Telemetry",
        "github_ssh_over_https": "Git Clone and Fetch",
        "nvidia_inference": "NVIDIA API Catalog",
        "github_rest_api": "GitHub API (Read-Only)",
        "pypi": "Python Package Installation",
        "vscode": "VS Code Remote and Marketplace",
        "gitlab": "GitLab",
    }
    subtitle = label_map.get(key, name)
    return f"{key} \u2014 {subtitle}"


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

        lines.append("### Filesystem, Landlock, and Process")
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
            lines.append("### Network Policy Blocks")
            lines.append("")

            for key, block in net.items():
                name = block.get("name", key)
                endpoints = block.get("endpoints", [])
                binaries = block.get("binaries", [])

                lines.append(f"**{_block_subtitle(key, name)}**")
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
                lines.append(f"**Binaries:** {_binaries_line(binaries)}")
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
