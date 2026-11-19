# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate local Claude Code and OpenCode adapters from `.agents/`.

`.claude/` and `.opencode/` are ignored. This script creates the entries those
tools need to discover the canonical contributor skills and agent prompts.
"""

from __future__ import annotations

import argparse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# (canonical agent, adapter frontmatter, generated definition)
AGENT_ADAPTERS = (
    (
        "principal-engineer-reviewer",
        "claude",
        ".claude/agents/principal-engineer-reviewer.md",
    ),
    (
        "principal-engineer-reviewer",
        "opencode",
        ".opencode/agents/principal-engineer-reviewer.md",
    ),
)

# Codex and OpenCode read `.agents/skills` directly; Claude Code does not.
SKILL_LINKS = ((".claude/skills", "../.agents/skills"),)


def render(root: Path, agent: str, adapter: str) -> str:
    agent_dir = root / ".agents/agents" / agent
    frontmatter = (agent_dir / "adapters" / f"{adapter}.yaml").read_text()
    body = (agent_dir / "prompts" / f"{agent}.md").read_text()
    if not frontmatter.strip() or not body.strip():
        raise ValueError(f"{agent} {adapter} adapter inputs must be nonempty")
    return f"---\n{frontmatter.rstrip()}\n---\n\n{body}"


def link_skills(root: Path, link: str, target: str) -> None:
    path = root / link
    if path.is_symlink():
        if str(path.readlink()) == target:
            return
        path.unlink()
    elif path.exists():
        raise FileExistsError(f"{link} exists and is not a symlink; move it aside")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(target, target_is_directory=True)


def sync(root: Path) -> list[str]:
    written = []
    for agent, adapter, destination in AGENT_ADAPTERS:
        path = root / destination
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render(root, agent, adapter))
        written.append(destination)
    for link, target in SKILL_LINKS:
        link_skills(root, link, target)
        written.append(link)
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    args = parser.parse_args()
    for path in sync(args.root):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
