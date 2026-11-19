# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import agent_adapters

REVIEWER = agent_adapters.REPO_ROOT / ".agents/agents/principal-engineer-reviewer"


@pytest.fixture
def root(tmp_path):
    shutil.copytree(REVIEWER, tmp_path / ".agents/agents/principal-engineer-reviewer")
    (tmp_path / ".agents/skills/example").mkdir(parents=True)
    return tmp_path


def frontmatter(text):
    assert text.startswith("---\n")
    header, body = text[4:].split("\n---\n\n", 1)
    return header, body


def test_adapters_share_the_canonical_prompt(root):
    agent_adapters.sync(root)
    canonical = (REVIEWER / "prompts/principal-engineer-reviewer.md").read_text()
    for _, _, destination in agent_adapters.AGENT_ADAPTERS:
        _, body = frontmatter((root / destination).read_text())
        assert body == canonical


def test_canonical_prompt_has_no_framework_frontmatter():
    prompt = (REVIEWER / "prompts/principal-engineer-reviewer.md").read_text()
    assert not prompt.startswith("---")


def test_adapters_preserve_framework_permissions(root):
    agent_adapters.sync(root)
    claude, _ = frontmatter(
        (root / ".claude/agents/principal-engineer-reviewer.md").read_text()
    )
    assert "name: principal-engineer-reviewer" in claude
    assert "tools: Read, Grep, Glob, Bash, WebFetch, WebSearch" in claude
    assert "memory: project" in claude
    opencode, _ = frontmatter(
        (root / ".opencode/agents/principal-engineer-reviewer.md").read_text()
    )
    assert "mode: subagent" in opencode
    assert "write: false" in opencode
    assert "edit: false" in opencode


def test_claude_skills_link_targets_shared_skills(root):
    agent_adapters.sync(root)
    link = root / ".claude/skills"
    assert link.is_symlink()
    assert (link / "example").is_dir()


def test_sync_is_idempotent(root):
    first = agent_adapters.sync(root)
    assert agent_adapters.sync(root) == first


def test_sync_refuses_to_replace_a_real_skills_directory(root):
    (root / ".claude/skills").mkdir(parents=True)
    with pytest.raises(FileExistsError):
        agent_adapters.sync(root)
