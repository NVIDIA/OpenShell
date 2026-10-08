# `.claude/` — Claude Code-specific configuration

Agent skills and sub-agent personas are canonical in `.agents/` and shared across all harnesses (Claude Code, OpenCode, Cursor, etc.). This directory contains only Claude Code-specific configuration that cannot be made tool-agnostic.

## Contents

- `skills/` and `agents/` — Symlinks to `.agents/skills/` and `.agents/agents/`. `.opencode/agents/` points at the same directory, so persona frontmatter must stay valid for both Claude Code and OpenCode.
- `agent-memory/` — Persistent agent memory files. Claude Code runtime state, not portable across tools.
