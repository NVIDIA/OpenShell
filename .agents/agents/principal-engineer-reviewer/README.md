# principal-engineer-reviewer

The principal engineer reviewer is a sub-agent prompt for code, plan, and architecture reviews. It is not yet a standalone agent runtime.

## Files

- `prompts/principal-engineer-reviewer.md` is the canonical, framework-neutral reviewer prompt. Edit reviewer behavior here.
- `adapters/claude.yaml` and `adapters/opencode.yaml` hold each framework's frontmatter: name, tool permissions, mode, and memory.

## Where it is used

- Claude Code and OpenCode load it as a sub-agent after `mise run agents:setup` generates `.claude/agents/` and `.opencode/agents/`. Both directories are ignored; rerun the task after changing this directory.
- Gator bakes the canonical prompt into its payload through `scripts/agents/gator/agent.yaml` and runs it with the selected harness.
