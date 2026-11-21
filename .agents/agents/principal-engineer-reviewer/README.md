# principal-engineer-reviewer

The principal engineer reviewer is a sub-agent prompt for code, plan, and architecture reviews. It is not yet a standalone agent runtime.

`prompts/principal-engineer-reviewer.md` is the canonical, framework-neutral prompt. Gator bakes it into its payload through `.agents/agents/gator/agent.yaml` and runs it with the selected harness.
