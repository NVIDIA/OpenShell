# Supported Agents

The following table summarizes the agents that run in OpenShell sandboxes. All agent sandbox images are maintained in the [OpenShell Community](https://github.com/NVIDIA/OpenShell-Community) repository. Agents in the base image are auto-configured when passed as the trailing command to `openshell sandbox create`.

| Agent | Source | Default Policy | Notes |
|---|---|---|---|
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | [`base`](https://github.com/NVIDIA/OpenShell-Community/tree/main/sandboxes/base) | Full coverage | Works out of the box. Requires `ANTHROPIC_API_KEY`. |
| [OpenCode](https://opencode.ai/) | [`base`](https://github.com/NVIDIA/OpenShell-Community/tree/main/sandboxes/base) | Partial coverage | Pre-installed. Add `opencode.ai` endpoint and OpenCode binary paths to the policy for full functionality. |
| [Codex](https://developers.openai.com/codex) | [`base`](https://github.com/NVIDIA/OpenShell-Community/tree/main/sandboxes/base) | No coverage | Pre-installed. Requires a custom policy with OpenAI endpoints and Codex binary paths. Requires `OPENAI_API_KEY`. |
| [OpenClaw](https://openclaw.ai/) | [`openclaw`](https://github.com/NVIDIA/OpenShell-Community/tree/main/sandboxes/openclaw) | Bundled | Agent orchestration layer. Launch with `openshell sandbox create --from openclaw`. |

More community agent sandboxes are available in the {doc}`../sandboxes/community-sandboxes` catalog.

For a complete support matrix, refer to the {doc}`../reference/support-matrix` page.