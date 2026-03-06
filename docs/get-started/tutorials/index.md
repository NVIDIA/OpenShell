# Tutorials

Each tutorial walks through an end-to-end workflow from bootstrapping a cluster to running an agent inside a policy-enforced sandbox. Pick the tutorial that matches your agent and follow along.

All tutorials assume you have [installed the CLI](../../index.md#install-the-nemoclaw-cli) and have Docker running.

::::{grid} 1 1 2 2
:gutter: 3

:::{grid-item-card} Run OpenClaw Safely
:link: run-openclaw
:link-type: doc

Launch OpenClaw inside a NemoClaw sandbox with inference routing and policy enforcement.
+++
{bdg-secondary}`Tutorial`
:::

:::{grid-item-card} Run Claude Safely
:link: run-claude
:link-type: doc

Run Anthropic Claude as a coding agent with credential management, inference routing, and policy enforcement.
+++
{bdg-secondary}`Tutorial`
:::

:::{grid-item-card} Run OpenCode with NVIDIA Inference
:link: run-opencode
:link-type: doc

Set up opencode with NVIDIA inference routing, custom policies, and the full policy iteration loop.
+++
{bdg-secondary}`Tutorial`
:::

::::

```{toctree}
:hidden:
:maxdepth: 2

Run OpenClaw Safely <run-openclaw>
Run Claude Safely <run-claude>
Run Opencode with NVIDIA Inference <run-opencode>
Run Any Agent Safely <run-agents>
```
