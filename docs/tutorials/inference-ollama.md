---
title:
  page: Inference with Ollama
  nav: Inference with Ollama
description: Run local and cloud models inside an OpenShell sandbox using the Ollama community sandbox, or route sandbox requests to a host-level Ollama server.
topics:
- Generative AI
- Cybersecurity
tags:
- Tutorial
- Inference Routing
- Ollama
- Local Inference
- Sandbox
content:
  type: tutorial
  difficulty: technical_intermediate
  audience:
  - engineer
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Run Local Inference with Ollama

This tutorial covers two ways to use Ollama with OpenShell:

1. **Ollama sandbox (recommended)** — a self-contained sandbox with Ollama, Claude Code, and Codex pre-installed. One command to start.
2. **Host-level Ollama** — run Ollama on the gateway host and route sandbox inference to it. Useful when you want a single Ollama instance shared across multiple sandboxes.

After completing this tutorial, you will know how to:

- Launch the Ollama community sandbox for a batteries-included experience.
- Use `ollama launch` to start coding agents inside a sandbox.
- Expose a host-level Ollama server to sandboxes through `inference.local`.

## Prerequisites

- A working OpenShell installation. Complete the {doc}`/get-started/quickstart` before proceeding.

## Option A: Ollama Community Sandbox (Recommended)

The Ollama community sandbox bundles Ollama, Claude Code, OpenCode, and Codex into a single image. Ollama starts automatically when the sandbox launches.

### Step 1: Create the Sandbox

```console
$ openshell sandbox create --from ollama
```

This pulls the community sandbox image, applies the bundled policy, and drops you into a shell with Ollama running.

:::

### Step 2: Chat with a Model

Chat with a local model

```console
$ ollama run qwen3.5
```

Or a cloud model

```console
$ ollama run kimi-k2.5:cloud
```


Or use `ollama launch` to start a coding agent with Ollama as the model backend:

```console
$ ollama launch claude
$ ollama launch codex
$ ollama launch opencode
```

For CI/CD and automated workflows, `ollama launch` supports a headless mode:

```console
$ ollama launch claude --yes --model qwen3.5
```

### Model Recommendations

| Use case | Model | Notes |
|---|---|---|
| Smoke test | `qwen3.5:0.8b` | Fast, lightweight, good for verifying setup |
| Coding and reasoning | `qwen3.5` | Strong tool calling support for agentic workflows |
| Complex tasks | `nemotron-3-super` | 122B parameter model, needs 48GB+ VRAM |
| No local GPU | `qwen3.5:cloud` | Runs on Ollama's cloud infrastructure, no `ollama pull` required |

:::{note}
Cloud models use the `:cloud` tag suffix and do not require local hardware.

```console
$ openshell sandbox create --from ollama
```
:::

### Tool Calling

Agentic workflows (Claude Code, Codex, OpenCode) rely on tool calling. The following models have reliable tool calling support: Qwen 3.5, Nemotron-3-Super, GLM-5, and Kimi-K2.5. Check the [Ollama model library](https://ollama.com/library) for the latest models.

### Updating Ollama

To update Ollama inside a running sandbox:

```console
$ update-ollama
```

Or auto-update on every sandbox start:

```console
$ openshell sandbox create --from ollama -e OLLAMA_UPDATE=1
```

## Option B: Host-Level Ollama

Use this approach when you want a single Ollama instance on the gateway host, shared across multiple sandboxes through `inference.local`.

:::{note}
This approach uses Ollama because it is easy to install and run locally, but you can substitute other inference engines such as vLLM, SGLang, TRT-LLM, and NVIDIA NIM by changing the startup command, base URL, and model name.
:::

### Step 1: Install and Start Ollama

Install [Ollama](https://ollama.com/) on the gateway host:

```console
$ curl -fsSL https://ollama.com/install.sh | sh
```

Start Ollama on all interfaces so it is reachable from sandboxes:

```console
$ OLLAMA_HOST=0.0.0.0:11434 ollama serve
```

:::{tip}
If you see `Error: listen tcp 0.0.0.0:11434: bind: address already in use`, Ollama is already running as a system service. Stop it first:

```console
$ systemctl stop ollama
$ OLLAMA_HOST=0.0.0.0:11434 ollama serve
```
:::

### Step 2: Pull a Model

In a second terminal, pull a model:

```console
$ ollama run qwen3.5:0.8b
```

Type `/bye` to exit the interactive session. The model stays loaded.

### Step 3: Create a Provider

Create an OpenAI-compatible provider pointing at the host Ollama:

```console
$ openshell provider create \
    --name ollama \
    --type openai \
    --credential OPENAI_API_KEY=empty \
    --config OPENAI_BASE_URL=http://host.openshell.internal:11434/v1
```

OpenShell injects `host.openshell.internal` so sandboxes and the gateway can reach the host machine. You can also use the host's LAN IP.

### Step 4: Set Inference Routing

```console
$ openshell inference set --provider ollama --model qwen3.5:0.8b
```

Confirm:

```console
$ openshell inference get
```

### Step 5: Verify from a Sandbox

```console
$ openshell sandbox create -- \
    curl https://inference.local/v1/chat/completions \
    --json '{"messages":[{"role":"user","content":"hello"}],"max_tokens":10}'
```

The response should be JSON from the model.

## Troubleshooting

Common issues and fixes:

- **Ollama not reachable from sandbox** — Ollama must be bound to `0.0.0.0`, not `127.0.0.1`. This applies to host-level Ollama only; the community sandbox handles this automatically.
- **`OPENAI_BASE_URL` wrong** — Use `http://host.openshell.internal:11434/v1`, not `localhost` or `127.0.0.1`.
- **Model not found** — Run `ollama ps` to confirm the model is loaded. Run `ollama pull <model>` if needed.
- **HTTPS vs HTTP** — Code inside sandboxes must call `https://inference.local`, not `http://`.
- **AMD GPU driver issues** — Ollama v0.18+ requires ROCm 7 drivers for AMD GPUs. Update your drivers if you see GPU detection failures.

Useful commands:

```console
$ openshell status
$ openshell inference get
$ openshell provider get ollama
```

## Next Steps

- To learn more about managed inference, refer to {doc}`/inference/index`.
- To configure a different self-hosted backend, refer to {doc}`/inference/configure`.
- To explore more community sandboxes, refer to {doc}`/sandboxes/community-sandboxes`.
