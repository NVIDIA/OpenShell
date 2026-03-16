---
title:
  page: Run Local Inference with Ollama
  nav: Local Inference with Ollama
description: Configure inference.local to route sandbox requests to a local Ollama server running on the gateway host.
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

This tutorial shows how to route sandbox inference to a model running locally.

:::{note}
This tutorial uses Ollama because it is easy to install and run locally, but you can substitute other inference engines such as vLLM, SGLang, TRT-LLM, and NVIDIA NIM by changing the startup command, base URL, and model name.
:::

After completing this tutorial, you will know how to:

- Expose a local inference server to OpenShell sandboxes.
- Verify end-to-end inference from inside a sandbox.

## Prerequisites

- A working OpenShell installation. Complete the {doc}`/get-started/quickstart` before proceeding.

If your gateway runs on a remote host or in a cloud deployment, Ollama must also run there. Another common scenario is running a model and the gateway on different nodes in the same local network.

Install [Ollama](https://ollama.com/) with:

```console  
$ curl -fsSL https://ollama.com/install.sh | sh
```

## Step 1: Start Ollama on All Interfaces

By default, Ollama listens only on the loopback address (`127.0.0.1`), which is not reachable from the OpenShell gateway or sandboxes. Start Ollama so it listens on all interfaces:

```console
$ OLLAMA_HOST=0.0.0.0:11434 ollama serve
```

:::{tip}
If you see `Error: listen tcp 0.0.0.0:11434: bind: address already in use`, Ollama is already running as a system service. Stop it first, then start it manually with the correct bind address:

```console
$ systemctl stop ollama
$ OLLAMA_HOST=0.0.0.0:11434 ollama serve
```
:::

## Step 2: Pull a Model

In a second terminal, pull a lightweight model:

```console
$ ollama run qwen3.5:0.8b
```

This downloads the model and starts an interactive session. Type `/bye` to exit the session. The model stays available for inference after you exit.

:::{note}
`qwen3.5:0.8b` is a good smoke-test target for verifying your local inference setup, but it is best suited for simple tasks. For more complex coding, reasoning, or agent workflows, use a stronger open model such as Nemotron or another larger open-source model that fits your hardware.
:::

Confirm the model is available:

```console
$ ollama ps
```

You should see `qwen3.5:0.8b` in the output.

## Step 3: Create a Provider for Ollama

Create an OpenAI-compatible provider that points at Ollama through `host.openshell.internal`:

```console
$ openshell provider create \
    --name ollama \
    --type openai \
    --credential OPENAI_API_KEY=empty \
    --config OPENAI_BASE_URL=http://host.openshell.internal:11434/v1
```

This works because OpenShell injects `host.openshell.internal` so sandboxes and the gateway can refer back to the gateway host machine. If that hostname is not the best fit for your environment, you can also use the host's LAN IP.

## Step 4: Configure Local Inference with Ollama

Set the managed inference route for the active gateway:

```console
$ openshell inference set --provider ollama --model qwen3.5:0.8b
```

If the command succeeds, OpenShell has verified that the upstream is reachable and accepts the expected OpenAI-compatible request shape.

Confirm the saved config:

```console
$ openshell inference get
```

You should see `Provider: ollama` and `Model: qwen3.5:0.8b`.

## Step 5: Verify from Inside a Sandbox

Run a simple request through `https://inference.local`:

```console
$ openshell sandbox create -- \
    curl https://inference.local/v1/chat/completions \
    --json '{"messages":[{"role":"user","content":"hello"}],"max_tokens":10}'
```

The response should be JSON from the upstream model. The `model` reported in the response may show the real model resolved by OpenShell.

## Troubleshooting

If setup fails, check these first:

- Ollama is bound to `0.0.0.0`, not only `127.0.0.1`
- `OPENAI_BASE_URL` uses `http://host.openshell.internal:11434/v1`
- The gateway and Ollama run on the same machine
- The configured model exists in Ollama
- The app calls `https://inference.local`, not `http://inference.local`

Useful commands:

```console
$ openshell status
$ openshell inference get
$ openshell provider get ollama
```

## Next Steps

- To learn more about managed inference, refer to {doc}`/inference/index`.
- To configure a different self-hosted backend, refer to {doc}`/inference/configure`.
