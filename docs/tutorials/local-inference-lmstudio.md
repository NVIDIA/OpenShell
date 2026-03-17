---
title:
  page: Route Local Inference Requests to LM Studio
  nav: Local Inference with LM Studio
description: Configure inference.local to route sandbox requests to a local LM Studio server running on the gateway host.
topics:
- Generative AI
- Cybersecurity
tags:
- Tutorial
- Inference Routing
- LM Studio
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

# Route Local Inference Requests to LM Studio

This tutorial describes how to configure OpenShell to route inference requests to a local LM Studio server.

:::{note}
The LM Studio server provides easy setup with both OpenAI and Anthropic compatible endpoints.
:::

This tutorial will cover:

- Expose a local inference server to OpenShell sandboxes.
- Verify end-to-end inference from inside a sandbox.

## Prerequisites

First, complete OpenShell installation and follow the {doc}`/get-started/quickstart`.

[Install the LM Studio app](https://lmstudio.ai/download). Make sure that your LM Studio is running in the same environment as your gateway.

If you prefer to work without having to keep the LM Studio app open, download llmster (headless LM Studio) with the following command:

### Linux/Mac
```bash
curl -fsSL https://lmstudio.ai/install.sh | bash
```

### Windows
```bash
irm https://lmstudio.ai/install.ps1 | iex
```

And start llmster:
```bash
lms daemon up
```

## Step 1: Start LM Studio Local Server

Start the LM Studio local server from the Developer tab, and verify the OpenAI-compatible endpoint is enabled.

LM Studio will listen to `127.0.0.1:1234` by default. For use with OpenShell, you'll need to configure LM Studio to listen on all interfaces (`0.0.0.0`).

If you're using the GUI, go to the Developer Tab, select Server Settings, then enable Serve on Local Network.

If you're using llmster in headless mode, run `lms server start --bind 0.0.0.0`.

## Step 2: Test with a small model

In the LM Studio app, head to the Model Search tab to download a small model like Qwen3.5 2B.

In the terminal, use the following command to download and load the model:
```bash
lms get qwen/qwen3.5-2b
lms load qwen/qwen3.5-2b
```


## Step 3: Add LM Studio as a provider

Choose the provider type that matches the client protocol you want to route through `inference.local`.

:::::{tab-set}

::::{tab-item} OpenAI-compatible

Add LM Studio as an OpenAI-compatible provider through `host.openshell.internal`:

```console
$ openshell provider create \
    --name lmstudio \
    --type openai \
    --credential OPENAI_API_KEY=lmstudio \
    --config OPENAI_BASE_URL=http://host.openshell.internal:1234/v1
```

Use this provider for clients that send OpenAI-compatible requests such as `POST /v1/chat/completions` or `POST /v1/responses`.

::::

::::{tab-item} Anthropic-compatible

Add a provider that points to LM Studio's Anthropic-compatible `POST /v1/messages` endpoint:

```console
$ openshell provider create \
    --name lmstudio-anthropic \
    --type anthropic \
    --credential ANTHROPIC_API_KEY=lmstudio \
    --config ANTHROPIC_BASE_URL=http://host.openshell.internal:1234
```

Use this provider for Anthropic-compatible `POST /v1/messages` requests.

::::

:::::


## Step 4: Configure LM Studio as the local inference provider

Set the managed inference route for the active gateway:

:::::{tab-set}

::::{tab-item} OpenAI-compatible

```console
$ openshell inference set --provider lmstudio --model qwen/qwen3.5-2b
```

If the command succeeds, OpenShell has verified that the upstream is reachable and accepts the expected OpenAI-compatible request shape.

::::

::::{tab-item} Anthropic-compatible

```console
$ openshell inference set --provider lmstudio-anthropic --model qwen/qwen3.5-2b
```

If the command succeeds, OpenShell has verified that the upstream is reachable and accepts the expected Anthropic-compatible request shape.

::::

:::::

The active `inference.local` route is gateway-scoped, so only one provider and model pair is active at a time. Re-run `openshell inference set` whenever you want to switch between OpenAI-compatible and Anthropic-compatible clients.

Confirm the saved config:

```console
$ openshell inference get
```

You should see either `Provider: lmstudio` or `Provider: lmstudio-anthropic`, along with `Model: qwen/qwen3.5-2b`.

## Step 5: Verify from Inside a Sandbox

Run a simple request through `https://inference.local`:

:::::{tab-set}

::::{tab-item} OpenAI-compatible

```console
$ openshell sandbox create -- \
    curl https://inference.local/v1/chat/completions \
    --json '{"messages":[{"role":"user","content":"hello"}],"max_tokens":10}'

$ openshell sandbox create -- \
    curl https://inference.local/v1/responses \
    -H "Content-Type: application/json" \
    -d '{
      "instructions": "You are a helpful assistant.",
      "input": "hello",
      "max_output_tokens": 10
    }'    
```

::::

::::{tab-item} Anthropic-compatible

```console
$ openshell sandbox create -- \
    curl https://inference.local/v1/messages \
    -H "Content-Type: application/json" \
    -d '{"messages":[{"role":"user","content":"hello"}],"max_tokens":10}'
```

::::

:::::

## Troubleshooting

If setup fails, check these first:

- LM Studio local server is running and reachable from the gateway host
- `OPENAI_BASE_URL` uses `http://host.openshell.internal:1234/v1` when you use an `openai` provider
- `ANTHROPIC_BASE_URL` uses `http://host.openshell.internal:1234` when you use an `anthropic` provider
- The gateway and LM Studio run on the same machine or a reachable network path
- The configured model name matches the model exposed by LM Studio

Useful commands:

```console
$ openshell status
$ openshell inference get
$ openshell provider get lmstudio
$ openshell provider get lmstudio-anthropic
```

## Next Steps

- To learn more about using the LM Studio CLI, refer to [LM Studio docs](https://lmstudio.ai/docs/cli)
- To learn more about managed inference, refer to {doc}`/inference/index`.
- To configure a different self-hosted backend, refer to {doc}`/inference/configure`.
