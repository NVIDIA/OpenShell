---
title:
  page: Configure Inference Routing
  nav: Configure
description: Set up the managed local inference endpoint with provider credentials and model configuration.
topics:
- Generative AI
- Cybersecurity
tags:
- Inference Routing
- Configuration
- Privacy
- LLM
- Provider
content:
  type: how_to
  difficulty: technical_intermediate
  audience:
  - engineer
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Configure Inference Routing

This page covers the managed local inference endpoint (`https://inference.local`). External inference endpoints go through sandbox `network_policies` — refer to [Network Access Rules](/sandboxes/index.md#network-access-rules) for details.

The configuration consists of two values:

| Value | Description |
|---|---|
| Provider record | The credential backend OpenShell uses to authenticate with the upstream model host. |
| Model ID | The model to use for generation requests. |

## Step 1: Create a Provider

Create a provider that holds the backend credentials you want OpenShell to use.

:::::{tab-set}

::::{tab-item} NVIDIA API Catalog

```console
$ openshell provider create --name nvidia-prod --type nvidia --from-existing
```

This reads `NVIDIA_API_KEY` from your environment.

::::

::::{tab-item} Local / self-hosted endpoint

```console
$ openshell provider create \
    --name my-local-model \
    --type openai \
    --credential OPENAI_API_KEY=empty-if-not-required \
    --config OPENAI_BASE_URL=http://192.168.10.15/v1
```

Use `--config OPENAI_BASE_URL` to point to any OpenAI-compatible server running on your network. Set `OPENAI_API_KEY` to a dummy value if the server does not require authentication.

::::

::::{tab-item} Anthropic

```console
$ openshell provider create --name anthropic-prod --type anthropic --from-existing
```

This reads `ANTHROPIC_API_KEY` from your environment.

::::

:::::

## Step 2: Set Inference Routing

Point `inference.local` at that provider and choose the model to use:

```console
$ openshell inference set \
    --provider nvidia-prod \
    --model nvidia/nemotron-3-nano-30b-a3b
```

## Step 3: Verify the Active Config

Confirm that the provider and model are set correctly:

```console
$ openshell inference get
Gateway inference:

  Provider: nvidia-prod
  Model: nvidia/nemotron-3-nano-30b-a3b
  Version: 1
```

## Step 4: Update Part of the Config

Use `update` when you want to change only one field:

```console
$ openshell inference update --model nvidia/nemotron-3-nano-30b-a3b
```

Or switch providers without repeating the current model:

```console
$ openshell inference update --provider openai-prod
```

## Use It from a Sandbox

After inference is configured, code inside any sandbox can call `https://inference.local` directly:

```python
from openai import OpenAI

client = OpenAI(base_url="https://inference.local/v1", api_key="dummy")

response = client.chat.completions.create(
    model="anything",
    messages=[{"role": "user", "content": "Hello"}],
)
```

The client-supplied model is ignored for generation requests. OpenShell rewrites it to the configured model before forwarding upstream.

Use this endpoint when inference should stay local to the host for privacy and security reasons. External providers that should be reached directly belong in `network_policies` instead.

### Verify the Endpoint from a Sandbox

`openshell inference get` confirms the configuration was saved, but does not verify the upstream endpoint is reachable. To confirm end-to-end connectivity, connect to a sandbox and run:

```bash
curl https://inference.local/v1/responses \
    -H "Content-Type: application/json" \
    -d '{
      "instructions": "You are a helpful assistant.",
      "input": "Hello!"
    }'
```

A successful response confirms the privacy router can reach the configured backend and the model is serving requests.

:::{note}
- **Gateway-scoped**: every sandbox using the active gateway sees the same `inference.local` backend.
- **HTTPS only** — `inference.local` is intercepted only for HTTPS traffic.
:::

## Next Steps

Explore related topics:

- To understand the inference routing flow and supported API patterns, refer to {doc}`index`.
- To control external endpoints, refer to [Network Access Rules](/sandboxes/index.md#network-access-rules).
- To manage provider records, refer to {doc}`../sandboxes/providers`.
