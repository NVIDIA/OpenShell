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

This page covers the managed local inference endpoint (`https://inference.local`). External inference endpoints go through sandbox `network_policies`. Refer to [Policies](/sandboxes/policies.md) for details.

The configuration consists of two values:

| Value | Description |
|---|---|
| Provider record | The credential backend OpenShell uses to authenticate with the upstream model host. |
| Model ID | The model to use for generation requests. |

For a list of tested providers and their base URLs, refer to [Supported Inference Providers](../sandboxes/manage-providers.md#supported-inference-providers).

## Create a Provider

Create a provider that holds the backend credentials you want OpenShell to use.

:::::{tab-set}

::::{tab-item} NVIDIA API Catalog

```console
$ openshell provider create --name nvidia-prod --type nvidia --from-existing
```

This reads `NVIDIA_API_KEY` from your environment.

::::

::::{tab-item} OpenAI-compatible Provider

Any cloud provider that exposes an OpenAI-compatible API works with the `openai` provider type. You need three values from the provider: the base URL, an API key, and a model name.

```console
$ openshell provider create \
    --name my-cloud-provider \
    --type openai \
    --credential OPENAI_API_KEY=<your_api_key> \
    --config OPENAI_BASE_URL=https://api.example.com/v1
```

Replace the base URL and API key with the values from your provider. For supported providers out of the box, refer to [Supported Inference Providers](../sandboxes/manage-providers.md#supported-inference-providers). For other providers, refer to your provider's documentation for the correct base URL, available models, and API key setup.

::::

::::{tab-item} Local Endpoint

```console
$ openshell provider create \
    --name my-local-model \
    --type openai \
    --credential OPENAI_API_KEY=empty-if-not-required \
    --config OPENAI_BASE_URL=http://host.openshell.internal:11434/v1
```

Use `--config OPENAI_BASE_URL` to point to any OpenAI-compatible server running where the gateway runs. For host-backed local inference, use `host.openshell.internal` or the host's LAN IP. Avoid `127.0.0.1` and `localhost`. Set `OPENAI_API_KEY` to a dummy value if the server does not require authentication.

::::

::::{tab-item} Anthropic

```console
$ openshell provider create --name anthropic-prod --type anthropic --from-existing
```

This reads `ANTHROPIC_API_KEY` from your environment.

::::

:::::

## Set Inference Routing

Point `inference.local` at that provider and choose the model to use:

```console
$ openshell inference set \
    --provider nvidia-prod \
    --model nvidia/nemotron-3-nano-30b-a3b
```

## Verify the Active Config

Confirm that the provider and model are set correctly:

```console
$ openshell inference get
Gateway inference:

  Provider: nvidia-prod
  Model: nvidia/nemotron-3-nano-30b-a3b
  Version: 1
```

## Update Part of the Config

Use `update` when you want to change only one field:

```console
$ openshell inference update --model nvidia/nemotron-3-nano-30b-a3b
```

Or switch providers without repeating the current model:

```console
$ openshell inference update --provider openai-prod
```

## Use the Local Endpoint from a Sandbox

After inference is configured, code inside any sandbox can call `https://inference.local` directly:

```python
from openai import OpenAI

client = OpenAI(base_url="https://inference.local/v1", api_key="unused")

response = client.chat.completions.create(
    model="anything",
    messages=[{"role": "user", "content": "Hello"}],
)
```

The client-supplied `model` and `api_key` values are not sent upstream. The privacy router injects the real credentials from the configured provider and rewrites the model before forwarding.

Some SDKs require a non-empty API key even though `inference.local` does not use the sandbox-provided value. In those cases, pass any placeholder such as `test` or `unused`.

Use this endpoint when inference should stay local to the host for privacy and security reasons. External providers that should be reached directly belong in `network_policies` instead.

When the upstream runs on the same machine as the gateway, bind it to `0.0.0.0` and point the provider at `host.openshell.internal` or the host's LAN IP. `127.0.0.1` and `localhost` usually fail because the request originates from the gateway or sandbox runtime, not from your shell.

If the gateway runs on a remote host or behind a cloud deployment, `host.openshell.internal` points to that remote machine, not to your laptop. A locally running Ollama or vLLM process is not reachable from a remote gateway unless you add your own tunnel or shared network path. Ollama also supports cloud-hosted models that do not require local hardware.

### Verify the Endpoint from a Sandbox

`openshell inference set` and `openshell inference update` verify the resolved upstream endpoint by default before saving the configuration. If the endpoint is not live yet, retry with `--no-verify` to persist the route without the probe.

`openshell inference get` confirms the current saved configuration. To confirm end-to-end connectivity from a sandbox, run:

```bash
curl https://inference.local/v1/responses \
    -H "Content-Type: application/json" \
    -d '{
      "instructions": "You are a helpful assistant.",
      "input": "Hello!"
    }'
```

A successful response confirms the privacy router can reach the configured backend and the model is serving requests.

- Gateway-scoped: Every sandbox using the active gateway sees the same `inference.local` backend.
- HTTPS only: `inference.local` is intercepted only for HTTPS traffic.
- Hot reload: Provider and inference changes are picked up within about 5 seconds by default.

## Next Steps

Explore related topics:

- To understand the inference routing flow and supported API patterns, refer to {doc}`index`.
- To follow a complete Ollama-based local setup, refer to {doc}`/tutorials/local-inference-ollama`.
- To follow a complete LM Studio-based local setup, refer to {doc}`/tutorials/local-inference-lmstudio`.
- To control external endpoints, refer to [Policies](/sandboxes/policies.md).
- To manage provider records, refer to {doc}`../sandboxes/manage-providers`.
