<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Configure Inference Routing

This page covers the managed local inference endpoint (`https://inference.local`). External inference endpoints go through sandbox `network_policies` — see [Network Access Rules](/sandboxes/index.md#network-access-rules) for details.

The configuration consists of two values:

| Value | Description |
|---|---|
| Provider record | The credential backend OpenShell uses to authenticate with the upstream model host. |
| Model ID | The model to use for generation requests. |

## Step 1: Create a Provider

Create a provider that holds the backend credentials you want OpenShell to use.

```console
$ nemoclaw provider create --name nvidia-prod --type nvidia --from-existing
```

You can also use `openai` or `anthropic` provider types.

## Step 2: Set Inference Routing

Point `inference.local` at that provider and choose the model to use:

```console
$ nemoclaw inference set \
    --provider nvidia-prod \
    --model nvidia/nemotron-3-nano-30b-a3b
```

## Step 3: Verify the Active Config

```console
$ nemoclaw inference get
provider: nvidia-prod
model:    nvidia/nemotron-3-nano-30b-a3b
version:  1
```

## Step 4: Update Part of the Config

Use `update` when you want to change only one field:

```console
$ nemoclaw inference update --model nvidia/nemotron-3-nano-30b-a3b
```

Or switch providers without repeating the current model:

```console
$ nemoclaw inference update --provider openai-prod
```

## Use It from a Sandbox

Once inference is configured, code inside any sandbox can call `https://inference.local` directly:

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

:::{note}
- **Gateway-scoped** — every sandbox on the active gateway sees the same `inference.local` backend.
- **HTTPS only** — `inference.local` is intercepted only for HTTPS traffic.
:::

## Next Steps

- **How does inference routing work?** See {doc}`index` for the interception flow and supported API patterns.
- **Need to control external endpoints?** See [Network Access Rules](/sandboxes/index.md#network-access-rules).
- **Managing provider records?** See {doc}`../sandboxes/providers`.
- **CLI reference?** See {doc}`../reference/cli` for `nemoclaw inference` commands.
