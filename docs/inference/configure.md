<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Configure Inference Routing

OpenShell exposes one managed inference backend behind `https://inference.local`
for the active gateway.

External inference endpoints still go through sandbox `network_policies`. This
page covers the special local inference endpoint only.

That configuration consists of two values:

- a provider record name
- a model ID

## Step 1: Create a Provider

Create a provider that holds the backend credentials you want OpenShell to use.

```console
$ openshell provider create --name nvidia-prod --type nvidia --from-existing
```

You can also use `openai` or `anthropic` providers.

## Step 2: Set Inference Routing

Point `inference.local` at that provider and choose the model to use:

```console
$ openshell inference set \
    --provider nvidia-prod \
    --model nvidia/nemotron-3-nano-30b-a3b
```

This sets the managed inference configuration.

## Step 3: Verify the Active Config

```console
$ openshell inference get
provider: nvidia-prod
model:    nvidia/nemotron-3-nano-30b-a3b
version:  1
```

## Step 4: Update Part of the Config

Use `update` when you want to change only one field:

```console
$ openshell inference update --model nvidia/nemotron-3-nano-30b-a3b
```

Or switch providers without repeating the current model manually:

```console
$ openshell inference update --provider openai-prod
```

## Use It from a Sandbox

Once inference is configured, userland code inside any sandbox can call
`https://inference.local` directly:

```python
from openai import OpenAI

client = OpenAI(base_url="https://inference.local/v1", api_key="dummy")

response = client.chat.completions.create(
    model="anything",
    messages=[{"role": "user", "content": "Hello"}],
)
```

The client-supplied model is ignored for generation requests. OpenShell
rewrites it to the configured model before forwarding upstream.

Use this endpoint when inference should stay local to the host for privacy and
security reasons. External providers that should be reached directly belong in
`network_policies` instead.

## Good to Know

- Gateway-scoped: every sandbox on the active gateway sees the same
  `inference.local` backend.
- HTTPS only: `inference.local` is intercepted only for HTTPS traffic.

## Next Steps

- {doc}`index`: understand the interception flow and supported API patterns.
- [Network policy evaluation](/safety-and-privacy/policies.md#network-policy-evaluation):
  configure direct access to external inference endpoints.
- {doc}`../sandboxes/providers`: create and manage provider records.
- {doc}`../reference/cli`: see the CLI reference for `openshell inference`
  commands.
