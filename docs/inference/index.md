---
title:
  page: About Inference Routing
  nav: Inference Routing
description: Understand how OpenShell routes inference traffic through external endpoints and the local privacy router.
topics:
- Generative AI
- Cybersecurity
tags:
- Inference Routing
- Privacy
- AI Agents
- LLM
content:
  type: concept
  difficulty: technical_beginner
  audience:
  - engineer
  - data_scientist
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# About Inference Routing

NVIDIA OpenShell handles inference traffic through two endpoints: `inference.local` and external endpoints.
The following table summarizes how OpenShell handles inference traffic.

| Path | How It Works |
|---|---|
| External endpoints | Traffic to hosts like `api.openai.com` or `api.anthropic.com` is treated like any other outbound request, allowed or denied by `network_policies`. Refer to {doc}`../sandboxes/policies`. |
| `inference.local` | A special endpoint exposed inside every sandbox for routing inference traffic locally, preserving privacy and security. The {doc}`privacy router </about/architecture>` strips the original credentials, injects the configured backend credentials, and forwards to the managed model endpoint. |

## How `inference.local` Works

When code inside a sandbox calls `https://inference.local`, the privacy router routes the request to the configured backend for that gateway. The configured model is applied to generation requests, and provider credentials are supplied by OpenShell rather than by code inside the sandbox.

If code calls an external inference host directly, that traffic is evaluated only by `network_policies`.

| Property | Detail |
|---|---|
| Credentials | No sandbox API keys needed. Credentials come from the configured provider record. |
| Configuration | One provider and one model define sandbox inference for the active gateway. Every sandbox on that gateway sees the same `inference.local` backend. |
| Provider support | NVIDIA, any OpenAI-compatible provider, and Anthropic all work through the same endpoint. |
| Hot-refresh | OpenShell picks up provider credential changes and inference updates without recreating sandboxes. Changes propagate within about 5 seconds by default. |

## Supported API Patterns

Supported request patterns depend on the provider configured for `inference.local`.

:::::{tab-set}

::::{tab-item} OpenAI-compatible

| Pattern | Method | Path |
|---|---|---|
| Chat Completions | `POST` | `/v1/chat/completions` |
| Completions | `POST` | `/v1/completions` |
| Responses | `POST` | `/v1/responses` |
| Model Discovery | `GET` | `/v1/models` |
| Model Discovery | `GET` | `/v1/models/*` |

::::

::::{tab-item} Anthropic-compatible

| Pattern | Method | Path |
|---|---|---|
| Messages | `POST` | `/v1/messages` |

::::

:::::

Requests to `inference.local` that do not match the configured provider's supported patterns are denied.

## Next Steps

Continue with one of the following:

- To set up the backend behind `inference.local`, refer to {doc}`configure`.
- To control external endpoints, refer to [Policies](/sandboxes/policies.md).
