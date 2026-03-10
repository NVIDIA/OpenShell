<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# About Inference Routing

OpenShell handles inference in two ways:

| Path | How It Works |
|---|---|
| **External endpoints** | Traffic to hosts like `api.openai.com` or `api.anthropic.com` is treated like any other outbound request — allowed or denied by `network_policies`. See [Network Access Rules](/sandboxes/index.md#network-access-rules). |
| **`inference.local`** | A special endpoint exposed inside every sandbox for inference that should stay local to the host for privacy and security. The {doc}`privacy router </about/architecture>` strips the original credentials, injects the configured backend credentials, and forwards to the managed model endpoint. |

## How `inference.local` Works

When code inside a sandbox calls `https://inference.local`, the privacy router routes the request to the configured backend for that gateway. The configured model is applied to generation requests, and provider credentials are supplied by OpenShell rather than by code inside the sandbox.

If code calls an external inference host directly, that traffic is evaluated only by `network_policies`.

| Property | Detail |
|---|---|
| Credentials | No sandbox API keys needed — credentials come from the configured provider record. |
| Configuration | One provider and one model define sandbox inference. |
| Provider support | OpenAI, Anthropic, and NVIDIA providers all work through the same endpoint. |
| Hot-refresh | Provider credential changes and inference updates are picked up without recreating sandboxes. |

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

- **Ready to configure?** Set up the backend behind `inference.local` in {doc}`configure`.
- **Need to control external endpoints?** See [Network Access Rules](/sandboxes/index.md#network-access-rules).
