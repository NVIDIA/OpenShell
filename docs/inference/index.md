<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# About Inference Routing

OpenShell handles inference in two ways:

- External inference endpoints are controlled by sandbox `network_policies`.
- Each sandbox also exposes `https://inference.local`, a special endpoint for
  inference that should stay local to the host for privacy and security.

## External Inference

If sandbox code calls an external inference API like `api.openai.com` or
`api.anthropic.com`, that traffic is treated like any other outbound network
request. It is allowed or denied by `network_policies`.

Refer to {doc}`/safety-and-privacy/policies` and the
[Network policy evaluation](/safety-and-privacy/policies.md#network-policy-evaluation)
section for details.

## `inference.local`

Every sandbox also exposes a special endpoint: `https://inference.local`.

This endpoint exists so inference can be routed to a model running locally on
the same host. In the future, it can also route to a model managed by the
cluster. It is the special case for inference that should stay local for
privacy and security reasons.

## Using `inference.local`

When code inside a sandbox calls `https://inference.local`, OpenShell routes the
request to the configured backend for that gateway.

The configured model is applied to generation requests, and provider
credentials are supplied by OpenShell rather than by code inside the sandbox.

If code calls an external inference host directly, that traffic is evaluated
only by `network_policies`.

## Supported API Patterns

Supported request patterns depend on the provider configured for
`inference.local`.

For OpenAI-compatible providers, these patterns are supported:

| Pattern | Method | Path |
|---|---|---|
| OpenAI Chat Completions | `POST` | `/v1/chat/completions` |
| OpenAI Completions | `POST` | `/v1/completions` |
| OpenAI Responses | `POST` | `/v1/responses` |
| Model Discovery | `GET` | `/v1/models` |
| Model Discovery | `GET` | `/v1/models/*` |

For Anthropic-compatible providers, this pattern is supported:

| Pattern | Method | Path |
|---|---|---|
| Anthropic Messages | `POST` | `/v1/messages` |

Requests to `inference.local` that do not match the configured provider's
supported patterns are denied.

## Key Properties

- External endpoints use `network_policies`.
- Explicit local endpoint: special local routing happens through
  `inference.local`.
- No sandbox API keys: credentials come from the configured provider record.
- Single managed config: one provider and one model define sandbox inference.
- Provider-agnostic: OpenAI, Anthropic, and NVIDIA providers all work through
  the same endpoint.
- Hot-refresh: provider credential changes and inference updates are picked up
  without recreating sandboxes.

## Next Steps

- {doc}`configure`: configure the backend behind `inference.local`.
- [Network policy evaluation](/safety-and-privacy/policies.md#network-policy-evaluation):
  understand how external endpoints are controlled.
