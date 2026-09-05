<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Google Vertex AI Provider

The `google-vertex-ai` provider gives sandboxes native access to Vertex AI
endpoints with gateway-managed short-lived credentials. Managed inference routes
and protocol translation are outside this design.

## Boundaries

The provider spans three existing boundaries:

1. The CLI discovers local ADC credentials or accepts service-account bootstrap
   material and stores provider configuration.
2. The gateway refresh subsystem mints short-lived Google Cloud access tokens.
3. The sandbox policy proxy resolves a token placeholder only for endpoints
   contributed by the attached provider profile.

The service-account JSON and private key remain gateway-side refresh material.
They are never included in the sandbox provider environment.

## Provider Profile

The built-in profile declares:

- regional `*-aiplatform.googleapis.com` endpoints;
- global `aiplatform.googleapis.com`;
- US and EU multi-region endpoints;
- bearer placement for the service-account and ADC access-token credentials;
- Google OAuth token refresh metadata.

The profile's `inference_capable` field is descriptive metadata. It does not
create a local route or select a model.

## Configuration Projection

The provider plugin projects `VERTEX_AI_PROJECT_ID` and
`VERTEX_AI_REGION` to the environment aliases used by supported Google Cloud
and Vertex clients. Base URL and publisher values are ordinary provider
configuration. They do not alter profile endpoint policy or cause OpenShell to
rewrite a request.

Clients construct the native Vertex URL, publisher/model path, request body, and
timeout. A private or nonstandard endpoint requires a custom provider profile
that declares that endpoint and its permitted binaries.

## Credential Refresh

Service-account providers use the `google_service_account_jwt` refresh strategy.
ADC-backed providers use the `oauth2_refresh_token` strategy. Both write the
current access token into the provider record and advance the provider revision
atomically.

The sandbox receives a revision-scoped placeholder, not the access-token value.
The proxy validates the destination against the credential binding before
replacing the placeholder in the outbound Authorization header. Rotation
updates the proxy credential snapshot without exposing the new token to the
agent process.

## Runtime Data Flow

```text
CLI provider create / refresh configure
                |
                v
Gateway provider record + refresh state
                |
                v
Attached provider profile and credential snapshot
                |
                v
Sandbox policy proxy -- native Vertex HTTPS request --> Vertex AI
```

This uses the same provider, policy, and credential path as other external
services. There is no `Inference` gRPC service, `InferenceRoute` persisted
object, supervisor route bundle, or `inference.local` interception path.

## Security Invariants

- Refresh bootstrap secrets remain gateway-side.
- Access-token placeholders resolve only for profile-authorized Vertex hosts.
- The calling binary must match provider profile or merged sandbox policy.
- SSRF and L7 enforcement apply to native Vertex traffic.
- Custom hosts require an explicit custom profile; a base URL string alone
  cannot widen egress or credential bindings.
