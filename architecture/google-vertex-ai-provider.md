# Google Vertex AI Provider

The `google-vertex-ai` provider gives selected sandboxes direct access to
Google Vertex AI endpoints without exposing long-lived Google credentials.
The provider profile owns endpoint policy and credential metadata; the
sandbox attachment owns which workload receives access.

## Boundaries

| Component | Responsibility |
|---|---|
| CLI | Discovers ADC or accepts service-account bootstrap material and creates the provider record. |
| Gateway | Stores refresh material through the credential driver and rotates short-lived access tokens. |
| Provider profile | Declares Vertex hosts, credential aliases, refresh constraints, and permitted binaries. |
| Sandbox supervisor | Delivers opaque credential placeholders and resolves them only for profile-authorized Vertex requests. |
| Workload | Selects the native Vertex endpoint, model, request format, streaming mode, and timeout. |

The provider does not select a model or transform requests. Anthropic Claude
uses Vertex's publisher-model `rawPredict` or `streamRawPredict` paths. Gemini
and other models use their documented native or OpenAI-compatible Vertex API.

## Credential Flows

Vertex accepts short-lived Google OAuth2 access tokens. Both supported setup
flows converge on a rotating access token stored in the provider record.

### Service account

The operator creates the provider with service-account bootstrap material and
configures `google-service-account-jwt` refresh. The private key remains in the
gateway credential store. The gateway mints
`GOOGLE_VERTEX_AI_SERVICE_ACCOUNT_TOKEN` and refreshes it before expiry.

### gcloud ADC

For local development, `--from-gcloud-adc` reads an authorized-user ADC file,
stores the refresh grant at the gateway, and mints
`GOOGLE_VERTEX_AI_TOKEN`. The ADC file and refresh token do not enter the
sandbox.

## Runtime Data Flow

1. The operator attaches the provider to a sandbox.
2. The effective policy includes the profile's Vertex endpoint and binary
   rules.
3. A newly launched workload receives the current token as an opaque
   placeholder plus non-secret project and region configuration.
4. The workload calls the native Vertex endpoint with that placeholder in the
   `Authorization: Bearer` header.
5. After policy and endpoint binding pass, the proxy substitutes the current
   real access token and forwards the request.
6. Token refresh updates the resolver; the workload continues using the same
   placeholder.

The raw `GOOGLE_SERVICE_ACCOUNT_KEY` credential is bootstrap-only and is never
part of sandbox runtime material.

## Endpoint Boundary

The built-in profile permits official Vertex hosts:

- `<region>-aiplatform.googleapis.com`
- `aiplatform.googleapis.com`
- `aiplatform.us.rep.googleapis.com`
- `aiplatform.eu.rep.googleapis.com`

The workload constructs the documented project, location, publisher, and model
path. The proxy does not infer the publisher or rewrite the body.

For Claude on Vertex, a request uses this form:

```text
https://<location>-aiplatform.googleapis.com/v1/projects/<project>/locations/<location>/publishers/anthropic/models/<model>:rawPredict
```

The request body includes the Vertex Anthropic API version expected by Google.
Streaming uses the corresponding native streaming endpoint.

## Invariants

- Refresh bootstrap material remains gateway-only.
- Sandboxes receive placeholders, never real access tokens.
- A token resolves only at endpoints covered by the attached provider profile.
- Detach and expiry revoke placeholder resolution.
- Project IDs, regions, publishers, and model IDs are non-secret workload
  configuration.
- Provider attachment does not grant access when a gateway global policy
  override suppresses provider-derived policy.
- Provider environment keys and dynamic credential bindings remain
  unambiguous across all providers attached to one sandbox.

## Operational Notes

Attach or detach the provider with the normal sandbox provider lifecycle. A
running sandbox observes policy and resolver changes, but a process must be
launched after attachment to receive new environment variables. Direct native
requests provide the end-to-end verification path; provider creation does not
probe a model endpoint or validate a model ID.
