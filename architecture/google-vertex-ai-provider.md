# Google Vertex AI Provider — Implementation Reference

This document covers the full implementation of the `google-vertex-ai` provider in
OpenShell. It is the canonical reference for maintainers working on anything in the
Vertex AI request path, from CLI through gateway to sandbox.

---

## 1. Overview

OpenShell's `google-vertex-ai` provider routes `inference.local` traffic through
Google Cloud's Vertex AI platform. It differs from a direct Anthropic or OpenAI
integration in two ways that touch nearly every layer of the stack:

1. **Authentication is OAuth2 bearer, not a static API key.** Vertex AI accepts
   short-lived GCP access tokens (`ya29.*`) as `Authorization: Bearer` headers. The
   gateway mints and rotates these tokens from one of two refresh sources: a GCP
   service account key (JWT-bearer grant) or gcloud Application Default Credentials
   (OAuth2 refresh-token grant).

2. **The URL and wire format depend on the model family.** Anthropic Claude models
   use Vertex AI's native rawPredict surface (`/publishers/anthropic/models/{model}:rawPredict`)
   with the Anthropic Messages API body shape. Gemini and all other models use Vertex
   AI's OpenAI-compatible Chat Completions surface
   (`/v1beta1/.../endpoints/openapi/chat/completions`). The gateway selects the right
   route at `openshell inference set` time based on the model name (or the explicit
   `VERTEX_AI_PUBLISHER` config key).

### Canonical provider type

The canonical provider type string is `google-vertex-ai`. The following aliases are
accepted everywhere and normalized to the canonical string:

| Input | Resolves to |
|---|---|
| `google-vertex-ai` | `google-vertex-ai` |
| `vertex` | `google-vertex-ai` |
| `vertex-ai` | `google-vertex-ai` |
| `google-vertex` | `google-vertex-ai` |
| `gcp-vertex` | `google-vertex-ai` |

Alias resolution lives in `openshell_core::inference::normalize_inference_provider_type`
and is the single source of truth shared by `openshell-server`, `openshell-providers`,
and the CLI.

---

## 2. Architecture — How the Pieces Fit Together

```
CLI (openshell provider create / openshell inference set)
  │
  ├── read_gcloud_adc()         reads ~/.config/gcloud/application_default_credentials.json
  ├── CreateProviderRequest     persists provider object (type, credentials, config)
  └── ConfigureProviderRefreshRequest  registers a refresh state record

Gateway (openshell-server)
  │
  ├── provider_refresh worker   background loop that rotates access tokens
  │     ├── mint_oauth2_refresh_token()         for gcloud ADC flow
  │     └── mint_google_service_account_jwt()   for service account key flow
  │
  ├── SetClusterInferenceRequest
  │     └── resolve_vertex_ai_route()           builds RouterResolvedRoute
  │           ├── infer_vertex_publisher()       model → publisher
  │           └── vertex_location_and_host()     region → Vertex API host
  │
  └── GetInferenceBundleRequest (from sandbox on connect)
        └── resolve_route_by_name()             re-resolves live route+credentials

Router (openshell-router)
  │
  ├── proxy_with_candidates_streaming()
  │     ├── build_provider_url()                appends model/:rawPredict or /chat/completions
  │     ├── sanitize_request_headers()          strips auth, strips anthropic-beta for rawPredict
  │     └── prepare_backend_request()
  │           ├── bearer_auth(access_token)     Authorization: Bearer ya29.*
  │           ├── remove "model" from body      (rawPredict only — model is in the URL)
  │           └── inject "anthropic_version"    (rawPredict only — must be in body, not header)
  │
  └── proxy_to_backend() / proxy_to_backend_streaming()

Sandbox (inference.local)
  └── agent connects to inference.local → gateway proxy → Vertex AI
```

Key crates and their roles:

| Crate | Role |
|---|---|
| `openshell-core` (`inference.rs`) | Canonical type aliases, profile constants, URL alias resolution |
| `openshell-providers` | Environment-based credential discovery for `--from-existing` |
| `openshell-server` (`inference.rs`) | Route resolution: maps provider + model → `RouterResolvedRoute` |
| `openshell-server` (`provider_refresh.rs`) | Credential refresh worker; mints access tokens |
| `openshell-router` (`backend.rs`) | Proxy: URL construction, header sanitization, body rewriting |
| `openshell-cli` (`run.rs`) | `provider create` and `--from-gcloud-adc` CLI flow |
| `providers/google-vertex-ai.yaml` | Provider type profile: credential keys, refresh strategy, endpoints |

---

## 3. Credential Model — Two Flows

Vertex AI accepts only short-lived GCP access tokens. The gateway never sends the raw
service account JSON or gcloud ADC material to Vertex AI. Both flows converge on the
same runtime secret: a `ya29.*` token stored under one of these credential keys,
searched in priority order:

```
GOOGLE_VERTEX_AI_SERVICE_ACCOUNT_TOKEN
VERTEX_AI_SERVICE_ACCOUNT_TOKEN
GOOGLE_VERTEX_AI_TOKEN
VERTEX_AI_TOKEN
```

These names are defined in `openshell_core::inference::VERTEX_AI_CREDENTIAL_KEY_NAMES`
and are shared between the profile, the CLI, and the route resolver.

### 3a. Service Account Key Flow (production)

```
User:      openshell provider create --type google-vertex-ai \
             --credential GOOGLE_SERVICE_ACCOUNT_KEY="$(cat key.json)" \
             --config VERTEX_AI_PROJECT_ID=my-project \
             --config VERTEX_AI_REGION=us-central1

User:      openshell provider refresh configure vertex-prod \
             --credential-key GOOGLE_VERTEX_AI_SERVICE_ACCOUNT_TOKEN \
             --strategy google-service-account-jwt \
             --material client_email="sa@..." \
             --material private_key="..." \
             --secret-material-key private_key

Gateway:   mint_google_service_account_jwt()
             1. build JWT claims: iss=client_email, scope=cloud-platform, aud=token_url
             2. sign with RS256 using private_key
             3. POST assertion to https://oauth2.googleapis.com/token
             4. store access_token as GOOGLE_VERTEX_AI_SERVICE_ACCOUNT_TOKEN
             5. schedule next refresh 300 s before expiry (max 3600 s lifetime)
```

The raw `GOOGLE_SERVICE_ACCOUNT_KEY` is stored as bootstrap material for the refresh
worker. It is never exposed to sandboxes; the sandbox only ever sees the short-lived
access token.

### 3b. gcloud Application Default Credentials Flow (local dev)

```
User:      gcloud auth application-default login
User:      openshell provider create --type google-vertex-ai \
             --from-gcloud-adc \
             --config VERTEX_AI_PROJECT_ID=my-project

CLI:       read_gcloud_adc()
             checks GOOGLE_APPLICATION_CREDENTIALS → $CLOUDSDK_CONFIG/... → ~/.config/gcloud/adc.json
             validates type == "authorized_user" (rejects service_account — different flow)
             extracts client_id, client_secret, refresh_token

           configure_provider_refresh(strategy=oauth2_refresh_token, ...)
           rotate_provider_credential(...)   ← mints first token immediately

Gateway:   mint_oauth2_refresh_token()
             POST to https://oauth2.googleapis.com/token
             grant_type=refresh_token, client_id, client_secret, refresh_token
             stores access_token as GOOGLE_VERTEX_AI_TOKEN
             if response includes a new refresh_token, rotates it in state
```

The `--from-gcloud-adc` flag is rejected for any provider type other than
`google-vertex-ai`. The CLI validates and reads the ADC file before creating the
provider, so a missing or malformed ADC file results in a clean error with no orphaned
gateway state.

### 3c. Refresh Worker

`provider_refresh.rs` runs a background tokio task (`spawn_refresh_worker`) that
sweeps all `StoredProviderCredentialRefreshState` records on a configurable interval.
For each record where `next_refresh_at_ms <= now` or `status == "rotation_requested"`,
it calls `refresh_provider_credential`, which calls `mint_credential` and then
`apply_minted_credential`. The minted access token is written back to the provider's
`credentials` map under the configured `credential_key` via a CAS update.

Key timing constants:

- Default `refresh_before_seconds`: 300 (refresh 5 minutes before expiry)
- Default `max_lifetime_seconds`: 3600 (token lifetime cap)
- Error retry interval: 60 seconds

---

## 4. Route Resolution — From Provider to RouterResolvedRoute

When `openshell inference set --provider <name> --model <id>` is called, the server
runs `resolve_vertex_ai_route` in `openshell-server/src/inference.rs`. This function
produces a `RouterResolvedRoute` that the router uses verbatim for every proxied
request.

### 4a. Publisher Inference

`infer_vertex_publisher(model_id)` maps model name prefixes to Vertex AI publishers:

| Prefix | Publisher | Routing |
|---|---|---|
| `claude-*` | `anthropic` | Anthropic Messages API (rawPredict) |
| `gemini-*`, `text-bison-*`, `chat-bison-*` | `google` | OpenAI-compat Chat Completions |
| `llama-*` | `meta` | OpenAI-compat Chat Completions |
| `mistral-*`, `codestral-*` | `mistralai` | OpenAI-compat Chat Completions |
| `jamba-*` | `ai21` | OpenAI-compat Chat Completions |
| `deepseek-*` | `deepseek` | OpenAI-compat Chat Completions |
| (unrecognized) | `None` | OpenAI-compat Chat Completions |

Only the `anthropic` result changes routing; all non-Anthropic publishers use the same
OpenAI-compatible Vertex surface. The `VERTEX_AI_PUBLISHER` config key overrides
inference: set it to `anthropic` to force rawPredict for a non-standard model name.

### 4b. Host Resolution

`vertex_location_and_host(region)` maps the `VERTEX_AI_REGION` config value to a
Vertex API host:

| Region value | Host |
|---|---|
| `global` | `aiplatform.googleapis.com` |
| `us` | `aiplatform.us.rep.googleapis.com` |
| `eu` | `aiplatform.eu.rep.googleapis.com` |
| `us-central1`, `europe-west4`, etc. | `<region>-aiplatform.googleapis.com` |

Default region when not set: `us-central1`.

### 4c. Endpoint and Protocol Selection

**Anthropic (Claude) models:**

```
endpoint = https://{host}/v1/projects/{project}/locations/{location}/publishers/anthropic/models
protocol = ["anthropic_messages"]
model_in_path = true
request_path_override = ":rawPredict"
```

The model ID is NOT embedded in the endpoint URL. It is stored in `route.model` and
appended by `build_provider_url` at proxy time: `{endpoint}/{model}:rawPredict` for
buffered requests, `{endpoint}/{model}:streamRawPredict` for streaming.

**Non-Anthropic models (Gemini, Llama, Mistral, etc.):**

```
endpoint = https://{host}/v1beta1/projects/{project}/locations/{location}/endpoints/openapi
protocol = ["openai_chat_completions"]
model_in_path = false
request_path_override = "/chat/completions"
```

**Base URL override (escape hatch, non-Anthropic only):**
When `GOOGLE_VERTEX_AI_BASE_URL` or `VERTEX_AI_BASE_URL` is set:

- `GOOGLE_VERTEX_AI_BASE_URL` takes priority over `VERTEX_AI_BASE_URL`
- Rejected with `InvalidArgument` for Anthropic models — Anthropic routes require
  model-path shaping that a bare URL override cannot preserve safely
- Must be `https://`, no IP literals, no userinfo, port 443 only if explicit, must
  target an official Vertex AI hostname (pattern validated by `is_allowed_vertex_override_host`)

### 4d. Credential Lookup

For Vertex AI specifically, `find_provider_api_key` uses `CredentialLookup::PreferredOnly`:
it searches only the four `VERTEX_AI_CREDENTIAL_KEY_NAMES` keys and returns `None` if
none match. This prevents the raw service account JSON stored under
`GOOGLE_SERVICE_ACCOUNT_KEY` from being mistakenly used as a bearer token, which would
produce a confusing auth failure from Vertex AI.

### 4e. Model ID Validation

Before any URL is constructed, `validate_vertex_model_id` rejects model IDs that
contain path separators (`/`, `\`), traversal segments (`..`), URL delimiters (`?`,
`#`, `%`), control characters, or surrounding whitespace. This is defense-in-depth
against injection into the URL path that appears in Anthropic rawPredict routes.

---

## 5. Request Proxying — Backend Transformations

The router (`openshell-router/src/backend.rs`) applies four Vertex-specific
transformations on every proxied request:

### 5a. URL Construction

`build_provider_url` is called with `model_in_path` and `request_path_override` from
the resolved route:

- **Anthropic buffered:** `{endpoint}/{model_id}:rawPredict`
- **Anthropic streaming:** `{endpoint}/{model_id}:streamRawPredict`
  (`:rawPredict` suffix is upgraded to `:streamRawPredict` when `stream_response=true`)
- **OpenAI-compat:** `{endpoint}/chat/completions`

### 5b. Authentication

All Vertex AI routes use `AuthHeader::Bearer`. The router injects
`Authorization: Bearer {access_token}` where `access_token` is the `ya29.*` token
read from the provider's credentials at route resolution time.

### 5c. Header Sanitization — Stripping `anthropic-beta`

For rawPredict routes (`is_vertex_anthropic_rawpredict_route`), `sanitize_request_headers`
strips the `anthropic-beta` header even though it is in the route's `passthrough_headers`
list. Vertex AI's rawPredict endpoint rejects requests that include `anthropic-beta` with
HTTP 400. Beta feature enablement for Vertex AI is controlled through Google Cloud
(Model Garden access), not HTTP headers. Claude Code always sends `anthropic-beta` flags;
stripping them here prevents spurious 400 errors.

Direct Anthropic API routes (non-Vertex) still forward `anthropic-beta` unchanged.

### 5d. Body Rewriting — `model` and `anthropic_version`

For rawPredict routes, `prepare_backend_request` rewrites the JSON request body:

- **Removes `"model"` field.** Vertex AI rawPredict encodes the model in the URL path.
  Sending `"model"` in the body causes HTTP 400 "Extra inputs are not permitted". Claude
  Code and other Anthropic SDK clients always include `"model"` in the body; the router
  strips it unconditionally for rawPredict routes.

- **Injects `"anthropic_version": "vertex-2023-10-16"`.** The standard Anthropic API
  sends this as the `anthropic-version` request header. Vertex AI's rawPredict expects
  it as a JSON body field instead. The router injects it only when the client has not
  already sent it (`!obj.contains_key("anthropic_version")`). The constant
  `VERTEX_ANTHROPIC_VERSION = "vertex-2023-10-16"` is the Google-published value.

For OpenAI-compatible routes, the standard model rewrite applies: `"model"` in the body
is overwritten with `route.model` (the model ID configured at `openshell inference set`
time).

---

## 6. Configuration Keys

These keys are set at `openshell provider create` time via `--config KEY=VALUE` and
stored in the provider's `config` map. They are re-read on every bundle resolution
(i.e. on every sandbox connect), so changing them with `openshell provider update` takes
effect for new sandboxes without restarting the gateway.

| Key | Required | Default | Description |
|---|---|---|---|
| `VERTEX_AI_PROJECT_ID` | Yes (unless base URL override set) | — | GCP project ID. Must be 6–30 chars, lowercase letters/digits/hyphens, no leading/trailing hyphen. |
| `VERTEX_AI_REGION` | No | `us-central1` | GCP region or `global`/`us`/`eu`. Determines the Vertex API host. |
| `GOOGLE_VERTEX_AI_BASE_URL` | No | — | Full base URL override for non-Anthropic routes. Takes priority over `VERTEX_AI_BASE_URL`. |
| `VERTEX_AI_BASE_URL` | No | — | Backward-compatible alias for `GOOGLE_VERTEX_AI_BASE_URL`. |
| `VERTEX_AI_PUBLISHER` | No | Inferred from model name | Set to `anthropic` to force rawPredict routing. |

Config key constants are defined in `openshell_core::inference`:
`VERTEX_AI_PROJECT_ID_KEY`, `VERTEX_AI_REGION_KEY`, `VERTEX_AI_PUBLISHER_KEY`.

The full list of config keys scanned during `--from-existing` discovery is
`VERTEX_AI_CONFIG_KEY_NAMES` in the same module.

---

## 7. Credential Keys and the Provider Profile

`providers/google-vertex-ai.yaml` is the authoritative provider type profile. It
defines:

- **`service_account_key` (`GOOGLE_SERVICE_ACCOUNT_KEY`):** The raw service account JSON.
  This is gateway-side bootstrap material, not a sandbox credential. Not injected into
  sandboxes. `required: false` because some deployments use gcloud ADC instead.

- **`service_account_token` (`GOOGLE_VERTEX_AI_SERVICE_ACCOUNT_TOKEN`,
  `VERTEX_AI_SERVICE_ACCOUNT_TOKEN`):** Short-lived access token minted from the service
  account key via `google_service_account_jwt` refresh strategy. `auth_style: bearer`.
  Refreshed 300 s before expiry; max lifetime 3600 s; scope
  `https://www.googleapis.com/auth/cloud-platform`.

- **`gcloud_adc_token` (`GOOGLE_VERTEX_AI_TOKEN`, `VERTEX_AI_TOKEN`):** Short-lived
  access token minted from gcloud ADC via `oauth2_refresh_token` refresh strategy.
  Same `auth_style: bearer`, same timing.

The `discovery` section lists `[service_account_token, gcloud_adc_token]` as the two
credential sources the gateway will scan during `--from-existing`.

The `endpoints` section enumerates all Vertex AI API hosts that sandbox network
policies must permit when `providers_v2_enabled=true`:

- `*-aiplatform.googleapis.com:443` (regional endpoints)
- `aiplatform.googleapis.com:443` (global endpoint)
- `aiplatform.us.rep.googleapis.com:443` (US multi-region)
- `aiplatform.eu.rep.googleapis.com:443` (EU multi-region)

---

## 8. `openshell-providers` — Discovery Plugin

`openshell-providers` handles credential discovery for `--from-existing`. There is no
dedicated `vertex.rs` plugin file because Vertex AI token discovery is profile-driven:
the gateway reads the `providers/google-vertex-ai.yaml` profile and scans the
credential env vars listed there.

Vertex AI config keys (`VERTEX_AI_PROJECT_ID`, `VERTEX_AI_REGION`, etc.) are not listed
in the profile's `discovery.credentials` section, so they are scanned separately in
`discover_existing_provider_data` in the CLI:

```rust
if provider_type == VERTEX_AI_PROVIDER_TYPE {
    for key in openshell_core::inference::VERTEX_AI_CONFIG_KEY_NAMES {
        if let Ok(val) = std::env::var(key) { ... }
    }
}
```

Provider type normalization for the `ProviderRegistry` (non-inference providers like
`claude-code`, `github`, `gitlab`) is handled by `normalize_provider_type` in
`openshell-providers/src/lib.rs`, which delegates Vertex AI aliases to
`normalize_inference_provider_type` in `openshell-core`.

---

## 9. Inference Routing in the Sandbox

When a sandbox agent connects to `https://inference.local`, the sandbox fetches the
inference bundle from the gateway (`GetInferenceBundleRequest`). The bundle contains one
or more `ResolvedRoute` proto messages built by `resolve_route_by_name`. For a Vertex AI
route the bundle contains:

```
ResolvedRoute {
  name: "inference.local",
  base_url: "https://us-central1-aiplatform.googleapis.com/v1/projects/.../publishers/anthropic/models",
  model_id: "claude-sonnet-4-20250514",
  api_key: "ya29.<short-lived-token>",
  protocols: ["anthropic_messages"],
  provider_type: "google-vertex-ai",
  model_in_path: true,
  request_path_override: ":rawPredict",
}
```

The sandbox proxy uses this bundle to configure the local `inference.local` route. The
bundle is re-fetched on reconnect, which picks up rotated access tokens automatically
without sandbox restart.

The gateway does NOT expose GCP credentials (project ID, region, service account key)
in the bundle. Sandboxes see only the short-lived access token.

---

## 10. Sandbox Usage Pattern

Agents inside sandboxes connect to Vertex AI through `inference.local`. The correct
setup differs by model family:

**Claude (Anthropic Messages API):**

```sh
ANTHROPIC_BASE_URL="https://inference.local" ANTHROPIC_API_KEY=unused claude --bare
```

The `ANTHROPIC_API_KEY` value is stripped by the gateway and replaced with the real
GCP token. `--bare` skips Claude Code's OAuth flow. Do NOT set
`CLAUDE_CODE_USE_VERTEX=1` inside a sandbox — that makes Claude Code connect directly
to Vertex AI and attempt GCP ADC discovery, which fails in the sandbox environment.

**Gemini / other models (OpenAI-compat):**
Point the SDK's base URL at `https://inference.local/v1` and use any non-empty value
as the API key.

**Common sandbox policy denials to expect:**

- `metadata.google.internal:80` — resolves to `169.254.169.254` (GCE metadata service).
  Always blocked by the proxy unconditionally.
- `downloads.claude.ai:443` — Claude Code update checking. Block or approve per policy.
- `storage.googleapis.com:443` — GCS access. Optional; approve if the agent needs it.

---

## 11. Key Files Reference

| File | Purpose |
|---|---|
| `providers/google-vertex-ai.yaml` | Provider type profile: credential keys, refresh strategy params, allowed endpoints |
| `docs/providers/google-vertex-ai.mdx` | User-facing documentation |
| `crates/openshell-core/src/inference.rs` | Canonical provider type aliases, `InferenceProviderProfile`, `VERTEX_AI_*` constants, auth header logic |
| `crates/openshell-server/src/inference.rs` | Route resolution: `resolve_vertex_ai_route`, `infer_vertex_publisher`, `vertex_location_and_host`, model ID validation |
| `crates/openshell-server/src/provider_refresh.rs` | Refresh worker: `mint_google_service_account_jwt`, `mint_oauth2_refresh_token`, `apply_minted_credential` |
| `crates/openshell-router/src/backend.rs` | Proxy engine: `build_provider_url`, `sanitize_request_headers`, `prepare_backend_request` (model strip + anthropic_version inject) |
| `crates/openshell-router/src/config.rs` | `ResolvedRoute` struct with `model_in_path`, `request_path_override` fields |
| `crates/openshell-cli/src/run.rs` | `provider_create`, `read_gcloud_adc`, `rollback_provider_create_after_vertex_adc_failure` |
| `crates/openshell-providers/src/lib.rs` | `ProviderRegistry`, `normalize_provider_type`, `discover_existing_provider_data` |

---

## 12. Maintenance Notes

### Adding a new Vertex AI region

No code changes are needed for standard regional endpoints (`<region>-aiplatform.googleapis.com`).
`vertex_location_and_host` constructs the host from the region string dynamically. For
new special-case multi-region endpoints (analogous to `us` and `eu`), update the match
arm in `vertex_location_and_host` in `openshell-server/src/inference.rs`.

Add the new host pattern to the `endpoints` list in `providers/google-vertex-ai.yaml`
so it is included in sandbox network policy injection.

### Adding a new model family publisher

Add a prefix match arm to `infer_vertex_publisher` in `openshell-server/src/inference.rs`.
Unless the new publisher uses a different wire format than the OpenAI-compatible
endpoint, no other changes are needed — all non-Anthropic publishers currently route
to the same `endpoints/openapi/chat/completions` surface.

If the new publisher requires a separate rawPredict-style surface (like Anthropic),
update `resolve_vertex_ai_route` to add a new branch for that publisher, and add the
corresponding body transformation logic in `prepare_backend_request` in
`openshell-router/src/backend.rs`.

### Updating `VERTEX_ANTHROPIC_VERSION`

The constant `VERTEX_ANTHROPIC_VERSION = "vertex-2023-10-16"` in
`openshell-router/src/backend.rs` is the version string Google requires in the body of
rawPredict requests. Update it when Google publishes a new required version for the
Vertex AI Anthropic API. Check the
[Google Cloud Claude documentation](https://cloud.google.com/vertex-ai/generative-ai/docs/partner-models/use-claude)
for the current required value.

### Rotating the GCP OAuth2 token endpoint URL

`google_token_url` in `provider_refresh.rs` defaults to `https://oauth2.googleapis.com/token`
when `state.token_url` is empty. The `providers/google-vertex-ai.yaml` profile sets this
in the `refresh.token_url` field. If Google changes the token endpoint, update both:

- `refresh.token_url` in `providers/google-vertex-ai.yaml`
- The default in `google_token_url` in `provider_refresh.rs`

### Changing the `cloud-platform` OAuth scope

The scope `https://www.googleapis.com/auth/cloud-platform` is set in the
`refresh.scopes` list in `providers/google-vertex-ai.yaml`. The gateway uses it when
constructing JWT claims and OAuth2 refresh requests. If a narrower scope becomes
available (e.g. a Vertex AI-specific scope), update the profile's `scopes` list.

### Adding a new Vertex AI body invariant

Body transformations for rawPredict live in `prepare_backend_request` in
`openshell-router/src/backend.rs`, gated by `is_vertex_anthropic_rawpredict_route`.
When adding a new transformation:

1. Add the transformation in the `needs_vertex_anthropic_version` branch.
2. Add a wiremock-based integration test directly below the existing tests in that file.
3. Ensure the new transformation does not apply to standard Anthropic or OpenAI routes.
