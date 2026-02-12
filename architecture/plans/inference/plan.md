# Inference Router Plan

Status: In Progress
Date: 2026-02-09

## Goals

- Use entity-managed inference configuration.
- Use `routing_hint` as the user-facing signal.
- Start with a simple and strict v1 model.
- Use fail-closed sandbox authorization.

## Design principles

- `routing_hint` is advisory intent from userland, not an internal route ID.
- Use a single entity in v1 (`InferenceRoute`) to keep control plane simple.
- v1 is intentionally small: 1:1 route-to-model mapping.
- Add richer route modes only after route-only CRUD + tests are solid.

## Naming

- `Inference`: top-level namespace/service name.
- `routing_hint`: request field used by callers.
- `InferenceRoute`: maps hint -> routing behavior.
- `InferencePolicy`: sandbox authorization settings.

## Entity model

### InferenceRoute

Represents how a `routing_hint` resolves.

Fields:
- `id`
- `spec`
  - `routing_hint`
  - `base_url`
  - `protocol` (`openai_chat_completions` initially)
  - `api_key` (plaintext for now)
  - `model_id`
  - `enabled`

Persistence:
- Store as protobuf payloads in the existing `objects` table.
- Route auth is plaintext in v1; future update will replace `api_key` with secret references.

## Request semantics

`CompletionRequest` remains centered on `routing_hint`.

- `routing_hint` is optional/advisory; server resolves an effective route.
- `model_id` is resolved from route `spec.model_id` in v1.

v1 behavior:
- Route contains full upstream target + model config.
- Userland sends `routing_hint` + messages only.

v2 behavior:
- Add optional passthrough model mode for downstream-router scenarios.

## Sandbox policy model

v1 control:
- `allowed_routing_hints`

Planned extension:
- optional `allowed_model_ids`
- optional provider/capability dimensions if needed later

Enforcement order:
1. Authenticate request identity.
2. Resolve route from `routing_hint`.
3. Apply sandbox policy checks.
4. Call upstream.

## API plan (entity management)

Routes:
- `CreateInferenceRoute`
- `UpdateInferenceRoute`
- `DeleteInferenceRoute`
- `ListInferenceRoutes`

CLI:
- Use `nav inference create|update|delete|list` for route CRUD and inspection.

## Router behavior

- Resolve by `routing_hint`.
- Load active route from entity store.
- Support dynamic refresh without restart (watch or polling).
- Perform protocol mapping to upstream API shape.

## Responsibility split

- Server responsibilities:
  - authenticate sandbox request
  - enforce `InferencePolicy` (`allowed_routing_hints`)
  - load enabled, policy-allowed route candidates from store
- Router responsibilities:
  - select route from candidate set using request context (`routing_hint` today)
  - execute upstream inference call
  - remain the single place for future routing logic (fallbacks, scoring, policy-aware strategy)

## AuthZ and governance

Required decisions:
- RBAC for inference entity CRUD.
- Audit trail for route mutations.

## Implementation phases

### Phase 1
- Define entities and protobufs.
- Implement CRUD APIs for routes.
- Implement router resolution from entities.
- Use fixed route-to-model mapping only.
- Enforce sandbox `allowed_routing_hints`.

### Phase 2
- Add optional passthrough-model route mode.
- Add optional per-sandbox `allowed_model_ids`.
- Add richer provider/capability policy dimensions if needed.

## Implementation status

- Done: `InferenceRoute` entity with `spec` shape (`id + spec`).
- Done: route-only gRPC CRUD (`Create/Update/Delete/ListInferenceRoute`).
- Done: completion path resolves route from store by `routing_hint`.
- Done: CLI route CRUD commands (`nav inference create|update|delete|list`).
- Done: sandbox policy enforcement remains `allowed_routing_hints`.
- Pending: expand integration tests for CRUD + completion + policy edges.

## Validation and testing

- Unit: entity validation, route resolution, policy evaluation.
- Integration: CRUD, router refresh, completion path.
- Security: API key redaction in logs/outputs.

## Open decisions

- Missing/unknown `routing_hint`: strict error or default route.
- Whether `routing_hint` must be globally unique or namespaced.
- Principal identity source and RBAC model for non-sandbox clients.
