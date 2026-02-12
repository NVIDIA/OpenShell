# navigator-router

`navigator-router` is the inference routing and upstream execution engine used by `navigator-server`.

## Responsibilities

- Select an upstream route from a candidate set (based on request context, `routing_hint` today).
- Execute OpenAI-compatible chat completion HTTP calls to the selected upstream.
- Normalize upstream failures into router-level errors (`unauthorized`, `unavailable`, protocol/internal errors).
- Keep routing decision logic in one place so strategies can evolve (fallbacks, scoring, health-based routing).

## Non-responsibilities

- Authentication and sandbox identity.
- Authorization and policy enforcement.
- Persistence of routes/entities.
- Loading sandbox or policy objects.

These are owned by `navigator-server`.

## Integration contract with navigator-server

Current split:

- `navigator-server`:
  - authenticates request origin
  - enforces sandbox policy (`allowed_routing_hints`)
  - loads enabled, policy-allowed route candidates from the entity store
- `navigator-router`:
  - picks a route from candidates (`completion_with_candidates`)
  - calls upstream and returns completion response

## Public APIs

- `Router::completion(&CompletionRequest)`
  - Uses router-internal routes loaded from `RouterConfig`.
  - Useful for config-file driven flows and tests.

- `Router::completion_with_candidates(&CompletionRequest, &[ResolvedRoute])`
  - Uses caller-provided route candidates.
  - Preferred path for entity-driven server routing.

- `Router::completion_for_route(&ResolvedRoute, &CompletionRequest)`
  - Executes a pre-selected route directly.

## Notes

- `protocol` is currently expected to be OpenAI chat completions compatible.
- Route selection currently matches by `routing_hint`; this is intentionally simple and will evolve.
