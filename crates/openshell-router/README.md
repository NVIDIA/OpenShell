# openshell-router

`openshell-router` is the inference routing and upstream execution engine used
by the sandbox proxy and gateway inference validation paths.

## Responsibilities

- Select an upstream route from a candidate set (based on protocol compatibility).
- Forward raw HTTP requests to the selected upstream backend.
- Normalize upstream failures into router-level errors (`unauthorized`, `unavailable`, protocol/internal errors).
- Keep routing decision logic in one place so strategies can evolve (fallbacks, scoring, health-based routing).

## Non-responsibilities

- Authentication and sandbox identity.
- Authorization and policy enforcement.
- Persistence of routes/entities.
- Loading sandbox or policy objects.

These are owned by `openshell-server` and `openshell-sandbox`.

## Integration Contract

Current split:

- `openshell-server`:
  - authenticates user-facing inference configuration changes
  - resolves managed route candidates from provider records
  - validates backend endpoints
- `openshell-sandbox`:
  - intercepts `https://inference.local`
  - detects the source inference protocol
  - passes sanitized requests and resolved route candidates to the router
- `openshell-router`:
  - picks a route from candidates (`proxy_with_candidates`)
  - forwards the HTTP request upstream and returns the raw response

## Public APIs

- `Router::proxy_with_candidates(source_protocol, method, path, headers, body, &[ResolvedRoute])`
  - Filters candidates by protocol compatibility, then forwards the request to the first match.
  - Preferred path for entity-driven server routing.

## Notes

- Route selection matches candidates by `protocol` field (e.g. `openai_chat_completions`).
- Route selection is intentionally simple and will evolve.
