# Supervisor middleware troubleshooting

Use this reference when the deployment registers supervisor middleware or a
sandbox policy attaches it through `network_middlewares`. Start with gateway
reachability and compute-platform checks in the [main skill](../SKILL.md).
Use installed CLI help for command syntax and the published
[gateway configuration reference](https://docs.nvidia.com/openshell/latest/reference/gateway-config.md)
for registration settings.

## Collect diagnostics

For operator-run supervisor middleware, inspect `[[openshell.supervisor.middleware]]`, service reachability, and both gateway and supervisor logs:

```shell
rg -n 'supervisor|middleware|grpc_endpoint|tls_ca_cert_path|audience|allow_insecure_transport|max_payload_bytes|timeout|gateway_jwt' /etc/openshell/gateway.toml
journalctl -u <middleware-service> --no-pager --lines=200
journalctl -u openshell-gateway --no-pager --lines=200
openshell logs <sandbox-name> --tail --source sandbox
```

## Startup and authentication

The middleware service must start before the gateway and be reachable from both the gateway and sandbox supervisors. Gateway startup fails if `Describe` is unavailable, a manifest exposes duplicate operation/phase bindings, the registration claims the reserved `openshell/` namespace, or payload and timeout limits are invalid. Supported V1 bindings are `HTTP_REQUEST/PRE_CREDENTIALS`, `HTTP_RESPONSE/PRE_RETURN`, and `WEBSOCKET_MESSAGE/PRE_CREDENTIALS`.

When gateway JWT signing is disabled, supervisors preserve the legacy unauthenticated connector and do not request extension credentials. When signing is enabled, credential acquisition and verification failures are fail closed: check HTTPS trust and hostname validation, audience and issuer agreement, the token `kid`, gateway `RefreshSandboxToken` errors, and middleware logs. Changing a registration requires a gateway restart. A policy update can also fail before persistence if the selected implementation rejects its `network_middlewares` config.

## HTTP response failures

For response failures, distinguish a deliberate `middleware_denied` decision from `response_delivery_failed`. Before response commitment, they produce canonical 403 and 502 responses respectively. After commitment, OpenShell aborts without adding an error body, final chunk, or trailer. A whole-body accumulation timeout is one fixed, non-resetting 120-second wall-clock deadline shared across response reads and whole-body barriers; inspect the active stage's `on_error` and `whole_body_accumulation_timeout` diagnostics. Header-only stages preserve upstream body framing. Body-processing stages normalize framing and send a trailer exchange, including an empty trailer set, after the final body result.

## Request and WebSocket failures

At request time, distinguish attachment, binding selection, coverage, denial, and failure. A host-matched HTTP-only attachment can inspect the upgrade GET but does not join the WebSocket chain; the connection proceeds under either `on_error` mode and emits `binding_not_selected` coverage. A selected WebSocket stage receives text messages only. Binary messages pass under both modes, emit `unsupported_message_type` coverage, and consume a session sequence without an RPC.

An explicit `middleware_denied` result is always enforced. WebSocket preflight returns `INSPECT`, voluntary `SKIP`, or authoritative `DENY`; `DENY` rejects the upgrade before upstream contact under both `on_error` modes. A selected-stage failure follows the policy-local `on_error`: `fail_closed` blocks the HTTP request or closes the WebSocket, while `fail_open` bypasses only that stage and emits a detection finding. A fail-open per-message capacity failure bypasses that message without disabling the stage. A timeout, transport failure, stream closure, missing or invalid response, duplicate or regressed sequence, or other failure that makes an established WebSocket stream unreliable disables that stage for later messages on the connection and emits `openshell.middleware.websocket_stage_disabled`.

Confirm preflight, session-start, and session-end in service logs. OpenShell best-effort sends at most one session-end to each still-writable opened stage, including a preflight that terminates before session start; distinguish `MIDDLEWARE_DENIAL` from `MIDDLEWARE_FAILURE`.

WebSocket message sequences are allocated session-wide; each stage receives a strictly increasing subset, so gaps are valid when binary messages or other units are not delivered to that stage. Zero, duplicate, or regressed sequences are protocol errors. If a running supervisor cannot install a new registry, it preserves its last-known-good generation and emits a configuration failure event.

## Common failure patterns

| Symptom | Likely cause | Check |
|---|---|---|
| Authenticated middleware rejects gateway calls | Private CA or hostname mismatch, expected audience or issuer mismatch, stale/unknown `kid`, or malformed extension token | `tls_ca_cert_path`, registration `audience`, service verifier config and logs; fetch well-known metadata only through the already-trusted gateway TLS endpoint |
| Gateway fails after registering supervisor middleware | Service unavailable, invalid manifest, duplicate binding, reserved name, or invalid payload/timeout limit | Middleware service and gateway logs; `[[openshell.supervisor.middleware]]`; `Describe` response |
| Policy update rejects `network_middlewares` | Unknown middleware name, implementation-owned config invalid, duplicate order, broad/invalid host selector, or fail-closed coverage of `tls: skip` | Policy error, gateway logs, middleware `ValidateConfig`, selector and order fields |
| HTTP request returns `middleware_failed` or `middleware_denied`, or WebSocket closes with `1008` | Selected stage failed or explicitly denied admitted traffic | Sandbox OCSF logs; policy-local middleware config; service availability; binding operation; `on_error` |
| HTTP response becomes canonical `403 middleware_denied`, `502 response_delivery_failed`, or closes mid-body | Response middleware blocked, failed before commitment, or stopped delivery after commitment | Sandbox OCSF response middleware events; `HTTP_RESPONSE/PRE_RETURN` binding; `on_error`; `whole_body_accumulation_timeout`; service stream lifecycle |
| WebSocket upgrades but a host-matched middleware receives no preflight or message RPC | The implementation did not advertise `WEBSOCKET_MESSAGE/PRE_CREDENTIALS` | `WEBSOCKET_MIDDLEWARE_COVERAGE state=binding_not_selected`; service `Describe`; the upgrade GET may still have used its HTTP binding |
| Binary WebSocket message passes without a middleware RPC | Binary is unsupported by the V1 text-message binding under both `on_error` modes | `WEBSOCKET_MIDDLEWARE_COVERAGE state=unsupported_message_type`; the next text RPC may have a valid sequence gap |
| WebSocket messages stop reaching middleware after one failure | A fail-open stage stream was disabled for the rest of the connection | `openshell.middleware.websocket_stage_disabled`; middleware timeout/stream/protocol logs. A per-message capacity bypass alone leaves the stage active. Reconnect to create a fresh stream after a genuine stream failure |
| Supervisor repeatedly fails to install middleware after enabling gateway JWT signing | Extension credential minting, distribution, or authenticated service connection failed; last-known-good registry remains active | Gateway `RefreshSandboxToken` logs, sandbox configuration events, service token-verification logs, registration TLS/audience settings |
