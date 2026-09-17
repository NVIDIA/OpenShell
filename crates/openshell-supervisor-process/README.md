# Process supervisor

`openshell-supervisor-process` owns the supervisor's process-facing runtime:
SSH access, the gateway session, log forwarding, and the OTLP telemetry
relay described below.

## Telemetry relay

The supervisor relays OpenTelemetry trace data from agent processes to the
gateway over the session stream, so OTel-instrumented agents reach an
external collector without any sandbox egress.

The relay is opt-in on the gateway. When `[openshell.gateway.otlp]` is
configured, `CreateSandbox` sets `OTEL_EXPORTER_OTLP_ENDPOINT` to
`http://192.0.0.8:4318` and `OTEL_EXPORTER_OTLP_PROTOCOL` to `http/protobuf`
in the sandbox environment unless the caller already set an endpoint. The
values persist in the stored spec, so restarts inherit them.

`192.0.0.8` is the RFC 7600 dummy address and is never routed. A workload
connect to any non-loopback address is intercepted by the sandbox seccomp
broker and staged for the supervisor as a `PendingTcpOpen`, so the address is
a label the supervisor switches on. The proxy recognises it ahead of host
mapping, policy, and SSRF validation and hands the staged stream to the OTLP
receiver instead of dialing upstream. The receiver speaks HTTP/1.1 on that
stream and accepts `POST /v1/traces` as protobuf or JSON. No socket is bound,
the driver outer fence is untouched, and the isolation contract and boundary
protocol are unchanged. Loopback cannot serve this purpose because the broker
completes loopback connects locally without mediation.

```
Agent process --> connect(192.0.0.8:4318) --> seccomp broker stages the open
  --> supervisor proxy, reserved destination --> OTLP receiver
  --> enrichment (openshell.sandbox.* resource attributes)
  --> bounded buffer (4096 items, newest dropped when full)
  --> supervisor session (OtelExportData) --> gateway
  --> dedicated OtelRelayExporter --> external OTLP collector
```

The relay starts before networking, so the first staged stream finds it. The
supervisor advertises `otel_export` in `SupervisorHello`; the gateway confirms
it in `SessionAccepted` only when it has a relay exporter. Forwarding is gated
per session on that confirmation. Items received before a confirming session,
or while a session declines, wait in the bounded buffer. The receiver serves
at most 64 concurrent connections and refuses further opens before the
sandbox commits the socket, which the agent observes as `EAGAIN`.

Forwarded spans gain `openshell.sandbox.id`, `openshell.workspace.id`,
`openshell.sandbox.policy`, `openshell.sandbox.user`,
`openshell.sandbox.image`, and `openshell.sandbox.driver`, and always
`openshell.telemetry.source=agent` so collectors can separate agent spans
from gateway spans. Agent-supplied values for these keys are replaced.

Both hops are non-blocking. The receiver uses `try_send` into the buffer and
the session uses `try_send` into its outbound channel, so telemetry can never
stall control traffic. After the main process exits and before the exit is
reported, the supervisor asks the session to stop the receiver (no new
streams, keep-alive disabled, two seconds for in-flight requests, then
stragglers cut) and flush the buffer onto the stream. The whole drain is
bounded at three seconds so an unreachable gateway cannot delay the report.

The gateway forwards trace bytes through a dedicated `OtelRelayExporter`
rather than its own tracer provider, so the supervisor's resource attributes
survive. `OtelExportData` also carries OCSF events, which the gateway
re-emits on the `ocsf_relay` target; the supervisor-side OCSF sink is not
installed yet.
