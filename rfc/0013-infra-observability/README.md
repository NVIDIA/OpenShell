---
authors:
  - "@rhuss"
state: draft
links:
  - https://github.com/NVIDIA/OpenShell/issues/1055
  - https://github.com/NVIDIA/OpenShell/issues/2507
  - https://github.com/NVIDIA/OpenShell/issues/909
---

# RFC 0013 - Infrastructure-level observability

## Summary

This RFC extends OpenShell's infrastructure observability to the components that have no OpenTelemetry (OTel) coverage today: in-process compute drivers (K8s, Docker, Podman), the CLI, and deployment configuration (Helm OpenTelemetry Protocol (OTLP) values, Prometheus Operator ServiceMonitor). It also adds Open Cybersecurity Schema Framework (OCSF)-to-OTel correlation so operators can pivot between security logs and traces, and lays out the metrics maturity path from the current basic Rate/Errors/Duration (RED) metrics to the full catalog proposed in [#909](https://github.com/NVIDIA/OpenShell/issues/909).

All of this work builds on existing foundations. OTLP trace export merged for the gateway ([#2534](https://github.com/NVIDIA/OpenShell/pull/2534)) and VM driver ([#2564](https://github.com/NVIDIA/OpenShell/pull/2564)), with a shared `openshell-otel` crate ([#2567](https://github.com/NVIDIA/OpenShell/pull/2567)). OCSF structured logging covers security events on both the sandbox and gateway sides. Prometheus metrics provide basic gateway request counting ([#920](https://github.com/NVIDIA/OpenShell/pull/920)). None of the proposed changes require new transport mechanisms or architectural novelty; they extend what exists to fill coverage gaps.

Agent-level observability (the OTLP relay for collecting traces from inside network-isolated sandboxes) is covered in a companion RFC (RFC 0014).

## Persona workflows

Each section of this RFC is motivated by a concrete workflow that a persona needs to perform today but cannot.

### Platform operator: debugging slow sandbox creation

An operator receives an alert that sandbox creation latency exceeds the SLO. They open Jaeger and search for `sandbox.create` spans in the last hour. They find one taking 15 seconds. They drill into the child spans, expecting to see which compute driver operation was slow, but the trace ends at the gateway request span. The K8s driver's `provision_pod` call, the Docker driver's `create_container`, the Podman driver's equivalent are all invisible because none of them have `#[tracing::instrument]` annotations.

**What this RFC enables:** The in-process driver spans appear as children of the gateway request span. The operator sees that `provision_pod` took 14 of the 15 seconds, drills into the K8s API calls, and identifies that the node was under memory pressure. No new infrastructure is needed because these drivers already inherit the gateway's tracing subscriber.

### CI engineer: tracing a pipeline step through the gateway

A CI pipeline runs `openshell sandbox create`, executes an agent task, and tears down the sandbox. The pipeline has its own OTel tracing (the CI system sets `TRACEPARENT` in the environment). The engineer wants to see the OpenShell operations as part of the pipeline trace: how long did sandbox creation take, which driver handled it, were there retries? Today, the CLI does not forward `TRACEPARENT` to the gateway, so the pipeline trace ends at the CLI invocation and a separate, disconnected trace starts at the gateway.

**What this RFC enables:** The CLI forwards the `TRACEPARENT` from the environment to the gateway via `TraceContextInterceptor` on the gRPC channel. The gateway's `sandbox.create` span becomes a child of the pipeline trace. The engineer sees the full flow in their CI tracing dashboard: pipeline step -> CLI -> gateway -> K8s driver -> pod provisioning. No OTel provider or collector configuration is needed on the CI runner; the CLI just passes through what the CI system already provides.

### Security/compliance reviewer: correlating a policy violation with its trace

A security reviewer investigating a suspicious network pattern opens the OCSF log aggregator (Loki, Splunk) and filters for DENY events in the last hour. They find a network deny for `api.suspicious.com` from sandbox `sb-abc123`. They want to see the full request context: which middleware evaluated it, what policy was active, what the agent was doing. But the OCSF event has no connection to the trace system. The reviewer has to manually search for the sandbox ID in Jaeger and hope the timestamps line up.

**What this RFC enables:** The OCSF event carries `trace_id` and `span_id` fields. The reviewer pastes the `trace_id` into Jaeger and lands directly on the supervisor's network span that produced the deny. They see the full egress path: Open Policy Agent (OPA) evaluation, L7 enforcement, middleware chain. One click from log to trace.

### Platform integrator: wiring OpenShell into an existing monitoring stack

A platform integrator is deploying OpenShell on a managed K8s cluster that already runs Prometheus, Grafana, and Tempo. They need OpenShell to emit traces to their Tempo endpoint and expose Prometheus metrics for their existing dashboards and alerts. Today, the Helm chart has no OTLP configuration values, no ServiceMonitor template, and the TOML config reference does not document the OTLP section.

**What this RFC enables:** The integrator sets `otlp.enabled=true` and `otlp.endpoint=http://tempo:4317` in the Helm values. They enable the ServiceMonitor and Prometheus starts scraping the gateway's `/metrics` endpoint. OpenShell traces appear in Tempo alongside their other services. The published docs at `docs/reference/gateway-config.mdx` document the configuration surface.

## Current state

Tracing coverage today is limited to the gateway and VM driver. Both gained OTLP trace export through three merged PRs, with a shared `openshell-otel` crate providing the common infrastructure. Everything else has no OTel integration. Tracing is configured through `[openshell.gateway.otlp]` in `gateway.toml`, where the table's presence acts as the on-switch.

| Component | OTLP Traces | W3C Propagation | Status |
|---|---|---|---|
| Gateway server | Per-request spans, gRPC conventions | Inbound + outbound to drivers | Merged ([#2534](https://github.com/NVIDIA/OpenShell/pull/2534)) |
| VM driver | Per-RPC spans, lifecycle ops | Receives from gateway | Merged ([#2564](https://github.com/NVIDIA/OpenShell/pull/2564)) |
| `openshell-otel` crate | Shared provider, layer, error helpers | `TraceContextInterceptor` | Merged ([#2567](https://github.com/NVIDIA/OpenShell/pull/2567)) |
| In-process drivers (K8s embedded/sidecar, Docker, Podman) | None | N/A (in-process) | Gap |
| CLI | None (not needed) | Passive `TRACEPARENT` forwarding proposed | Lightweight |

On the logging side, OCSF structured logging covers security events on both the sandbox side (network decisions, process lifecycle, security findings) and the gateway side (TLS events, service routing, policy operations). OCSF events have no connection to the trace system today.

For monitoring, the Prometheus wiring is in place: a `metrics` crate facade, a dedicated `/metrics` endpoint, and Helm chart port 9090 exposed. Basic gRPC/HTTP RED metrics and gateway interceptor metrics are implemented and working. The broader catalog proposed in [#909](https://github.com/NVIDIA/OpenShell/issues/909) (16 metric families, 3 priority tiers, SLI/SLO definitions) is mostly unimplemented. No Prometheus Operator ServiceMonitor CRDs, dashboards, or alerting rules exist.

## Proposal

### In-process driver instrumentation

The K8s, Docker, and Podman compute drivers run in-process within the gateway by default and inherit its tracing subscriber. K8s and Podman also have standalone gRPC binary entry points for external deployment, but the in-process path is the current default. What these drivers lack are explicit `#[tracing::instrument]` annotations that would create spans for driver operations like provisioning, teardown, status checks, and exec. The VM driver is the reference here, with 15 instrumented operations (9 via `#[tracing::instrument]`, 6 via `.instrument()`) and `ErrorStatusGuard` for error marking.

Because these drivers are in-process, they share the gateway's OTLP exporter and need no separate provider setup or W3C propagation. Instrument the `ComputeDriver` trait implementations in `crates/openshell-driver-kubernetes/`, `crates/openshell-driver-docker/`, and `crates/openshell-driver-podman/`, and the resulting spans appear as children of the gateway's request span automatically.

[#2507](https://github.com/NVIDIA/OpenShell/issues/2507) notes these drivers are expected to migrate to external gRPC services eventually, at which point they will need their own `SdkTracerProvider` and W3C propagation, but the in-process annotations are still the right starting point.

### CLI passive trace propagation

The CLI does not need its own OTel provider or OTLP export. The CLI runs on developer laptops, CI runners, and jump hosts where an OTel collector is typically not reachable, and the gateway already traces every incoming request. The gateway is the instrumentation boundary for platform tracing.

The one useful thing the CLI can do is passive `traceparent` propagation: if the CLI is invoked from a context that already has `TRACEPARENT` set (e.g., a CI pipeline with its own tracing), it should forward that context to the gateway via `TraceContextInterceptor` on the gRPC channel. This is a lightweight addition (no `SdkTracerProvider`, no collector configuration) that gives CI pipelines end-to-end trace continuity without imposing operational overhead on every CLI installation.

### OCSF-to-OTel correlation

When a trace context is active, OCSF events should include `trace_id` and `span_id` fields. This lets operators pivot between "I see a network deny in the security log" and "show me the trace that triggered it" (the security reviewer workflow above).

The OCSF builders already accept arbitrary fields via the `unmapped` mechanism. Add optional `trace_id`/`span_id` fields to the builder pattern, populated from the current `tracing::Span` when available. [#2508](https://github.com/NVIDIA/OpenShell/issues/2508) sub-issue 5 ("OCSF correlation") tracks this but has not defined the mechanism.

### Deployment configuration

Today, none of the deployment surfaces (Helm, Docker Compose, RPM) include OTLP configuration.

The gateway's `gateway.toml` needs an OTLP section:

```toml
[openshell.gateway.otlp]
endpoint = "http://otel-collector.monitoring:4317"
service_name = "openshell-gateway"
```

The Helm chart needs corresponding values that template into the ConfigMap:

```yaml
otlp:
  enabled: false
  endpoint: ""
  serviceName: "openshell-gateway"
```

When these values are set, the chart should also pass `OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_RESOURCE_ATTRIBUTES` as environment variables to the gateway container. Docker Compose's example `gateway.toml` should include a commented-out OTLP section. The published configuration reference at `docs/reference/gateway-config.mdx` needs to document the OTLP settings.

OpenShell is collector-agnostic. The Helm chart does not deploy an OTel Collector.

### Metrics maturity path

Metrics remain Prometheus-first. Priority order:

1. Complete P0 metrics from [#909](https://github.com/NVIDIA/OpenShell/issues/909) (supervisor sessions, sandbox phase, relay)
2. Add Prometheus Operator `ServiceMonitor` CRD to the Helm chart (gated, off by default)
3. P1 metrics (SSH, compute driver, DB, policy)
4. Dashboards and alerting rules
5. OTLP metrics push (opt-in complement for environments that cannot use pull-based collection)

## Non-goals

- Agent-level trace collection (covered in companion RFC 0014)
- OTel log export (OCSF and stdout are sufficient)
- Deploying an OTel Collector (the platform integrator owns the collector)
- TUI and router tracing (future items)
- Python SDK OTel hooks (tracked separately in [#1818](https://github.com/NVIDIA/OpenShell/issues/1818))

## Risks

The OpenTelemetry Rust SDK is a non-trivial dependency. Feature-gating it at compile time is worth evaluating (alongside [#1943](https://github.com/NVIDIA/OpenShell/issues/1943)) so that builds without OTel support do not pay the binary size and compile time cost.

Adding `#[tracing::instrument]` to driver operations has a small runtime cost (span allocation and export). On hot paths like sandbox status checks and exec, this cost should be measured to confirm it is acceptable.

The Prometheus Operator `ServiceMonitor` CRD must be installed in the cluster for the Helm chart's ServiceMonitor template to work. If the CRD is absent and the template is enabled, the Helm install will fail. The template should be gated behind a Helm value (off by default) with clear documentation.

## Open questions

- How should `OTEL_*` environment variables and TOML gateway configuration interact when both are set? [#2507](https://github.com/NVIDIA/OpenShell/issues/2507) and [RFC 0003](../0003-gateway-configuration/README.md) discuss this but no decision has been made on precedence.
- Should the OTel SDK dependency be gated behind a Cargo feature flag so that builds without tracing support do not pay the binary size and compile time cost?
- Per [#2507](https://github.com/NVIDIA/OpenShell/issues/2507), should `--metrics-port` auto-enable when the Helm chart wires the ServiceMonitor for Prometheus scraping?
