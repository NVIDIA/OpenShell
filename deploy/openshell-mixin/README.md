# OpenShell monitoring mixin

Reusable Grafana dashboards for OpenShell, packaged as a [monitoring mixin](https://monitoring.mixins.dev/). Render the mixin to dashboard JSON and import it into your Grafana instance. Configure collection and datasources in your own monitoring environment.

## Dashboards

| Dashboard | Datasources | Purpose |
| --- | --- | --- |
| OpenShell operational health | Prometheus; optional Tempo | Gateway readiness, RPC/HTTP traffic and latency, supervisor sessions, routing, relay pressure, and mutation locks |
| OpenShell operational logs | Loki | Gateway, supervisor, and workload diagnostics |
| OpenShell OCSF logs | Loki | Structured security and audit events from gateways and supervisors |

Dashboard UIDs and panel IDs remain stable across renders. Datasource variables are visible and independently selectable. Credentials, tenant headers, datasource provisioning, and Grafana folders belong in the consuming environment.

## Render and import

From the repository root, render the dashboards with mise:

```shell
mise run monitoring:generate
```

The tasks declare Go **1.26.7**, Go Jsonnet and jsonnetfmt **v0.22.0**, plus jsonnet-bundler **v0.6.0**, as task-specific tools. Mise installs them when needed. Generation and tests first run `jb install` using the committed dependency lockfile. Grafonnet is pinned to revision `8de2f3c83a38f68085c239df979f57d8dfdb7588` (the `grafonnet-latest` entry point at that revision uses the Grafana 13.0.0 API).

Import the JSON files from `deploy/openshell-mixin/build/dashboards/` through Grafana's dashboard import screen, or use your existing Grafana file provisioning, API, or Kubernetes sidecar workflow. Select the appropriate metrics, logs, and optional traces datasource in each dashboard, then choose the cluster and gateway instance.

Files under `dashboards/` construct dashboards with Grafonnet in `.libsonnet` modules. Import the rendered JSON from `build/dashboards/`. Queries are built directly from configuration; there is no token substitution.

The standard mixin exports are `grafanaDashboards`, `prometheusAlerts`, and `prometheusRules`. The two rule exports contain empty groups; no alerts or recording rules are defined. `monitoring:generate` writes their YAML alongside the dashboard directory, but they need not be installed.

## Customize

Defaults live in [config.libsonnet](config.libsonnet). Override `_config.openshell` in a consumer Jsonnet file. [examples/custom.jsonnet](examples/custom.jsonnet) demonstrates a different metric selector and cluster label, namespace regex, disabled traces, and datasource name filters:

```shell
MIXIN=examples/custom.jsonnet OUT=build/custom mise run monitoring:generate
```

`MIXIN` and `OUT` are relative to `deploy/openshell-mixin`; `OUT` also accepts an absolute path.

- `metricsMatchers` is a nonempty array of `{ name, operator, value }` objects. Supported operators are `=`, `!=`, `=~`, and `!~`. Names and operators are checked during rendering; string values are quoted and escaped. For example, `{ name: 'job', operator: '=~', value: 'gateway|openshell-gateway' }` selects either scrape job. Regex values must use valid Prometheus RE2 syntax.
- Metric and log label settings let you match your collection pipeline. Invalid label and TraceQL attribute identifiers fail during rendering.
- Regex values are escaped before insertion into queries. Datasource regexes match Grafana datasource names, not UIDs.
- Set `tracesEnabled: false` when Tempo is unavailable. This removes the trace panel and its datasource variable.

- `uidPrefix` defaults to an empty string. Set a different prefix for each copy of the mixin installed in the same Grafana instance. `dashboardUids` maps exported JSON filenames to alternative IDs before applying the prefix.
- `tags`, `refresh`, and `timezone` supply shared dashboard defaults; `ocsfTags` adds the OCSF dashboard's tags. Defaults remain `['openshell']`, `30s`, `browser`, and `['ocsf']` respectively. `dashboardOverrides` applies per-dashboard field overrides after the shared defaults, keyed by exported JSON filename.

Consumers do not need the OpenShell checkout or mise. Install the mixin with jsonnet-bundler, then render with Jsonnet:

```shell
jb init
jb install github.com/NVIDIA/OpenShell/deploy/openshell-mixin@COMMIT_SHA
mkdir -p dashboards
jsonnet -J vendor -m dashboards -e '(import "github.com/NVIDIA/OpenShell/deploy/openshell-mixin/mixin.libsonnet").grafanaDashboards'
```

Replace `COMMIT_SHA` with a published immutable revision containing this package. Import `github.com/NVIDIA/OpenShell/deploy/openshell-mixin/mixin.libsonnet` from the consumer's vendor directory and compose its exports into your existing monitoring resources, including kube-prometheus ConfigMaps where applicable.

Each dashboard module contributes `grafanaDashboards+::`. The final defaults layer exposes the standard dashboard export. Consumers can extend it with ordinary Jsonnet inheritance:

```jsonnet
(import 'github.com/NVIDIA/OpenShell/deploy/openshell-mixin/mixin.libsonnet') + {
  _config+:: { openshell+: { uidPrefix: 'prod-', refresh: '1m' } },
  grafanaDashboards+: {
    'openshell-operational-health.json'+: { title: 'Production OpenShell' },
  },
}
```

[examples/composed.jsonnet](examples/composed.jsonnet) changes a panel threshold, appends a Grafonnet panel with an explicit ID, changes dashboard defaults, and removes tracing panels and the trace variable. Preserve unique panel IDs when appending panels; arrays can be filtered or transformed using `super.panels` and `super.templating.list`.

```shell
MIXIN=examples/composed.jsonnet OUT=build/composed mise run monitoring:generate
```

## Collection requirements

| Signal | Required collection contract |
| --- | --- |
| Metrics | OpenShell gateway metrics, with default scrape job `openshell-gateway` and `cluster` / `instance` labels. Cluster discovery uses `openshell_server_readiness_database_healthy`. See the [gateway metrics reference](../../docs/observability/gateway-metrics.mdx) for emitted families. |
| Logs | Loki labels `k8s_cluster_name`, `k8s_namespace_name`, and `service_name`. Preserve `k8s_pod_name`, `log_iostream`, and `log_kind` as queryable metadata. Operational service names are `openshell-gateway`, `supervisor`, and `agent`. |
| OCSF | Preserve the event JSON body and supply `log_kind="ocsf"`, `sandbox_name`, `sandbox_id`, `ocsf_class_uid`, and `ocsf_severity_id` as queryable metadata when available. Collect events from both the gateway and supervisors. |
| Traces | Tempo spans with `resource.service.name="openshell-gateway"` and `resource.k8s.cluster.name`. Cluster values must match the metric cluster labels. Service and cluster attribute settings can be overridden. |

The default namespace regex is `openshell.*`. Map collection-specific labels, metadata, and service names to this contract or adjust the mixin configuration. Use consistent cluster values across metrics, logs, and traces.

RPC and HTTP summaries show weighted means, not aggregate p95. Streaming RPC completion durations include session lifetime. Mutation-lock histograms support the displayed fleet p95. Routed retries count as separate attempts; supervisor sessions are not sandbox counts. Missing observations remain absent. Threshold colors provide provisional operational guidance, not SLOs. OCSF class IDs include the emitted value `0`.

## Validate in your environment

The local checks use `uv`, with pinned `promql-parser==0.12.0`, to validate standard exports, dashboard identity, datasource references, portability, composition, configuration overrides, and generated PromQL syntax. A consumer integration test snapshots the current package into a temporary Git repository, runs a real `jb install` into a fresh consumer, and renders through `vendor/github.com/NVIDIA/OpenShell/deploy/openshell-mixin/`. Git URL rewriting directs only that package to the local fixture; Grafonnet dependencies are installed from the pinned manifests. These checks require Git and network access for dependency installation:

```shell
mise run monitoring:check
```

Branch Checks runs `mise run monitoring:check` when files in `deploy/openshell-mixin/` change. Manual Branch Checks runs always include it.

Users validate queries and visual behavior against their own collection pipeline and Grafana version:

1. Confirm cluster and instance selectors populate from the intended deployment.
2. Generate representative gateway and sandbox activity, then check readiness, request rates, latency, and supervisor sessions.
3. Confirm operational logs and gateway/supervisor OCSF events appear with the expected metadata filters.
4. If traces are enabled, open a gateway trace from the trace table and confirm the cluster matches.
5. Investigate query errors and missing data before treating a panel as evidence of health. Exercise failure paths separately; an empty error series does not prove those paths work.

`monitoring:check` checks formatting, runs the structural tests, and renders the default mixin. Use `monitoring:format` to format Jsonnet files, or run `monitoring:format:check` and `monitoring:test` individually. These tasks do not start a telemetry stack or execute live backend queries.
