# Supervisor metrics experiment

This local proof of concept adds an opt-in Prometheus listener to dedicated and
shared supervisors. It provisions Prometheus and Grafana with ephemeral storage and
six hours of metric retention. It does not export OTLP metrics or forward
workload metrics through the agent trace relay.

From the repository root, create a separate dev cluster:

```shell
HELM_K3S_CLUSTER_NAME=openshell-supervisor-metrics HELM_K3S_LB_HOST_PORT=18080 \
  mise run helm:k3s:create
cd deploy/helm/openshell
KUBECONFIG=../../../kubeconfig mise exec -- skaffold run -p supervisor-metrics \
  --kube-context k3d-openshell-supervisor-metrics
cd ../../..
```

The profile builds all three OpenShell images, enables the two-member shared
supervisor pool and gateway TLS, and installs this dev chart in `observability`.
Prometheus discovers each supervisor Pod's named metrics port. Discovery is
restricted to the configured gateway namespace and Helm release.

Forward the UIs in separate terminals:

```shell
KUBECONFIG=kubeconfig mise exec -- kubectl --context k3d-openshell-supervisor-metrics -n observability port-forward \
  service/supervisor-metrics-grafana 13000:3000 --address 127.0.0.1
```

```shell
KUBECONFIG=kubeconfig mise exec -- kubectl --context k3d-openshell-supervisor-metrics -n observability port-forward \
  service/supervisor-metrics-prometheus 19090:9090 --address 127.0.0.1
```

Open [the dashboard](http://127.0.0.1:13000/d/openshell-supervisor-poc)
or [Prometheus targets](http://127.0.0.1:19090/targets). Grafana permits anonymous
viewing for this local experiment. Neither UI has an Ingress or external Service.
Both services remain reachable within the dev cluster.

Forward the gateway in another terminal:

```shell
KUBECONFIG=kubeconfig mise exec -- kubectl --context k3d-openshell-supervisor-metrics -n openshell port-forward \
  service/openshell 18090:8080 --address 127.0.0.1
```

Register this gateway in a separate temporary CLI configuration directory so
the experiment does not change the active gateway or certificates in your
usual configuration. Run the following in the shell used for the exercise:

```shell
export XDG_CONFIG_HOME=$(mktemp -d /tmp/openshell-metrics-config.XXXXXX)
pki_dir="$XDG_CONFIG_HOME/pki"
mkdir -p "$pki_dir/client"
for key in ca.crt tls.crt tls.key; do
  secret=openshell-client-tls
  destination="$pki_dir/client/$key"
  if [ "$key" = ca.crt ]; then
    secret=openshell-server-tls
    destination="$pki_dir/ca.crt"
  fi
  KUBECONFIG=kubeconfig mise exec -- kubectl --context k3d-openshell-supervisor-metrics \
    -n openshell get secret "$secret" \
    -o "go-template={{index .data \"$key\"}}" | base64 -d \
    > "$destination"
done
source e2e/support/gateway-common.sh
e2e_register_mtls_gateway "$XDG_CONFIG_HOME" supervisor-metrics \
  https://127.0.0.1:18090 18090 "$pki_dir"
chmod 600 "$pki_dir/client/tls.key"
chmod 600 "$XDG_CONFIG_HOME/openshell/gateways/supervisor-metrics/mtls/tls.key"
export OPENSHELL_GATEWAY=supervisor-metrics
```

```shell
bash deploy/helm/supervisor-metrics-dev/exercise.sh
```

Keep this temporary configuration path while inspecting the experiment; remove
it after deleting the sandboxes and cluster. It contains the local gateway's
client private key and must not be committed or shared.
The dev helper registers these exact certificates; `gateway add --local` can
instead import certificates from an unrelated local Docker gateway.

The exercise creates two uniquely named sandboxes using the E2E harness's pinned
Python workload image, generates allowed and denied HTTP traffic, changes a
network policy, and verifies that the previously denied host is allowed. It needs
access to example.com and example.org. Override `OPENSHELL_METRICS_DEMO_IMAGE` to
use another image with uv and Python. Upstream HTTP errors remain distinct from
OpenShell policy denials. It leaves the sandboxes running and prints
their deletion commands so their state stays visible in the dashboard.

## HTTPS and mTLS scraping

The main chart accepts `supervisor.metrics.tls.enabled`, `certSecretName`,
`clientCaSecretName`, and `requireClientCert`. TLS stays opt-in. Use a dedicated
metrics server Secret; supervisors must not mount the gateway API's private
key or a gateway client identity. The scraper CA must also be independent of
gateway control-plane trust. The chart checks Secret names; operators must
keep the underlying materials separate too.

For this local experiment, generate a separate metrics PKI through the gateway
certificate command, then create the server and scraper Secrets. This uses a
fresh CA, not the gateway's API CA:

```shell
metrics_pki=$(mktemp -d /tmp/openshell-metrics-pki.XXXXXX)
mise exec -- target/debug/openshell-gateway generate-certs --output-dir "$metrics_pki" \
  --server-san openshell-supervisor.openshell.svc.cluster.local
export KUBECONFIG="$PWD/kubeconfig"
mise exec -- kubectl --context k3d-openshell-supervisor-metrics -n openshell create secret tls \
  supervisor-metrics-server-tls --cert="$metrics_pki/server/tls.crt" --key="$metrics_pki/server/tls.key"
mise exec -- kubectl --context k3d-openshell-supervisor-metrics -n openshell create secret generic \
  supervisor-metrics-client-ca --from-file=ca.crt="$metrics_pki/ca.crt"
mise exec -- kubectl --context k3d-openshell-supervisor-metrics -n observability create secret generic \
  supervisor-metrics-server-ca --from-file=ca.crt="$metrics_pki/ca.crt"
mise exec -- kubectl --context k3d-openshell-supervisor-metrics -n observability create secret tls \
  supervisor-metrics-client-tls --cert="$metrics_pki/client/tls.crt" --key="$metrics_pki/client/tls.key"
mise exec -- helm upgrade openshell deploy/helm/openshell --kube-context k3d-openshell-supervisor-metrics \
  -n openshell --reuse-values -f deploy/helm/openshell/ci/values-supervisor-metrics-tls.yaml --wait
mise exec -- helm upgrade supervisor-metrics deploy/helm/supervisor-metrics-dev \
  --kube-context k3d-openshell-supervisor-metrics -n observability --reuse-values \
  -f deploy/helm/supervisor-metrics-dev/values-tls.yaml --wait
```

The native gateway binary must be built, and the deployed supervisor image must
include this branch's TLS flags. The certificate output contains a CA private
key; retain it only in the temporary directory, outside the checkout. The
chart uses operator-provided Secrets and does not generate metrics PKI.
The collector upgrade replaces its Pod and clears the dev chart's ephemeral
history. Restart its loopback port-forward afterward.

For subsequent Skaffold builds, select `supervisor-metrics-tls` so both releases
keep their TLS configuration. It uses the same four pre-created Secrets:

```shell
cd deploy/helm/openshell
KUBECONFIG=../../../kubeconfig mise exec -- skaffold run -p supervisor-metrics-tls \
  --kube-context k3d-openshell-supervisor-metrics
```

Prometheus discovers Pod IPs but verifies the certificate using the stable
`server_name` above. It supplies its metrics-specific client certificate and
keeps server verification enabled. For HTTPS without client auth, omit the
supervisor `clientCaSecretName`, set `requireClientCert: false`, and clear
`prometheus.tls.clientSecretName` while retaining its CA and server name.

Invalid initial material disables metrics without affecting supervision and
never falls back to HTTP. Correct the files and restart the supervisor. An
active listener reloads valid material every five seconds and retains its last
valid configuration on an invalid replacement; new connections use the current
configuration. Missing Secrets fail Kubernetes volume mounting before startup.

The binary supports the same listener and TLS flags in dedicated mode. The
Helm `supervisor.metrics` values now also configure dedicated Kubernetes Pods:
the driver supplies the environment, metrics Secret mounts, named port,
discovery label, and scraper NetworkPolicy. Provision metrics Secrets in every
sandbox namespace. Listener settings apply to newly created supervisors.

For a gateway using dedicated supervisors (omit `supervisor_topology`), install
another instance of this dev chart with `values-dedicated.yaml` and, for mTLS,
`values-tls.yaml`. Set `supervisorNamespace` and `supervisorGatewayID` to match
the gateway. Dedicated discovery selects `openshell.ai/supervisor-metrics=enabled`
and the gateway ID; shared discovery selects the Deployment's Helm labels.
Discovery RBAC is limited to the configured namespace. For managed workspaces,
provision metrics Secrets and discovery permissions in every workspace namespace.
No per-sandbox metrics Service or public Ingress is needed.

```shell
KUBECONFIG=kubeconfig mise exec -- helm upgrade --install dedicated-metrics \
  deploy/helm/supervisor-metrics-dev --kube-context k3d-openshell-supervisor-metrics \
  -n observability -f deploy/helm/supervisor-metrics-dev/values-dedicated.yaml \
  -f deploy/helm/supervisor-metrics-dev/values-tls.yaml
```

This example expects a dedicated gateway named `openshell` in
`openshell-metrics-dedicated`, with metrics enabled using the main chart's TLS
overlay. The server and scraper Secrets described above must already exist in
the relevant namespaces. Change the discovery namespace, gateway ID, and TLS
server name when using another release or certificate. The live dedicated
validation and UI addresses are recorded in `FINDINGS.md`.


## Metric semantics

All experimental supervisor metrics use the `openshell_supervisor_` prefix.
Prometheus supplies `pod`, `namespace`, and scrape identity. Instrumentation
labels contain only bounded phases, outcomes, layers, and paths. No sandbox
IDs, destinations, policy hashes, credentials, or error strings enter labels.

| Suffix | Meaning |
| --- | --- |
| `sandboxes{phase}` | Shared: latest assignment status, including deferred/rejected assignments; dedicated: the single sandbox lifecycle |
| `runtime_connections` | Currently open Sandbox Protocol control transports after boundary opening, excluding mediation streams |
| `runtime_connections_total`, `runtime_disconnects_total` | Successful control transport openings and closures; replacements and recoveries count too |
| `gateway_connected` | Shared: assignment stream accepted; dedicated: sandbox session accepted and ready, 0 or 1 |
| `gateway_connection_attempts_total` | Initial connection attempts plus retries |
| `network_decisions_total{layer,outcome}` | L4/HTTP domain allow/deny records; companion security findings excluded |
| `network_failures_total{layer}` | Domain failure records excluding denials |
| `upstream_connect_errors_total{path}` | Failed authorized upstream dials, including corporate proxy failures |
| `proxy_connections{path}` | Active proxy client handlers, including setup, policy evaluation, and relaying |
| `policy_updates_total{outcome}` | Runtime activation attempts: success/runtime_failure; gateway validation rejections: validation_rejected |
| `policy_update_duration_seconds{outcome}` | Atomic runtime activation duration, excluding gateway polling and status reporting |
| `settings_poll_failures_total` | Failed settings polls; pushed updates are not polls |
| `admission_failures_total` | Failed pool assignment admission attempts; ordinary deferrals excluded |
| `instance_terminations_total{outcome}` | Hosted instance endings: exited/nonzero_exit/failed; cancellation during removal can count as failed |

Policy runtime activation can include provider or middleware changes. Unchanged
polls do not count as activations. Repeated rejected deliveries and retry attempts
count again. Initial policy loading before reconciliation is not an update.
Activation success does not imply that its acknowledgment reached the gateway.

A runtime connection measures transport liveness observed through I/O, EOF,
replacement, and destruction. An unreachable peer can remain counted until the
transport detects its loss. It does not assert that the sandbox is ready.
Transport replacements can briefly overlap; this is a connection count rather
than a count of unique sandbox identities.

L4 and HTTP decisions are different layers and should not be added together as a
request count. Operational network failures and upstream dial failures can
describe the same incident; do not sum them. Metrics are attached to domain event
emission and are independent of trace sampling or log export success.

Core counters start at zero; histograms and OCSF exporter counters appear after
their first event. A blank latency/export panel can mean no event has happened
yet. Process restarts reset counters. Use `rate`/`increase` per Pod
before aggregating. `up=0` distinguishes scrape failure from a reported zero;
deleted Pods eventually disappear from discovery entirely.

Existing `openshell_ocsf_otlp_*` exporter counters become visible when those
exporters run inside a process with this recorder. They measure OCSF exports,
not metric delivery. The dev profile does not require OCSF export to be enabled.

## Evaluation

1. Verify two healthy targets and compare sandbox assignment counts with live
   runtime connections while creating and deleting the demo sandboxes.
2. Verify L4/HTTP allow and deny activity and policy activation success.
3. Exercise policy validation rejection and runtime activation failure in the
   focused configuration-runtime tests. A malformed policy rejected at CLI/API
   intake does not necessarily reach a supervisor and should not be claimed as
   a supervisor rejection.
4. Restart the supervisor Deployment in this isolated cluster. Confirm scrape
   gaps, instance recovery on the surviving member, and new process counters.
   Existing streams may break; retry a fresh sandbox exec afterward.
5. Record the same repeated workload with metrics disabled and enabled, then
   compare request duration and supervisor CPU/memory. Do not infer an overhead
   percentage from successful scrapes alone.

Run focused Rust tests with `mise exec -- cargo test -p openshell-supervisor
-p openshell-supervisor-network -p openshell-sandbox-backend --lib metrics`.
Run the shared supervisor E2E task with the metrics overlay in
`OPENSHELL_E2E_KUBE_EXTRA_VALUES` to check that metrics do not change sandbox
behavior. Keep any failure injection scoped to this disposable cluster.

The listener is disabled by default and uses plaintext unless TLS is enabled. When enabled, the shared
supervisor NetworkPolicy permits its port only from labeled collector Pods in
`supervisor.metrics.scraperNamespace`. Disabling NetworkPolicy removes that
restriction. Production monitoring integration, alerts, byte throughput, detailed
per-sandbox views, and OTLP metric export remain future work.

Delete the profile's releases with Skaffold, or remove this experiment's entire
cluster after inspection:

```shell
HELM_K3S_CLUSTER_NAME=openshell-supervisor-metrics mise run helm:k3s:delete
```
