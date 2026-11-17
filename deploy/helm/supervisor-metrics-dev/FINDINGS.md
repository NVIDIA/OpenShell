# Local experiment findings

Date: November 6, 2026. Base: `origin/main` at
`00f7ba72bf084d95c877c583882e7b376e3ea54b`. Branch:
`codex/supervisor-metrics-poc`. No commits from the previous scheduling branch
were included.

## Implementation

Dedicated and shared supervisors serve an opt-in Prometheus endpoint. Instrumentation
uses the existing Rust metrics facade and Prometheus exporter dependency.
The endpoint aggregates all hosted instances and includes existing OCSF export
counters when their exporters run. There are no per-sandbox or destination
labels, and metric publication does not depend on OTLP trace sampling.

The local Skaffold profile provisions a two-member supervisor pool, Prometheus
with Pod discovery, and Grafana with a 13-panel dashboard. All three OpenShell
images are built from this checkout. The monitoring storage is ephemeral.

## Source validation

- Focused metrics tests pass, covering assignment removal, identity label
  exclusion, policy success/rejection/runtime failure, unchanged snapshots,
  companion finding exclusion, handler cleanup, runtime EOF/drop accounting,
  and one initial TLS connection reused by eight concurrent requests.
- All 40 configuration reconciliation tests pass.
- Clippy passes for all targets of the three changed crates with warnings
  treated as errors.
- All 458 OpenShell Helm unit tests pass, including fourteen supervisor metrics tests.
- Supervisor scaling checks pass: replica counts and HPA tuning preserve the
  gateway configuration and supervisor Pod template.
- The dev chart passes Helm lint; Skaffold resolves the new profile.
- Prometheus accepts all 18 dashboard query expressions, and Grafana loads the
  provisioned dashboard successfully.

## Live validation

- The existing `kubernetes_shared_supervisor` isolation E2E passed on the final
  metrics-enabled image. It covered two concurrent sandbox instances with
  independent policies and credentials, stopping/restarting one without ending
  the other, and rejection of stale/unknown runtime routes.
- Two retained demo sandboxes generated allowed HTTP GETs, L4 destination
  denials, and HTTP POST denials from a read-only rule. A policy update became
  active and allowed the previously blocked destination.
- The upstream server returned HTTP 403 after that destination was allowed.
  OCSF and the metrics classified the request as allowed. Upstream application
  errors must remain distinct from OpenShell policy denials.
- A rolling replacement of both supervisor Pods preserved both workload Pod
  UIDs and the exact sleep process PIDs and start times. Fresh sandbox exec
  calls succeeded after adoption. This tested graceful recovery, not abrupt
  host loss or socket continuity.
- Live comparison found that the first transport-counter hook covered
  reconnections but missed initial channels. Moving it to boundary opening
  and adding a real TLS regression test fixed it. The final image reports two
  open runtime connections for the two retained sandboxes, including after
  the E2E's temporary sandboxes were removed.
- A fresh scrape connection from an unlabeled Grafana Pod was rejected by the
  supervisor NetworkPolicy while the labeled Prometheus collector scraped
  successfully. Removing the collector label did not terminate an existing
  scrape connection. Label revocation should not be treated as immediate
  connection termination.
- The final two-member pool reports both assignment streams connected. One
  member hosts both retained sandboxes (two supervising assignments and two
  open runtime connections); the other is idle. Scaling up adds placement
  capacity without automatically rebalancing existing assignments.
- A final snapshot recorded two successful policy activations, three HTTP
  method denials, and both L4 and HTTP allowed activity on the final image.
  All 18 queries from the live provisioned dashboard executed successfully.
  Exported label keys contained only metric/scrape identity plus bounded
  `phase`, `outcome`, `layer`, `path`, and histogram `le` labels.

Before the TLS follow-up, the active member exported 43 samples per scrape and the
idle member exported 28. Local Prometheus scrape durations were approximately
0.61–0.67 ms. Kubernetes reported 3 millicores / 59 MiB for the member hosting
two sandboxes and 1 millicore / 11 MiB for the idle member. These are individual
observations after testing, not measurements of incremental metrics overhead
or a production capacity estimate.

The experiment remains in k3d cluster `openshell-supervisor-metrics`:

- Grafana: <http://127.0.0.1:13000/d/openshell-supervisor-poc>
- Prometheus: <http://127.0.0.1:19090>
- Gateway: `https://127.0.0.1:18090`
- Demo sandboxes: `mp-1794002248-a` and `mp-1794002248-b`
- Temporary CLI configuration: `/tmp/openshell-metrics-config.zfd2jh0m`

Inspect this gateway without changing the normal CLI configuration:

```shell
XDG_CONFIG_HOME=/tmp/openshell-metrics-config.zfd2jh0m OPENSHELL_GATEWAY=supervisor-metrics openshell sandbox list
```

Loopback port-forward process IDs are recorded in
`/tmp/supervisor-metrics-session.json`; forwards must reconnect if their target
Pod is replaced. The setup guide registers exact cluster certificates through
the E2E helper: `gateway add --local` imported certificates from an unrelated
local Docker gateway during initial setup.

## TLS follow-up

The supervisor now supports opt-in HTTPS and mTLS. The local experiment uses
`supervisor.metrics.tls.enabled` with required scraper certificates and separate
metrics PKI. Prometheus validates the metrics server using a stable TLS server
name while discovering individual Pod IPs. The `supervisor-metrics-tls` Skaffold
profile preserves that configuration on subsequent builds; create its four
metrics Secrets first as described in the setup guide.

Eight supervisor metrics tests and twenty CLI regression tests pass. Transport
tests cover HTTPS, required and optional client authentication, wrong scraper
CAs, plaintext rejection, valid bundle rotation, and retention of the last valid
configuration after a bad replacement. Clippy passes with warnings denied.
The shared-supervisor isolation E2E also passes on the TLS-enabled image.

Live authentication checks confirmed:

- The metrics-specific scraper certificate receives HTTP 200.
- A missing client certificate is rejected.
- The gateway's control-plane client certificate is rejected.
- Plain HTTP on the metrics port is rejected.
- Prometheus reports healthy HTTPS/mTLS targets with server verification enabled.

An invalid key was temporarily projected through the real Kubernetes metrics
Secret. The reload worker detected it, and a fresh authenticated TLS connection
still received HTTP 200 using the previous configuration. The original key was
restored. A malformed initial configuration instead disables only metrics,
without falling back to plaintext; fixing it requires a supervisor restart.

The metrics PKI directory is recorded in `/tmp/supervisor-metrics-session.json`.
It contains private material and stays outside the checkout. The dev collector
Pod was replaced when HTTPS scraping was enabled, resetting its ephemeral history.

## Interpretation and limits

Assignment counts, runtime transport connections, and readiness represent
different observations. A transport can outlive its peer until I/O detects the
loss; replacement transports can briefly overlap. Instance cancellation during
removal can count as a failed termination, so that counter alone should not
become a production alert.

Policy validation rejections and runtime activation failures are distinct from
failed status reporting. An invalid policy rejected before supervisor delivery
does not test the supervisor rejection counter. The focused tests exercise
both failure outcomes without weakening gateway validation.

This experiment does not establish a production metric contract,
OTLP metric export, byte throughput, or a statistically controlled
overhead measurement. Those need separate decisions after inspecting the local
signals. The next useful reliability addition would be explicit update/status
delivery outcomes and measures of convergence time, with clear retry semantics.

## Dedicated mode support

The listener and TLS configuration now also work in dedicated mode. The single
instance publishes lifecycle phases and accepted gateway session readiness;
network, runtime transport, and policy metrics use the common instrumentation.
Shared-only admission counters remain zero in dedicated mode. The standalone
network-proxy role exposes network metrics with zero sandbox and gateway gauges.
The earlier live results above exercise shared mode. Dedicated mode was also
validated live on November 9, 2026, as described below.

### Live dedicated Kubernetes validation

Installed a separate gateway release in `openshell-metrics-dedicated` in the
existing `k3d-openshell-supervisor-metrics` cluster. It omits `supervisor_topology`
and uses the new dedicated metrics driver configuration. No Pod patching or
manual supervisor replacement was needed: the driver generated the listener
environment, Secret mounts, discovery label, named port, and ingress policy.
The existing shared release and unrelated clusters were left unchanged.

Two demo sandboxes, `mp-1794256686-a` and `mp-1794256686-b`, each have their own
supervisor Pod. Both Prometheus targets are healthy over verified HTTPS with
required scraper certificates. Each target reports one `supervising` sandbox,
one open runtime control transport, and gateway connectivity. The exercise
produced five HTTP denials, six HTTP allows, and one successful policy runtime
activation. L4 counters are separate decisions, not HTTP request counts.

A fresh direct connection using the metrics scraper identity returned HTTP 200.
Connections without a client certificate, with the gateway client identity, or
using plaintext HTTP were rejected. A fresh scrape from the unlabeled Grafana
Pod could not connect while the labeled Prometheus scraper remained healthy.
The Grafana dashboard loaded, and all 18 queries across 13 panels succeeded.

The first live launch exposed a missing NetworkPolicy PATCH permission. The
chart now grants PATCH only for this gateway's named metrics policy, and only
for dedicated mode with metrics enabled; broader network-policy permissions
were not added. Runtime control continues through its existing per-pair policy.
The driver skips dedicated metrics policy provisioning for shared topology.

Validation: all 334 Kubernetes driver library tests, all 467 gateway Helm tests,
driver Clippy across all targets, and dedicated/mTLS dev chart lint passed.
Live evidence is stored in `/tmp/dedicated-metrics-{live-results,auth-results,
networkpolicy-result,dashboard-result}.json`. Local forward/config metadata is
in `/tmp/dedicated-metrics-session.json`; it references private material outside
the checkout and must not be committed.

The retained dedicated dashboard is at
http://127.0.0.1:13002/d/openshell-supervisor-poc and Prometheus is at
http://127.0.0.1:19092/targets. Use the temporary gateway configuration from the
session metadata to delete the demo sandboxes. Remove the `dedicated-metrics`
release in `observability` and the `openshell` release in
`openshell-metrics-dedicated`, then remove that namespace, to tear down this
additional demo without affecting the shared one.

The final gateway image (`metrics-poc-dedicated-v2`) was rolled out after the
exercise. Both supervisor and workload Pods retained their UIDs, container
start times, and restart counts. Both metrics targets stayed healthy, gateway
sessions reconnected, and sandbox exec succeeded afterward. The final snapshot
is `/tmp/dedicated-metrics-final-results.json`.

This validates automatic Kubernetes provisioning. Docker, Podman, and VM driver
configuration still needs separate metrics deployment wiring; binary flag
support alone does not supply scraper reachability or certificate mounts.

## Parking review — November 17, 2026

Parked on `feat/5364-supervisor-metrics-poc/TaylorMutch`. The original local
experiment branch was `codex/supervisor-metrics-poc`. This branch preserves the
validated `00f7ba72b` base; it has not been rebased onto newer main changes.

Compared with `origin/main` at `d66d33844` (87 commits after that base). A dry
merge reports four content conflicts:

- `crates/openshell-driver-kubernetes/src/driver.rs`
- `crates/openshell-sandbox-backend/Cargo.toml`
- `crates/openshell-supervisor-network/src/telemetry.rs`
- `crates/openshell-supervisor/src/lib.rs`

Before turning this experiment into a PR, rebase and preserve main's dedicated
shutdown deadline and `shutdown_ends_process` behavior, attachment timeout
configuration, and Kubernetes RuntimeClass plumbing. Main now emits inspected
HTTP records through `emit_inspected_decision`; add metrics accounting there
as well as the legacy emission path. Preserve main's separate gateway
`metrics.enabled` setting and listener-port validation when integrating Helm.
Resolve dependency additions against main rather than replacing its manifests
or lockfile wholesale. These integration steps have not been validated here.

Fresh checks on the parked branch passed: 15 focused Rust metrics tests across
supervisor, network, and sandbox backend crates; all 467 gateway Helm tests;
dedicated/mTLS dev chart lint; Rust formatting; shell syntax; dashboard JSON
parsing; and Git whitespace checks. Reviewed all 51 experiment files for private
key material and common access-token patterns; runtime PKI and kubeconfig files
remain outside the commit. Earlier live validation is recorded above; the dev
cluster was not redeployed for this parking review.
