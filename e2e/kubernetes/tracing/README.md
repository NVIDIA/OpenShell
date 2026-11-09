# Kubernetes trace receipt

This focused lane completes the collector-validation part of #3767. The missing
collector configuration fix is already covered by #5348.

Run the checker controls without a cluster:

```shell
uv run --no-project python -m unittest discover -s e2e/kubernetes/tracing -p '*_test.py'
```

Build the CLI, select a **disposable** kind or k3d test cluster with the supported
Agent Sandbox controller, and run:

```shell
OPENSHELL_E2E_KUBE_CONTEXT=kind-my-test-cluster \
  OPENSHELL_BIN="$PWD/target/debug/openshell" \
  IMAGE_TAG=<full-source-commit> \
  mise run e2e:kubernetes:tracing
```

The existing gateway harness installs and removes its test gateway in the
`openshell` namespace. It must not target a working installation. Use matching
gateway, supervisor, and sandbox images; a floating `latest` or `dev` tag
does not establish exact-source validation.

The lane installs OpenTelemetry Collector Contrib 0.164.0 in a fresh namespace,
waits for its OTLP/gRPC receiver, then enables export only for the test gateway.
The collector writes newline-delimited OTLP JSON to its container output through
the file exporter. It has no service-account token, drops all capabilities, and
uses a read-only root filesystem. The fixture runs as UID 0 to reopen the runtime
stdout pipe; it is intended for disposable kind/k3d CI clusters, not restricted
OpenShift namespaces or production deployments.

A successful probe creates a sandbox and executes a small command. Receipt
requires all of:

- Gateway `openshell.v1.OpenShell/CreateSandbox`.
- Kubernetes driver `openshell.compute.v1.ComputeDriver/ValidateSandboxCreate`,
  sharing the gateway request's trace ID.
- Kubernetes driver `openshell.compute.v1.ComputeDriver/CreateSandbox`.
- Expected service names, the unique test gateway identity, the Kubernetes
  compute-driver attribute, a nonempty service version, and valid nonzero IDs.

Only successful or unset span statuses qualify. Asynchronous provisioning need
not share the original gateway request's root. The dedicated fixture uses
always-on sampling so this check is deterministic; production sampling and
supervisor denial correlation remain separate tests.

The receipt deadline is 60 seconds after the workload probe succeeds. An absent
export, wrong service/resource identity, or broken validation context fails
clearly. Checker tests include those negative controls. Readiness alone cannot
pass the lane.

The parent runner also requires the probe's receipt file and independently
rechecks it against the captured collector data. A zero exit status from the
gateway harness cannot pass a run that never reached the probe.

Evidence under `results/kubernetes-tracing/<run-id>/` includes collector
configuration, Helm values, gateway harness output, collector logs, a receipt
summary, pod image IDs, and cleanup output. The collector namespace is removed
on success and failure, including handled SIGINT/SIGTERM cancellation. Harness
output is written as it arrives, so timeout diagnostics survive. On timeout or
cancellation, the runner terminates its process group, allows up to 180 seconds
for gateway teardown, then kills any remaining descendants. Collector cleanup
verifies the run's namespace ownership label before deleting it. Cleanup failures
are recorded and cannot turn a failed or cancelled run into a pass. SIGKILL,
host loss, or an unreachable Kubernetes API can still require manual cleanup;
the evidence records the namespace to inspect.

Collector receipt does not establish trace-backend
indexing, retention, loss-free delivery, or fleet reliability.
