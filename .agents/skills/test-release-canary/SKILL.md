---
name: test-release-canary
description: Manually dispatch and iterate on the Release Canary workflow that smoke-tests published OpenShell artifacts (install.sh on macOS/Ubuntu/Fedora, Snap, and Helm on kind) after Release Dev and prerelease publications. Use when changing `.github/workflows/release-canary.yml`, validating a release before tagging, debugging a canary failure, or reproducing a canary job locally. Trigger keywords - release canary, release-canary, canary failed, canary dispatch, test release canary, post-release smoke, install.sh canary, helm chart canary, kind canary, dispatch canary.
metadata:
  internal: true
---

# Test Release Canary

The Release Canary (`.github/workflows/release-canary.yml`) smoke-tests published OpenShell artifacts. It runs after Release Dev and is also called by Release Tag after a prerelease candidate publishes. If the canary is red, the selected channel does not install on a stock environment.

## What the canary verifies

| Job | Runner | Verifies |
|---|---|---|
| `macos` | `macos-latest-xlarge` | Installs the selected Homebrew release, reaches the VM gateway, and creates, executes in, and deletes a sandbox. |
| `ubuntu` | `ubuntu-latest` | Installs the selected Debian package, reaches the Docker gateway, and creates, executes in, and deletes a sandbox. |
| `fedora` | `fedora:latest` container | Installs the selected RPM packages, reaches the Podman gateway, and creates, executes in, and deletes a sandbox. |
| `ubuntu-snap` | `ubuntu-latest` | Installs the Snap artifact from the calling release run, connects its interfaces, reaches the Docker gateway, and creates, executes in, and deletes a sandbox. |
| `kubernetes` | `ubuntu-latest` + kind | Installs the caller-selected Helm chart, reaches the in-cluster gateway, and creates, executes in, and deletes a sandbox using the published runtime images. |

All canary jobs disable anonymous OpenShell telemetry. Host package jobs inject
`OPENSHELL_TELEMETRY_ENABLED=false` through the service environment, and the
Kubernetes job installs with `server.telemetryEnabled=false`, so smoke traffic
does not contribute to product usage metrics.

After Release Dev, the workflow sets `OPENSHELL_VERSION=dev` and pins the
matching `0.0.0-dev` chart and `:dev` images. After a prerelease publication,
the caller supplies the rolling `pre-X.Y.Z` install channel and `<version>-pre`
Helm chart, so every job exercises the newly published candidate.

The host-package jobs exercise fresh installs, not upgrades from a persisted
schema-v1 gateway config. Validate Homebrew and RPM exact-default migration with
the release-tooling and package lifecycle tests before relying on the canary.

The canary does not install or import `@nvidia/openshell-sdk`. TypeScript SDK
validation lives in the `TypeScript SDK` branch check, including a publish
dry-run. The tagged release workflow publishes the package to GitHub Packages;
verify that job directly when diagnosing SDK publication failures.

## Trigger paths

The workflow has three triggers:

```yaml
on:
  workflow_call:
  workflow_dispatch:
  workflow_run:
    workflows: ["Release Dev"]
    types: [completed]
```

- **Automatic.** Every successful `Release Dev` run (on `main` or a manual dispatch of Release Dev) fires the canary. Each job gates on `github.event.workflow_run.conclusion == 'success'` so a failed Release Dev does not run the canary.
- **Reusable.** A successful prerelease publication in Release Tag calls the canary with its rolling install channel, floating Helm version, and release run ID. This smoke-tests Debian, RPM, Homebrew, Snap, and Helm after publication.
- **Manual.** `workflow_dispatch` lets you run the canary on demand against any branch's workflow definition. To include `ubuntu-snap`, supply `release-dev-run-id` for a successful Release Dev run whose Snap artifact should be tested; without it, that job is skipped because no artifact is available.

When dispatched manually, `github.event.workflow_run.head_sha` is empty and the workflow falls back to `github.sha` (the branch tip) for the `install.sh` URL.

## Manual dispatch

Run the canary as-is on the current branch:

```shell
gh workflow run release-canary.yml --ref "$(git branch --show-current)"
```

To exercise the Ubuntu Snap job, pass the successful Release Dev run ID:

```shell
gh workflow run release-canary.yml --ref "$(git branch --show-current)" \
  -f release-dev-run-id=<release-dev-run-id>
```

Watch the run that starts:

```shell
sleep 5  # let GitHub register the dispatch
gh run list --workflow release-canary.yml --limit 1
gh run watch "$(gh run list --workflow release-canary.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```

View only failed jobs after completion:

```shell
gh run view <run-id> --log-failed
```

## Iterating on the canary itself

When you change `release-canary.yml` on a branch, a manual dispatch on that branch tests *your branch's workflow logic* against *main's published dev artifacts* (`0.0.0-dev` chart, `:dev` images, and the `dev` GitHub release). This is what you want for iterating on the canary — you're validating that the canary still works against known-good artifacts.

Note `install.sh` is pulled from `raw.githubusercontent.com/NVIDIA/OpenShell/${head_sha}/install.sh`, so changes to `install.sh` on your branch *are* exercised even though the binaries it downloads are from the latest public tag.

## Testing artifacts from a specific SHA

`Release Dev` publishes two chart versions for every dev build (see `.github/actions/release-helm-oci/action.yml:89-102`):

- `oci://ghcr.io/nvidia/openshell/helm-chart:0.0.0-dev` — floating, overwritten on every main push.
- `oci://ghcr.io/nvidia/openshell/helm-chart:0.0.0-dev.<sha>` — immutable, `appVersion` set to the same SHA so it pulls the matching `gateway`, `sandbox`, and `supervisor` images.

To smoke-test the chart for a specific dev build, dispatch `Release Dev` on the branch first, then run the kind canary steps locally pointed at the SHA-pinned chart (see "Local kind reproduction" below). Reusable callers can select a published chart with the `chart-version` input and its matching CLI release with `install-version`.

## Local kind reproduction

The `kubernetes` job can be reproduced on any machine with Docker and `mise install`-provided `kubectl` + `helm`:

```shell
kind create cluster --name release-canary-local

bash e2e/support/install-agent-sandbox.sh

helm install openshell oci://ghcr.io/nvidia/openshell/helm-chart \
  --version 0.0.0-dev \
  --namespace openshell --create-namespace \
  --set server.disableTls=true \
  --set server.telemetryEnabled=false \
  --wait --timeout 5m

kubectl wait --namespace openshell \
  --for=condition=Ready pod \
  --selector="app.kubernetes.io/name=openshell,app.kubernetes.io/instance=openshell" \
  --timeout=300s

kubectl port-forward --namespace openshell svc/openshell 8080:8080 &
openshell gateway add http://127.0.0.1:8080 --local --name kind
openshell status
```

Keep `pkiInitJob.enabled=true` (the chart default), even when
`server.disableTls=true`. The hook also generates the sandbox JWT signing
secret that the gateway pod always mounts.

Swap `0.0.0-dev` for `0.0.0-dev.<sha>` to pin to a specific dev build. Tear down with `kind delete cluster --name release-canary-local`.

Loopback registration auto-derives the gateway name to `openshell` if `--name` is omitted, which collides with the `install.sh`-installed local gateway — always pass `--name kind` (or another distinct name) when registering in addition to a local install.

## Diagnosing failures

| Symptom | Likely cause | Where to look |
|---|---|---|
| `macos`/`ubuntu`/`fedora` job fails on `install.sh` | Dev release missing an asset, checksum mismatch, or `install.sh` regression on this branch. | Job log around the `curl … install.sh \| sh` step. |
| Sandbox create or exec fails | Published sandbox and supervisor artifacts are missing, incompatible, or cannot establish the protected runtime channel. | Gateway logs plus Docker, Podman, VM, Snap, or Kubernetes runtime diagnostics for the job. |
| `macos`/`ubuntu`/`fedora` job fails on `openshell status` | Local gateway service did not start (systemd/brew/podman). Often a driver issue. | Service logs in the job log; `OPENSHELL_COMPUTE_DRIVER` env in the "Ensure …" step. |
| `ubuntu-snap` fails after interface connection | The gateway did not recover after Docker became available, or did not become reachable within the 30-second bound. | Failure diagnostics dump Snap service/connection/change state, gateway and snapd journals, Snap logs, and port 17670 listeners. |
| `kubernetes` job fails on `helm install --wait` | Chart did not deploy in 5 min — usually image pull failure or readiness probe failing. | "Diagnostics on failure" step dumps `helm status`, manifest, pod describe, pod logs. |
| `kubernetes` job fails on `kubectl wait` | Gateway pod stuck `CrashLoopBackOff` or `ImagePullBackOff`. | Diagnostics dump; check `:dev` image existence at `ghcr.io/nvidia/openshell/gateway`. |
| `kubernetes` job fails on `openshell gateway add` or `status` | Port-forward not reachable, or CLI/gateway proto mismatch. | `port-forward.log` and `openshell gateway list` in the diagnostics dump. |

The `kubernetes` job's diagnostics step (only runs `if: failure()`) emits, in order: helm status, rendered manifest, `kubectl get all`, pod descriptions, pod logs (200 lines per container), port-forward log, gateway list, CLI version. Read it top-to-bottom — most failures fall out by the manifest or pod logs.

## Related

- `helm-dev-environment` skill — local k3d-based dev environment (more featureful than the canary's kind cluster, but uses Skaffold-built local images, not published artifacts).
- `watch-github-actions` skill — generic `gh run` workflow monitoring.
- `debug-openshell-cluster` skill — runtime gateway/sandbox diagnostics that pair with the kind job's diagnostics dump.
