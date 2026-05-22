---
name: test-release-canary
description: Manually dispatch and iterate on the Release Canary workflow that smoke-tests published OpenShell artifacts (install.sh on macOS/Ubuntu/Fedora, Helm chart on kind) after each Release Dev publish. Use when changing `.github/workflows/release-canary.yml`, validating a release before tagging, debugging a canary failure, or reproducing a canary job locally. Trigger keywords - release canary, release-canary, canary failed, canary dispatch, test release canary, post-release smoke, install.sh canary, helm chart canary, kind canary, dispatch canary.
---

# Test Release Canary

The Release Canary (`.github/workflows/release-canary.yml`) smoke-tests the artifacts a `Release Dev` run just published. It is the last automated checkpoint before tagging a public release: if the canary is red, the published `dev` artifacts do not install on a stock environment.

## What the canary verifies

| Job | Runner | Verifies |
|---|---|---|
| `macos` | `macos-latest-xlarge` | `install.sh` resolves the Homebrew formula, brew installs the cask, and `openshell status` reaches the brew-services–backed local gateway with the VM driver. |
| `ubuntu` | `ubuntu-latest` | `install.sh` installs the Debian package, the post-install systemd user service starts, and `openshell status` reaches the local gateway with the Docker driver. |
| `fedora` | `fedora:latest` container | `install.sh` installs the RPM packages, the local gateway starts under Podman, and `openshell status` succeeds. |
| `kubernetes` | `ubuntu-latest` + kind | `helm install oci://ghcr.io/nvidia/openshell/helm-chart --version 0.0.0-dev` succeeds in a kind cluster, the gateway pod becomes Ready, port-forward exposes 8080, and the released CLI registers the in-cluster gateway and runs `openshell status` against it. |

`install.sh` defaults to the *latest tagged* release — the canary is therefore checking that the most recent public release still installs, not the just-published `dev` build. The `kubernetes` job is the exception: it pins to `0.0.0-dev` chart + `:dev` images.

## Trigger paths

The workflow has two triggers:

```yaml
on:
  workflow_dispatch:
  workflow_run:
    workflows: ["Release Dev"]
    types: [completed]
```

- **Automatic.** Every successful `Release Dev` run (on `main` or a manual dispatch of Release Dev) fires the canary. Each job gates on `github.event.workflow_run.conclusion == 'success'` so a failed Release Dev does not run the canary.
- **Manual.** `workflow_dispatch` lets you run the canary on demand against any branch's workflow definition.

When dispatched manually, `github.event.workflow_run.head_sha` is empty and the workflow falls back to `github.sha` (the branch tip) for the `install.sh` URL.

## Manual dispatch

Run the canary as-is on the current branch:

```shell
gh workflow run release-canary.yml --ref "$(git branch --show-current)"
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

When you change `release-canary.yml` on a branch, a manual dispatch on that branch tests *your branch's workflow logic* against *main's published artifacts* (`0.0.0-dev` chart, `:dev` images, latest tagged install.sh assets). This is what you want for iterating on the canary — you're validating that the canary still works against known-good artifacts.

Note `install.sh` is pulled from `raw.githubusercontent.com/NVIDIA/OpenShell/${head_sha}/install.sh`, so changes to `install.sh` on your branch *are* exercised even though the binaries it downloads are from the latest public tag.

## Testing artifacts from a specific SHA

`Release Dev` publishes two chart versions for every dev build (see `.github/actions/release-helm-oci/action.yml:89-102`):

- `oci://ghcr.io/nvidia/openshell/helm-chart:0.0.0-dev` — floating, overwritten on every main push.
- `oci://ghcr.io/nvidia/openshell/helm-chart:0.0.0-dev.<sha>` — immutable, `appVersion` set to the same SHA so it pulls `ghcr.io/nvidia/openshell/gateway:<sha>` and `:supervisor:<sha>`.

To smoke-test the chart for a specific dev build, dispatch `Release Dev` on the branch first, then run the kind canary steps locally pointed at the SHA-pinned chart (see "Local kind reproduction" below). The release-canary workflow itself does not currently expose `chart_version` / `image_tag` inputs.

## Local kind reproduction

The `kubernetes` job can be reproduced on any machine with Docker and `mise install`-provided `kubectl` + `helm`:

```shell
kind create cluster --name release-canary-local

helm install openshell oci://ghcr.io/nvidia/openshell/helm-chart \
  --version 0.0.0-dev \
  --namespace openshell --create-namespace \
  --set server.disableTls=true \
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
| `macos`/`ubuntu`/`fedora` job fails on `install.sh` | Latest tagged release missing an asset, checksum mismatch, or `install.sh` regression on this branch. | Job log around the `curl … install.sh \| sh` step. |
| `macos`/`ubuntu`/`fedora` job fails on `openshell status` | Local gateway service did not start (systemd/brew/podman). Often a driver issue. | Service logs in the job log; `OPENSHELL_DRIVERS` env in the "Ensure …" step. |
| `kubernetes` job fails on `helm install --wait` | Chart did not deploy in 5 min — usually image pull failure or readiness probe failing. | "Diagnostics on failure" step dumps `helm status`, manifest, pod describe, pod logs. |
| `kubernetes` job fails on `kubectl wait` | Gateway pod stuck `CrashLoopBackOff` or `ImagePullBackOff`. | Diagnostics dump; check `:dev` image existence at `ghcr.io/nvidia/openshell/gateway`. |
| `kubernetes` job fails on `openshell gateway add` or `status` | Port-forward not reachable, or CLI/gateway proto mismatch. | `port-forward.log` and `openshell gateway list` in the diagnostics dump. |

The `kubernetes` job's diagnostics step (only runs `if: failure()`) emits, in order: helm status, rendered manifest, `kubectl get all`, pod descriptions, pod logs (200 lines per container), port-forward log, gateway list, CLI version. Read it top-to-bottom — most failures fall out by the manifest or pod logs.

## Related

- `helm-dev-environment` skill — local k3d-based dev environment (more featureful than the canary's kind cluster, but uses Skaffold-built local images, not published artifacts).
- `watch-github-actions` skill — generic `gh run` workflow monitoring.
- `debug-openshell-cluster` skill — runtime gateway/sandbox diagnostics that pair with the kind job's diagnostics dump.
