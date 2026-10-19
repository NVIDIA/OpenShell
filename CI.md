# CI

This document describes how OpenShell's continuous integration works for pull requests, with a focus on what contributors need to do to get their PR tested.

For local test commands see [TESTING.md](TESTING.md). For PR conventions see [CONTRIBUTING.md](CONTRIBUTING.md).

## Overview

PR CI that runs candidate code on NVIDIA self-hosted runners requires an
exact-revision approval. A maintainer with Write, Maintain, or Admin access
reviews the current revision and comments `/ok to test <SHA>`, using the full
40-character PR head SHA. Every new commit requires a new approval.
Commit statuses belong to the SHA rather than an individual PR. If several
eligible open PRs share a head SHA, the dispatcher uses one valid exact-SHA
approval and the union of their opt-in test labels. One PR therefore cannot
publish a not-applicable result for a suite requested by another PR.

The trusted `PR CI Dispatch` workflow runs from the default branch. It verifies
the command and the commenter's current permission, then dispatches `Branch
Checks` and `Helm Lint` from the default branch with the PR number, approved
head SHA, and approval comment ID. The dispatched workflow revalidates all
three values before it checks out candidate code. Candidate jobs receive
read-only tokens and cache access. PR image builds transfer images as workflow
artifacts and do not log in to or publish to GHCR.

The self-hosted pools used for approved candidate jobs must provide a fresh,
isolated runner and container daemon for every job. Do not route PR jobs to a
persistent host, a shared Docker daemon, or a runner later reused by release
jobs: candidate code is intentionally arbitrary, even though its token and
cache permissions are read-only. Self-hosted images must run GitHub Actions
Runner 2.336.0 or newer because trusted `$/.` self-repository action and
reusable-workflow references require it.

`PR CI Dispatch` posts PR-head statuses and ties each pending status to the
exact run it creates. `Required CI Gates` completes a status only
when its run URL, approved SHA, approval comment, current approver permission,
and authorization job still match. Queue results additionally require the live
PR, queue entry, and temporary Git ref. E2E suites remain opt-in because they
are more expensive.

Fork pull requests that add, remove, rename, or modify files under
`.github/workflows/` are rejected before candidate code runs. A maintainer must
recreate an intended workflow change on a branch in the NVIDIA repository after
reviewing it. This keeps an untrusted merge-queue revision from adding its own
`merge_group` trigger and requesting write permissions or repository secrets.
The organization ruleset described under [Merge queue](#merge-queue) enforces
the same policy with a required workflow whose identity is controlled outside
this repository.

Merge queue validation is a second integration gate for `main`. After a PR has
passed the required PR-head statuses, a maintainer adds it to the merge queue.
GitHub creates a temporary queue revision that combines the latest `main`, the
queued PR, and any earlier queued PRs. The trusted dispatcher verifies that
revision through the merge queue API and temporary Git ref before it starts CI.
The same required `OpenShell / ...` status contexts are then published against
the queue SHA before GitHub merges it.

### Protobuf API compatibility

`Protobuf Compatibility` runs in Branch Checks, Release, and Pre-release through the shared
`check-protobuf-compatibility` action and Nix app. The app supplies Python, Buf,
and Git from the flake lockfile.
It uses Buf's `FILE` policy for the `proto/`
module, covering SDK descriptors and extension contracts. Storage-only protobufs
remain subject to their separate durability checks.

Branch Checks compares the prospective merge tree with the PR target commit,
so additions on the target do not look like deletions in an outdated PR. Merge
queues use their base commit. Both paths resolve the train from tags reachable
from that target, preventing a PR from selecting its own train. The checkout
must contain full history and tags; the checker leaves HEAD and working files
unchanged.

The current train's version is compared with the latest stable release. During
`0.x`, a minor increment permits breaking changes: for example, `0.2.0-pre.N`
after stable `0.1.2`. A patch increment such as `0.1.3-pre.N` rejects them.
Commit messages do not affect this decision. No active train also rejects
breaking changes. Allowed findings remain visible as warnings; schema errors,
missing baselines, merge conflicts, and tool failures always fail the check.

Release qualification compares the tagged candidate cumulatively against the previous
stable release, using the same minor-versus-patch policy. Its result is part
of the qualification profile: failure blocks stable publication and fails the
Pre-release workflow without blocking pre-release publication. Qualification evidence
remains in Actions. This checks
protobuf compatibility; SDK/configuration compatibility and migration review
remain separate qualification work.

Fetch the target and tags to check committed branch changes locally, replacing
`origin/main` for another target:

```shell
git fetch origin main --tags
nix run .#check-protobuf-compatibility -- origin/main
```

The same command accepts a release tag to qualify it against the previous stable
release. Branch names and commit SHAs select the branch comparison instead:

```shell
nix run .#check-protobuf-compatibility -- refs/tags/v0.2.0-pre.1
```

For an intentional minor-train incompatibility, record the Buf finding,
linked issue, consumer impact, and migration plan in the PR. Keep the finding
visible; do not disable the job or add a broad Buf ignore rule.

Windows PR checks are opt-in: add `test:windows`. If the current SHA is already
approved, the dispatcher starts the Windows MSVC run. Otherwise, approve it
with `/ok to test <SHA>` and the approval dispatches the labeled run.
Windows checks are not required for merging and do not run in merge queues.
Pushes to the `windows` branch and manual runs on that branch also build release
binaries, with `continue-on-error: true` so Windows failures do not fail the
workflow.

### Advisory compatibility review

`Codex Compatibility Review` runs in Branch Checks and alongside tagged release
qualification. Branch checks compare the prospective merge tree with its target,
using workflow-revision review tooling and the target's tag-derived train policy.
Release qualification reviews the cumulative diff from the previous reachable
stable release to the exact candidate commit, using the same tag-derived
patch/minor policy as the protobuf check. It reviews public Rust, Python, Go,
and TypeScript SDKs, API behavior, CLI contracts, configuration, policy, Helm,
and persisted state.
Both Codex workflows share the `codex-release-review` concurrency group with
`queue: max`, so only one review runs at a time and up to 100 pending reviews
are retained across branch, release, and manual runs. The release compatibility
review is scheduled independently of Security Scan; other security scanners run
in parallel.
It does not replace Buf or change the release train's version.

The agent inspects code first, then uses `gh` with a read-only GitHub token to
look up the introducing PR and its discussion for each finding. Release reviews
resolve introducing PRs from commit associations. Findings show `ACKED`
only for explicit acceptance of the specific risk by the PR author or a verified
maintainer. Missing context produces `UNKNOWN` when acceptance cannot be
established; acknowledgement does not override release policy. Reports lead with
the concrete change, consumer impact, action, and PR, with coverage details
collapsed.

Approved PR runs with findings post a fresh PR comment on every run,
including reruns. Runs without findings post no comment. The publisher checks
that the PR is still open at the reviewed head before commenting. Merge-queue
and manual branch runs retain reports without posting PR comments. The reviewer
has read access; a separate branch job has permission to publish comments.

The reviewer uses the Python Codex SDK (`openai-codex==0.160.0`) and its bundled
runtime through the same NVIDIA endpoint, model, medium reasoning effort, and
`CODEX_SECURITY_API_KEY` as Codex Security. The workflow uses `uv run` from the
existing Nix devShell; the SDK is not an OpenShell package dependency.
It runs on a GitHub-hosted runner with a read-only sandbox and reads a bare Git
repository; candidate-side agent configuration and instructions are not loaded.
Its permission profile keeps files read-only and routes shell network access
through the Codex network proxy, allowing only `api.github.com` for GitHub
lookups. Upstream proxy chaining and SOCKS access are disabled.
Only the GitHub token and tool/certificate paths are passed to
agent shell commands; the inference credential is excluded.
It does not run candidate builds or tests. The review has a 30-minute execution
limit inside a 40-minute job timeout.

This rollout is report-only: findings and review failures remain advisory.
The qualification caller waits for the review to finish, but its result does not
affect the required profile. Its summary distinguishes complete, incomplete, and failed execution
from the agent's compatibility assessment. Missing credentials, invalid
baselines, source mismatches, malformed reports, and timeouts are not clean
reviews. A completed review still does not prove that no breaks exist.

Each run retains `report.json` and `report.md` for 90 days in
`compatibility-review-run-<run-id>-attempt-<attempt>`. The report records both
revisions, the train, tool/model metadata, coverage gaps, and actionable
findings. Raw agent transcripts and PR discussions are not published.
The qualification summary links this separate advisory evidence without waiting
for it; compatibility
review remains missing from the blocking RFC profile during this rollout.

After the workflow is available on the default branch, run a review without
building or publishing a release:

```shell
gh workflow run codex-compatibility.yml -f candidate_ref=v0.1.3-pre.1
```

Use an existing release tag appropriate to the train being reviewed. Inspect
the report before deciding whether to fix a finding, document an intentional
minor-release break, or investigate an uncertain result. Enabling a blocking
agent gate is separate work after calibration.

`Branch E2E Checks` builds binaries and images only when an E2E suite is
selected. DEB and RPM packages build only when integration qualification is selected. Core integration qualification builds and installs
the DEB on Ubuntu with Docker and installs the CLI and gateway RPMs on Fedora with
rootful and rootless Podman. These lanes run conformance using the matching runtime
images. Release Dev, Release, and Pre-release use the same package installers.
Fedora provider-refresh tests also use RPMs. The Podman driver-specific suites
retain the binary installer because their fixtures configure its system service,
local HTTP gateway, and CLI path. The manual Integration Tests workflow defaults
to the package installers and downloads the packages selected by its matrix.

Three opt-in labels enable the long-running E2E suites:

- `test:e2e` runs the Docker, rootless Podman, Kubernetes, and VM E2E suites
  with both managed and standalone compute drivers in `Branch E2E Checks`
- `test:e2e-gpu` runs GPU E2E in `Branch E2E Checks`
- `test:e2e-kubernetes` runs Kubernetes E2E with the HA Helm overlay
  (`replicaCount: 2` and bundled PostgreSQL) and the credential-driver suite
  (Kubernetes Secrets plus Vault) in `Branch E2E Checks`

When multiple labels are present, `Branch E2E Checks` builds each required
image once per target architecture and fans out enabled suites in parallel.
The shared image build uploads gateway, sandbox, and supervisor Docker archives
as workflow artifacts; each consumer loads only the archives it needs after the
shared build completes. Runtime-specific reusable workflows define the Docker,
Podman, VM, and Kubernetes lanes. Composite actions own the replaceable Podman,
KVM, kind, and mise setup. Docker, Podman, GPU, Rust, Python, MCP, and VM E2E
reuse matching prebuilt gateway and CLI binaries instead of compiling debug
binaries in test jobs. Standalone-driver lanes additionally reuse driver-free
gateway and compute-driver artifacts. Kubernetes managed-driver lanes load the
gateway and supervisor image artifacts, while the standalone-driver lane
composes its gateway image from prebuilt binaries.
The `OpenShell / E2E` and `OpenShell / GPU E2E` required statuses are evaluated from separate suite result jobs inside that workflow. `test:e2e-kubernetes` is optional while Kubernetes HA and credential-driver behavior are under active iteration: failures are visible in the workflow run but do not publish a required CI gate status.

The GitHub ruleset should require the four `OpenShell / ...` statuses published
by `Required CI Gates`, not the dispatched workflow jobs themselves.

### K3s conformance version baseline

The tmachine `ubuntu-k3s` conformance lanes pin Agent Sandbox v0.5.0 as the
compatibility baseline for the v1beta1 Sandbox API. They do not track the local
K3s development default, currently v1.0.3. OpenShell also supports v0.4.6 through
its v1alpha1 fallback, so v0.5.0 is not the overall minimum supported version.

The `ubuntu-k3s` lanes register the gateway's ClusterIP Service directly, so
recreating the Service requires reprovisioning the fixture. The `k3s` lane runs
one plaintext gateway. The `k3s-ha` lane runs the supported HA configuration:
three gateway replicas sharing PostgreSQL, serving TLS, with the CLI connecting
over mTLS. Before conformance, every installer waits up to five minutes for a
connected gateway; interactive shells skip the wait. K3s failures upload
diagnostics as `tmachine-diagnostics-*` artifacts.

### Run only the policy advisor conformance tests

Manually dispatch `Integration Tests` with an `artifact-run-id` from the
candidate build and its exact `source-sha`. Set `checkout-repository` when the
commit belongs to a fork; it defaults to this repository. The workflow loads
the binaries and packages from that artifact run and checks out the same source
revision for the test definitions. Keep `use-image-artifacts` enabled to load
the runtime images from a Branch E2E or pull request run. Disable it only for a
Release Dev, Release, or Pre-release run whose exact-SHA runtime images were published in
GHCR. There is no automatic registry fallback. Set `category` to
`policy-advisor` and `test-matrix` to:

```json
[{"environment":"ubuntu-docker-rootful","installer":"binaries","testsuite":"policy-advisor"}]
```

This runs the `mechanistic-proposal`, `new-hostname-proposal`, and
`policy-local` conformance tests in the installed-artifact suite. The artifact run must contain the candidate CLI and
gateway binaries and runtime images. This manual run does not replace the
required PR E2E gate.

## Informational security reports

Security workflow compute runs directly on GitHub-hosted runners instead of
NVIDIA self-hosted runners. The PR-oriented workflows receive no secrets and run
on fork pull requests without waiting for exact-SHA approval. Codex Security release
qualification is the exception: it runs only for maintainer-created
pre-release tags and receives a scoped NVIDIA Inference API key for the scan
step. Scanner jobs request `security-events: write` to publish SARIF to Code
Scanning. GitHub permits Code Scanning uploads from `pull_request` runs even
when fork and Dependabot contexts receive a read-only `GITHUB_TOKEN`, so those
scanners upload results directly:

- `Workflow Security Reports` runs Actionlint and Zizmor. Actionlint reports
  workflow syntax and expression findings. Zizmor reports only High severity,
  its maximum level. Nix provides both scanners. They publish SARIF to Code
  Scanning and retain report artifacts.
- `Dependency Review` compares the base and head dependency graphs and reports
  newly introduced vulnerabilities with a High-or-higher policy. It runs in
  warn-only mode. A preflight turns an unavailable GitHub Dependency Graph into
  a warning, so the workflow remains neutral until the repository feature is
  available.
- `CodeQL` analyzes product Rust code, examples, and the Go, Python, and
  TypeScript SDKs. Rust `cfg(test)` blocks, Rust integration-test targets, and
  E2E test code are excluded. It runs nightly on `main`, remains manually
  dispatchable for diagnostics, uploads results to Code Scanning, and retains
  workflow artifacts.
- `Codex Security Release Qualification` can manually analyze a `vX.Y.Z-pre.N`
  candidate against the previous stable release. It is temporarily excluded
  from tagged-release qualification. Each scan reviews the cumulative
  stable-to-candidate diff. It calls
  `https://inference-api.nvidia.com/v1` with
  `openai/openai/gpt-5.6-sol` at medium reasoning effort. The
  `CODEX_SECURITY_API_KEY` secret must contain an API key authorized for that
  NVIDIA endpoint. Results are uploaded against the candidate commit on `main`
  under a category shared by the train, for example
  `codex-security/v0.1.1`, so later candidates replace earlier analyses. The
  slash-qualified NVIDIA model identifier prevents Codex Security 0.1.24 from
  enforcing `--max-cost`, so the workflow relies on its timeout, serialized
  concurrency, and the inference account's spend controls. Raw reports are not
  retained as workflow artifacts. Pre-release creation and stable-promotion
  enforcement remain part of RFC 0014 and are not implemented by this workflow.

Findings do not fail these workflows. Tool startup, configuration, build, and
analysis failures still fail so a broken scanner cannot appear healthy. CodeQL
is not a PR or merge-queue check. None of these reports are required statuses or
gate merges.

Run the workflow-definition scanners locally with:

```shell
nix develop --command actionlint -shellcheck= -pyflakes=
nix develop --command zizmor --offline --persona=regular --min-severity=high --no-exit-codes .
```

## Run the security scans together

`Security Scan` (`.github/workflows/security-scan.yml`) calls CodeQL, Trivy,
Cargo Deny, and Workflow Security Reports (Actionlint/Zizmor) in parallel for a
release tag. Codex Security is temporarily excluded; its standalone workflow
remains available for manual investigation. Run the parent manually from
Actions or call it from another workflow. All applicable children analyze the
candidate snapshot. Cargo Deny uses its existing NVIDIA self-hosted runner and
CI container.

Tagged releases treat Cargo Deny findings as failures of the
currently implemented qualification profile. A profile failure prevents stable
publication. Pre-release publication runs alongside qualification; failed qualification fails the parent
workflow and sends the failure notification while published artifacts remain
available. CodeQL, Trivy, and Zizmor findings are
temporarily informational for tagged releases: the existing findings were
reviewed and accepted for v0.1.0 and will be addressed in 0.1.x releases.
Scanner failures still fail qualification.

Failed pre-release builds, publication, or qualification send notifications via Slack using a webhook and
at-mentioning the triage engineer with a link to the failure. The webhook is
stored in the repository secret `SLACK_OPENSHELL_TRIAGE_WEBHOOK_URL` and the
mention is stored in the repository secret `SLACK_OPENSHELL_TRIAGE_MENTION`.
Successful pre-release builds post a top-level message to the same webhook
without a mention, so a recovery after failures is visible in the channel.
Notifications are non-blocking and do not affect release results; an unset
webhook skips sending; an unset mention sends without a mention.

```shell
gh workflow run security-scan.yml --ref main \
  -f candidate_ref=v0.1.1-pre.1 \
  -F fail-on-static-findings=false
```

To integrate it into a larger workflow, run it after the job that creates the
candidate tag and stages source-addressed artifacts for scanning. Stable
publication follows successful qualification; pre-release publication runs alongside it.
This example assumes an existing
`build` job with outputs named `candidate_tag`, `gateway_image`, `sandbox_image`,
and `chart_ref`; adapt those names to your workflow:

```yaml
jobs:
  security:
    needs: build
    uses: ./.github/workflows/security-scan.yml
    permissions:
      actions: read
      contents: read
      packages: read
      security-events: write
    with:
      candidate_ref: ${{ needs.build.outputs.candidate_tag }}
      images: |
        ${{ needs.build.outputs.gateway_image }}
        ${{ needs.build.outputs.sandbox_image }}
      charts: ${{ needs.build.outputs.chart_ref }}
      fail-on-static-findings: true
    secrets:
      CACHIX_AUTH_TOKEN: ${{ secrets.CACHIX_AUTH_TOKEN }}
```

Set `needs: security` on a downstream promotion job to require successful scans.
`Release` and `Pre-release` share `release-build.yml`, `release-publish.yml`, and
`release-qualification.yml`. Release builds, qualifies, then publishes. Pre-release
builds, then publishes and qualifies in parallel within the same run, using native job dependencies.
Its platform package artifacts are uploaded after versioned images and the chart,
so the installer can use them while qualification runs or after it fails.
The implemented `release-tag-v1` profile is an incremental subset of RFC 0014
qualification. Failed checks fail the parent workflow and retain evidence in Actions.

Each qualification attempt writes its result to the Actions run summary and
uploads `qualification-summary.json` as a 90-day workflow artifact. The qualification
workflow attempts to publish passing and failing summaries to
`ghcr.io/nvidia/openshell/qualification:<version>-run-<run-id>-attempt-<run-attempt>`.
The summary contains qualification results and policy coverage only; artifact
identity belongs in the release manifest. The run ID and attempt distinguish
reruns without overwriting earlier evidence.

`CACHIX_AUTH_TOKEN` is optional. The parent publishes SARIF from CodeQL, Trivy,
and workflow reports against the candidate tag and commit. Existing standalone
triggers stay active.

The parent fails on HIGH/CRITICAL findings from CodeQL, Trivy, and Zizmor when
`fail-on-static-findings` is `true`, which is the default. Set it to `false`
to make those findings informational. Scanner setup,
execution, and report publication errors still fail. Reports are published
before the finding threshold is enforced.

CodeQL uses the rule's security score
(at least 7.0); Trivy uses `HIGH,CRITICAL`, including vulnerabilities without an
upstream fix; Zizmor uses its High severity. Actionlint remains informational.
Existing scanner exceptions still apply.

Cargo Deny runs only `cargo deny check advisories` in the parent. It keeps its
native failure behavior and configured exceptions regardless of the finding
threshold input; it has no HIGH/CRITICAL filter. Its standalone runs still check
all dependency policies.

The standalone Codex workflow scans the cumulative diff from `stable_ref` to
`candidate_ref`. Both inputs
are tag names, not arbitrary commit SHAs. Omit `stable_ref` to resolve the previous
stable automatically; set `allow_full_bootstrap: true` to permit a full scan when
no previous stable exists.

Trivy accepts optional `images` and `charts`, one reference per line. Images can
use tags or digests, such as `ghcr.io/nvidia/openshell/gateway:0.1.1-pre.1` or
`ghcr.io/nvidia/openshell/gateway@sha256:<digest>`. Charts use versioned OCI
references, such as `oci://ghcr.io/nvidia/openshell/helm-chart:0.1.1-pre.1`.
Artifacts must already be published and accessible to the workflow. The caller
selects artifacts matching the candidate; the workflow does not verify that
association. Without artifact inputs, Trivy scans only the candidate's deployment
configuration.
Dependency Review and Trivy Changes keep their separate comparison workflows.

## Artifact scanning

`Trivy Scan` is a self-contained `workflow_dispatch`/`workflow_call` step. It
always scans deployment configuration and optionally scans supplied OCI image
and chart references. `Security Scan` calls it alongside the other independent
scanners; release workflows can also call it directly.

The scan job checks static deployment files (including Dockerfiles) once, both
local charts with default values, the OpenShell `HELM_PROFILES` selected in
`tasks/scripts/trivy-scan.sh`, requested packaged charts, and both Linux
architectures of each requested image. The profile list includes development
and E2E overlays for regression coverage, but excludes `values-spire-stack.yaml`,
which belongs to the external SPIRE chart. A new OpenShell values fixture needs
an explicit entry in this list to receive Trivy coverage.

Findings are informational by default, but scanner failures still fail the job
and `fail-on-findings` enables enforcement. Reports retain every severity; the
gate uses `HIGH,CRITICAL` by default.

All detailed JSON reports are retained in one artifact. The workflow summary and
Code Scanning configuration report deduplicate the same rule, target, resource,
and message across profiles, listing the affected profiles in each finding.
Images and packaged charts retain separate analyses, keyed by full reference
and platform so different registries or versions cannot overwrite each other.
SARIF is generated only for publication. The upload job publishes
only this consolidated configuration SARIF and the artifact analyses, in batches
of at most 20 runs to respect GitHub's per-file limit. It also publishes complete
reports when `fail-on-findings` makes the scan job fail; incomplete scans are
retained as artifacts but are not published to Code Scanning.

`.trivyignore.yaml` is reserved for false positives. Every entry must use at
least one `**/<concrete-basename>` path; `yq` and `jq` validate this structure
before scanning.

Run the scanner locally with:

```shell
nix develop --command tasks/scripts/trivy-scan.sh config
nix develop --command tasks/scripts/trivy-scan.sh images ghcr.io/nvidia/openshell/gateway:dev
nix develop --command tasks/scripts/trivy-scan.sh gate
nix develop --command tasks/scripts/trivy-scan.sh prepare-sarif
```

Use a fresh `TRIVY_REPORT_DIR` for each scan session. `prepare-sarif` creates
`code-scanning/uploads/<batch>/`; only these directories are intended for upload.

### Pull-request change gate

`Trivy Changes` scans the base and candidate when a pull request changes
deployment configuration or scanner inputs; manual runs always scan. It fails
only for new `HIGH` or `CRITICAL` misconfigurations and retains
both report sets.

For pull requests, change detection compares the exact tested merge commit with
its first parent. Both detection and scanning use that same pair. This excludes
unrelated changes on `main` even when the event carries an older base SHA or a
job is rerun. Manual runs use the supplied base and head. A missing revision or
invalid PR merge checkout fails the gate.

The candidate ignore file is validated, but the baseline policy applies to both
scans so a change cannot exempt its own finding. Existing profiles are compared
independently using the detailed reports, before any presentation deduplication;
a new profile reuses the maximum known occurrence count. A selected fixture
missing from the candidate fails the scan; a new fixture absent from the base
has no baseline profile. Invalid Trivy reports fail closed. Image package and
operating-system CVEs remain the responsibility of the standalone scan.

## Commit signing

Cryptographic commit signing is recommended, but it does not admit a revision
to self-hosted PR CI. Every candidate revision requires a maintainer's exact
`/ok to test <SHA>` approval, whether the commits are signed or unsigned.

DCO sign-off (`-s` / `Signed-off-by`) is a separate requirement and does not count as commit signing. Dependabot-authored dependency update PRs are allowlisted in DCO Assistant because the bot cannot sign commits.

### One-time setup with an SSH key

If you already use an SSH key for `git push`, you can reuse it as a signing key. (You can also generate a separate one - GitHub allows the same SSH key as both auth and signing.)

1. Generate a key (skip if reusing your existing SSH key):

   ```shell
   ssh-keygen -t ed25519 -C "you@example.com" -f ~/.ssh/id_ed25519_signing
   ```

2. Add the **public** key at <https://github.com/settings/keys> using **New SSH key**, and set **Key type: Signing Key** (not Authentication). Signing keys are managed separately from authentication keys, even when they reuse the same key material - you have to add the entry once for each role.

3. Configure git globally:

   ```shell
   git config --global gpg.format ssh
   git config --global user.signingkey ~/.ssh/id_ed25519_signing.pub
   git config --global commit.gpgsign true
   git config --global tag.gpgsign true
   ```

4. Verify on a test commit:

   ```shell
   git commit --allow-empty -s -m "test: signing"
   ```

   Push the branch and confirm GitHub shows the commit as **Verified**.

## Pull request flows

### Pull request CI

Prerequisites:

- All commits include a DCO sign-off (`git commit -s`).
- First-time external contributors must be vouched. See the
  [First-Time Contributors](CONTRIBUTING.md#first-time-contributors).

Flow:

1. Open the PR. The vouch check confirms first-time external contributors are vouched (otherwise their PRs are auto-closed).
2. A maintainer with Write access or greater reviews the exact diff and comments
   `/ok to test <SHA>` with the full current head SHA. `PR CI Dispatch` starts
   `Branch Checks` and `Helm Lint` from the trusted default-branch definitions.
3. For extended testing, apply `test:e2e`, `test:e2e-gpu`,
   `test:e2e-kubernetes`, and/or `test:windows`. If the current SHA is already
   approved, applying the label dispatches the corresponding workflow. Labels
   already present when the approval is posted are dispatched with the standard
   checks.
4. `Required CI Gates` keeps each required status tied to the exact dispatched
   run and turns it green when that run succeeds. When open PRs share the same
   head SHA, the dispatcher applies their combined opt-in test requirements.
5. Every new commit returns the standard statuses to pending. A maintainer must
   review the new diff and post `/ok to test <new-SHA>` before candidate code
   runs again.
6. When the PR is ready to merge, use **Add to merge queue** instead of merging
   directly. The queue validates the final integration state before updating
   `main`.

## Merge queue

GitHub merge queue is required for `main`. Repository administrators must enable **Require merge queue** in the branch ruleset for `main` and keep these required status contexts aligned with the PR gates:

- `OpenShell / Branch Checks`
- `OpenShell / Helm Lint`
- `OpenShell / E2E`
- `OpenShell / GPU E2E`

Keep **Only merge non-failing pull requests** enabled (`ALLGREEN`) and restrict
ruleset bypass to repository administrators.

The merge queue also requires an organization or enterprise **Require workflows
to pass** rule. Commit-status names and their GitHub Actions source do not prove
which workflow definition produced them: a candidate workflow can use the same
job names. GitHub can also suppress `pull_request_target` for head branch names
that resemble commit SHAs. The required-workflow rule supplies the independent
workflow identity and must be active before fork pull requests can enter the
queue.

Define the policy workflow in a separate, protected, public NVIDIA repository
and pin its exact commit SHA in the ruleset. It must:

- trigger on both `pull_request` and `merge_group`
- use read-only `contents` and `pull-requests` permissions
- avoid candidate checkout, local actions, or any candidate code execution
- fail closed for a fork PR unless the immutable `.github/workflows` tree at
  the exact fork head equals the tree at its exact merge base

Target only `NVIDIA/OpenShell` and its default branch. The rule parameters have
this shape; replace the placeholders with the trusted source repository ID and
40-character source commit:

```json
{
  "type": "workflows",
  "parameters": {
    "do_not_enforce_on_create": false,
    "workflows": [
      {
        "repository_id": 123456789,
        "path": ".github/workflows/openshell-workflow-policy.yml",
        "sha": "0123456789abcdef0123456789abcdef01234567"
      }
    ]
  }
}
```

Keep the four required statuses below in addition to this rule: they carry the
exact-SHA approval and test results, while the required workflow establishes
non-spoofable policy identity. Test the rule in evaluate mode with a fork PR and
the merge queue, then make it active. Until it is active, do not approve
candidate Actions workflows or enqueue fork PRs.

No repository workflow runs directly on `merge_group`, because GitHub loads
that workflow definition from the synthetic revision being tested. A fork could
otherwise add the trigger back to an existing workflow and request a write
token. The trusted dispatcher and authorizer therefore compare the immutable
`.github/workflows` Git tree at the exact fork head with the tree at its merge
base and reject any difference.

`PR CI Dispatch` handles enqueue and dequeue events from the default branch,
rescans after updates to `main`, and runs a five-minute scheduled reconciliation
as a fallback. For every current queue entry it verifies the GraphQL entry, the
matching `gh-readonly-queue` Git ref, and the workflow-change policy before it
dispatches trusted default-branch workflow definitions. Reconciliation is
idempotent and does not replace a current run.

In the queue:

- `Branch Checks` runs the standard non-E2E gates on the exact queue SHA.
- `Helm Lint` compares the queue revision with its queue base.
- E2E suites remain opt-in on PRs. The dispatcher publishes successful
  not-applicable statuses for both E2E contexts on queue revisions.
- `Required CI Gates` accepts only the exact dispatched run recorded in the
  pending status. It repeats the approval, queue entry, Git ref, authorization
  job, and result checks before publishing success.
- The exact `/ok to test <PR-head-SHA>` approval remains required while the PR
  is queued.

Maintainers should add ready PRs to the queue rather than pressing a direct
merge button. GitHub removes a PR from the queue if its checks fail or time out.

## PR CI dispatch controller

PR checks do not run candidate workflow definitions or copy candidate commits
to internal branches. `.github/copy-pr-bot.yaml` keeps copy-pr-bot disabled.

`PR CI Dispatch` handles approval comments, opt-in test labels, and merge queue
reconciliation without checking out candidate code. It dispatches a target
workflow at the repository's default branch and passes the PR number, exact
head SHA, approval comment ID, and, for queue work, the verified synthetic SHA
as inputs. The target workflow uses the trusted `authorize-pr-ci` action before
checkout to verify that:

- the PR is open, ready for review, and targets the default branch
- the supplied SHA is still the current PR head
- the supplied comment belongs to the PR and exactly equals
  `/ok to test <SHA>`
- the commenter still has Write, Maintain, or Admin permission
- a fork PR's immutable `.github/workflows` tree is identical to the tree at
  its exact merge base
- a supplied queue SHA is still the PR's current GraphQL queue entry and the
  corresponding temporary Git ref resolves to that SHA

The dispatcher records the returned run URL in the pending commit status.
`Required CI Gates` accepts completion only from that exact run and repeats the
SHA, approval, permission, and authorization-job checks. Queue runs also repeat
the current PR, queue entry, and Git-ref checks. A stale run cannot complete the
status for a newer revision.

Candidate jobs check out the approved SHA only after authorization. Trusted
composite actions are loaded from the workflow revision, tokens and caches are
read-only, and PR container images remain Actions artifacts. Workflows that
publish releases continue to run only from trusted branches or tags.

## Workflow files

| File | Role |
|---|---|
| `.github/workflows/pr-ci-dispatch.yml` | Verifies exact-SHA maintainer approvals, reconciles merge queue entries, and dispatches trusted default-branch workflows. It does not check out candidate code. |
| `.github/workflows/branch-checks.yml` | Required non-E2E checks, dispatched from the trusted default branch for approved PR and verified queue SHAs. |
| `.github/workflows/branch-e2e.yml` | Standard, GPU, Kubernetes HA, and Kubernetes credential-driver E2E, dispatched for approved PR SHAs selected by `test:e2e`, `test:e2e-gpu`, and `test:e2e-kubernetes`. Merge groups do not run E2E. |
| `.github/workflows/windows-msvc.yml` | Opt-in Windows lint and tests, dispatched for approved PR SHAs labeled `test:windows`, plus advisory cache seeding and binary builds on the `windows` branch. |
| `.github/workflows/build-binaries.yml`, `build-vm-driver.yml` | Shared binary matrices used by branch and release workflows. The VM driver remains separate because its build consumes the runtime binaries. |
| `.github/workflows/build-images.yml` | Builds container images. Approved PR runs upload per-architecture Docker archives without registry authentication; release callers explicitly enable multi-platform publication. |
| `.github/workflows/package-release-binaries.yml` | Packages raw build artifacts into release tarballs without rebuilding them. |
| `.github/workflows/e2e-docker-test.yml`, `e2e-podman-test.yml`, `e2e-vm-test.yml`, `e2e-kubernetes-test.yml` | Reusable runtime lanes called directly by branch and release workflows. Callers select suites and declare only the artifacts each runtime consumes. |
| `.github/actions/setup-e2e-*` | Shared artifact, Podman, KVM, and kind setup used by the runtime lanes. |
| `.github/workflows/helm-lint.yml` | Helm chart validation. Approved PR dispatches skip lint jobs unless Helm inputs changed; queue dispatches compare the synthetic revision with its queue base. |
| `.github/actions/setup-nix/action.yml` | Installs Nix and configures the OpenShell Cachix cache, using read-only cache access when no authentication token is available. |
| `.github/actions/authorize-pr-ci/action.yml` | Revalidates the PR, exact head SHA, approval comment, current approver permission, and optional queue entry/ref before a dispatched workflow checks out candidate code. |
| `.github/workflows/required-ci-gates.yml` | Posts required PR-head and queue-revision statuses. Completions must match the exact run URL recorded by the trusted dispatcher. This is what branch protection and merge queue should require. |
| `.github/workflows/e2e-label-help.yml` | When a `test:e2e*` label is applied, reminds maintainers of the exact-SHA approval command when the current revision is not approved. |
| `.github/workflows/workflow-security.yml` | Runs informational Actionlint and High-severity Zizmor reports on GitHub-hosted runners. |
| `.github/workflows/dependency-review.yml` | Reports dependency changes when GitHub Dependency Graph is available; otherwise publishes a neutral warning. |
| `.github/workflows/codeql.yml` | Runs nightly informational CodeQL analysis on `main` for Rust and the Go, Python, and TypeScript SDKs and retains SARIF artifacts. |
| `.github/workflows/codex-security.yml` | Scans the cumulative diff from the previous stable release to each pre-release candidate and publishes train-scoped SARIF on `main`. |
| `.github/workflows/codex-compatibility.yml` | Reviews branch and cumulative tagged-release compatibility with Codex and retains advisory findings, PR acknowledgements, and coverage; it does not gate merging or publication. |
| `.github/workflows/trivy-changes.yml` | Scans pull requests for new High or Critical Helm or Dockerfile misconfigurations. |
| `.github/workflows/trivy-scan.yml` | Manual or reusable scan of supplied OCI image/chart references and deployment configuration. Findings are informational by default and can be configured to fail the workflow. |

## Release workflows

These workflows run after merge to publish dev/tagged artifacts and verify them. They are not PR-gated.

| File | Role |
|---|---|
| `.github/workflows/release-dev.yml` | Publishes the rolling `dev` build on every push to `main`. Builds gateway, sandbox, and supervisor images and binaries, packages, wheels, and pushes the Helm chart as `oci://ghcr.io/nvidia/openshell/helm-chart:0.0.0-dev` (plus an immutable `0.0.0-dev.<sha>` pin). Also dispatchable manually. |
| `.github/workflows/release-tag.yml` | Release orchestrator for stable tags: build, qualify, publish. Automatic tag triggers exclude `-pre.*`. |
| `.github/workflows/release-prerelease.yml` | Pre-release orchestrator, triggered by prerelease tag pushes or dispatched by Release Auto-Tag or manually: build, then publish and qualify in parallel. Qualification failure fails the run and sends the failure notification; published artifacts remain available. |
| `.github/workflows/release-build.yml` | Shared version computation, binary and image builds, and package builds. Validates that the tag matches the caller's release kind. |
| `.github/workflows/release-publish.yml` | Shared artifact assembly, OCI image tags and Helm chart publication, and package publication. Stable releases also publish to GitHub Releases, snap, npm, PyPI, and Fern. |
| `.github/workflows/release-qualification.yml` | Reusable qualification suites and result aggregation. Runs security scans, conformance and feature integration, Docker and VM E2E, protobuf compatibility, and advisory compatibility review. |
| `.github/workflows/snap-package.yml` | Builds snap and component artifacts for Release Dev, Release, and Pre-release without Store credentials or publication. |
| `.github/workflows/snap-publish.yml` | Uploads existing snap and component artifacts to the Store without rebuilding. Release Dev calls it directly for `latest/edge` after snap builds and requires it to succeed before creating the dev release. Release calls it through `release-publish.yml` for `latest/stable` after qualification and release publication succeed. |
| `.github/workflows/release-canary.yml` | Smoke-tests published dev artifacts in the `macos`, `ubuntu-deb`, `ubuntu-snap-system-docker`, `fedora`, and `kubernetes` (kind + Helm) jobs. Each job reaches its gateway and creates, exercises, and deletes a sandbox. The `ubuntu-snap-system-docker` job verifies a compatible system Docker lifecycle, while `ubuntu-snap-docker-preflight` tests fail-fast behavior when Docker is absent or supplied by the Docker snap. The positive snap lane also runs a local policy containment check with the packaged prover. It runs automatically after an API-verified `Release Dev` push on `main` or maintainer dispatch and supports direct manual dispatch (`gh workflow run release-canary.yml --ref <branch>`). See the `test-release-canary` skill for the playbook and local kind reproduction. |

## Required status contexts

Require these statuses in the branch ruleset for PR and merge-queue CI:

- `OpenShell / Branch Checks`
- `OpenShell / Helm Lint`
- `OpenShell / E2E` (`test:e2e` on PRs; not applicable in the merge queue)
- `OpenShell / GPU E2E` (`test:e2e-gpu` on PRs; not applicable in the merge queue)

For dispatch-based workflows, require the statuses published by
`Required CI Gates`, not their underlying jobs. Together these contexts prove
the expected checks completed for the commit GitHub is about to merge. They do
not replace the organization-level required workflow described under
[Merge queue](#merge-queue).

Do not add the informational Actionlint, Zizmor, Dependency Review, or CodeQL
jobs to the required status list while they remain in observation mode.

## Nix download recovery

Jobs that enter the development shell enable `prepare-shell: "true"` on
`setup-nix`. After configuring Cachix, the action prepares the shell with
`nix develop -c true` and retries once on failure. Use `shell-installable`
to select a different development shell. Rust setup assumes this preparation
has completed. Jobs that only use Nix apps leave shell preparation disabled.

Nix can report a transport error after receiving a complete cache download,
then resume at EOF and receive HTTP 416. A fresh invocation restarts the
operation. Both attempts appear in the job log; a second failure fails the
step. Any preparation failure is retried once, including deterministic errors.
Cargo, lint, and test commands are not retried.

Direct `nix build` commands retry once. Before each `nix run`, CI builds the
app's package with `nix build --no-link`, retrying preparation once, then runs
the app once. The artifact and protobuf-check apps expose matching package
outputs for this preparation. Runtime failures from tests, artifact generation,
and compatibility checks are not retried. Downloads initiated inside an app
are outside this preparation retry.
