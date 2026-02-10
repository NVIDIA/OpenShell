# Reuse Server Image for Gateway PKI Job

## Goals

- Keep the existing Helm hook PKI Job flow for mTLS secret generation.
- Eliminate the separate `navigator-pki-job` image build and distribution path.
- Reuse `navigator-server` image for the PKI hook job with minimal behavior change.

## Non-goals

- Rewriting PKI generation logic in Rust.
- Changing PKI secret semantics (all-or-none checks, secret names, cert contents).
- Altering gateway TLS behavior or CLI mTLS retrieval flow.

## Current State

- PKI generation is implemented as a Helm pre-install/pre-upgrade Job in `deploy/helm/navigator/templates/gateway-pki-job.yaml`.
- The Job currently uses `gateway.tls.jobImage` defaulting to `navigator-pki-job:dev` in `deploy/helm/navigator/values.yaml`.
- `navigator-pki-job` is built from `deploy/docker/Dockerfile.pki-job`.
- Cluster build/deploy tasks in `mise.toml` build, export, import, and set this dedicated PKI image.

## Proposed Change

Use `navigator-server` image as the PKI Job image and remove dedicated PKI image plumbing.

## Implementation Steps

1. **Switch Helm default PKI image**
   - Update `gateway.tls.jobImage` in `deploy/helm/navigator/values.yaml`:
     - from `navigator-pki-job:dev`
     - to `navigator-server:dev`

2. **Ensure server image supports PKI job runtime tools**
   - Update runtime stage in `deploy/docker/Dockerfile.server` to include:
     - `kubectl`
     - `openssl`
   - Keep existing server startup behavior unchanged.

3. **Remove dedicated PKI Dockerfile**
   - Delete `deploy/docker/Dockerfile.pki-job`.

4. **Remove PKI image build pipeline wiring**
   - Update `mise.toml` to:
     - remove task `[tasks."docker:build:pki-job"]`
     - remove dependency from `[tasks."docker:build:cluster"]`
     - remove export step for `navigator-pki-job` tarball
     - remove `docker save/import` path for `navigator-pki-job` in `cluster:deploy`
     - replace `--set gateway.tls.jobImage=navigator-pki-job:${IMAGE_TAG}` with `navigator-server:${IMAGE_TAG}`

5. **Docs touch-up**
   - Update any references that imply a dedicated PKI image is required:
     - `CONTRIBUTING.md` (if needed)
     - architecture plan notes that mention separate PKI image build path (if present)

## Validation Plan

- `mise run helm:lint`
- `mise run docker:build:server`
- `mise run docker:build:cluster`
- Deploy path smoke test:
  - `mise run cluster` (fresh) or `mise run cluster:deploy` (existing cluster)
  - Confirm hook job succeeds:
    - `kubectl get jobs -n navigator`
    - `kubectl logs job/<navigator>-gateway-pki -n navigator`
  - Confirm required secrets exist:
    - `navigator-gateway-tls`
    - `navigator-gateway-client-ca`
    - `navigator-cli-client`
- Confirm CLI mTLS bundle fetch still works via existing bootstrap flow.

## Risks and Mitigations

- **Risk:** Larger server image due to `kubectl` + `openssl`.
  - **Mitigation:** Accept short-term; later move PKI generation into server code if image size/tooling surface becomes an issue.
- **Risk:** Job command assumptions may differ under Debian-based server image.
  - **Mitigation:** Keep `/bin/sh` compatibility and validate with hook job logs in CI/local cluster.

## Rollout

- Land as a single refactor PR (no functional TLS behavior changes expected).
- If issues arise, rollback by restoring `Dockerfile.pki-job` and previous `mise`/values wiring.

## Acceptance Criteria

- No `navigator-pki-job` image build/import/export remains.
- PKI hook job still runs and generates the same three secrets.
- Cluster deploy workflows continue to pass using only `navigator-server` and `navigator-sandbox` image paths.
