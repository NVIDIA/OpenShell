# Docker image-update qualification

This suite uses the real gateway, Docker driver, sandbox runtime and supervisor
through the public API and CLI. It requires a fresh gateway owned by the E2E
wrapper; it does not modify an existing gateway or Docker Desktop settings.

It verifies:

- Mutual TLS authorization, including rejection without the client identity.
- Workload execution through the SDK and authenticated SSH on images A and B.
- A stopped image-only update retaining the sandbox ID, SSH host fingerprint,
  original workspace volume and a synthetic session record.
- Gateway restart and Stop/Start with authenticated workload access restored.
- Repair through Start of an intentionally interrupted credential publication
  in the stopped test sandbox's private runtime state.
- Public API deletion removing the native workload, all four sandbox-owned
  volumes and private runtime state.

Build matching gateway, CLI and runtime images from the source under test. The
wrapper accepts `OPENSHELL_GATEWAY_BIN`, `OPENSHELL_BIN`,
`OPENSHELL_DOCKER_SANDBOX_RUNTIME_IMAGE` and
`OPENSHELL_DOCKER_SUPERVISOR_IMAGE` for prebuilt inputs. Record their source
revisions and hashes with the results. For local runtime images use
`mise run build:docker:sandbox build:docker:supervisor`.

Prepare the A and B workload fixtures using the Dockerfile and instructions in
the [driver README](../../../../crates/openshell-driver-docker/README.md#live-driver-integration-test),
then run from the repository root:

```shell
OPENSHELL_E2E_DOCKER_IMAGE_UPDATES=1 \
OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE=openshell-image-update-test:A \
OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE_PULL_POLICY=never \
OPENSHELL_DOCKER_UPDATE_IMAGE_A=openshell-image-update-test:A \
OPENSHELL_DOCKER_UPDATE_IMAGE_B=openshell-image-update-test:B \
bash e2e/with-docker-gateway.sh \
  cargo test --locked --manifest-path tests/suites/features/Cargo.toml \
  -p docker-updates -- --nocapture
```

On Docker Desktop without host networking, also set
`OPENSHELL_E2E_DOCKER_SUPERVISOR_NETWORK_MODE=bridge`. Its documented
`host.docker.internal` endpoint can reach the host listener. Native Linux
loopback listeners use the default host mode. Select `DOCKER_HOST` to match
the Docker CLI context when necessary. TLS verification remains enabled.

The fault injection changes only the descriptor of the stopped, test-owned
sandbox, after a successful launch. It does not print or export credential
files. The wrapper cleans up its private gateway state after the run. Preserve
a sanitized result summary and input hashes, rather than uploading raw state.
