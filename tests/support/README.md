# Test support crates

Each crate here is a fixture for one concern, such as a service the
environment runs, and any suite can depend on it by path. See
[Adding a feature suite](../../TESTING.md#adding-a-feature-suite) for how an
environment and a fixture share a contract.

## Environment contract

These are the variables that an environment, the test runner or CI sets for
tests to read. A tmachine environment publishes its variables with
`tests/tmachine/ansible/playbooks/test-env.yaml`, and `openshell-test-runner`
passes them to the tests. To run a suite against your own deployment, set them
yourself. A fixture fails the test when a variable it needs is missing; it
never skips it. Add a row when you add a variable.

| Variable | Set by | Read by | Meaning |
|---|---|---|---|
| `OPENSHELL_TEST_CONTAINER_ENGINE` | Every Docker and Podman base environment (`playbooks/docker.yaml`, `podman-rootful.yaml`, `podman-rootless.yaml`); `e2e:oci-image` tasks | `container-engine-support` | The command that reaches the gateway's container engine, split on whitespace, such as `docker` or `sudo -n podman`. |
| `OPENSHELL_TEST_PODMAN_USERNS` | `<podman base>-userns-<mode>` (`playbooks/drivers/podman/userns.yaml`) | `podman-support` | The gateway's Podman user-namespace mode: `default`, `auto`, `keep-id` or `private`. |
| `OPENSHELL_TEST_CDI_SCENARIOS` | `<base>-cdi` (`playbooks/cdi.yaml`) | `tests/suites/features/cdi` | The path of the document that names the CDI device kind, each scenario and the checks it expects. |
| `OPENSHELL_TEST_KEYCLOAK_ISSUER` | `<base>-keycloak` (`playbooks/keycloak.yaml`) | `keycloak-support` | The OIDC issuer URL of the test realm, reachable from the test process. |
| `OPENSHELL_TEST_KEYCLOAK_CLIENT_ID` | `<base>-keycloak` | `keycloak-support` | A client in that realm that allows password grants. |
| `OPENSHELL_TEST_KEYCLOAK_USERNAME` | `<base>-keycloak` | `keycloak-support` | The realm user that tests sign in as. |
| `OPENSHELL_TEST_KEYCLOAK_PASSWORD` | `<base>-keycloak` | `keycloak-support` | That user's password. |
| `OPENSHELL_TEST_OTLP_LISTEN` | `<podman base>-otlp` (`playbooks/otlp.yaml`) | `otlp-support` | The address the test's OTLP/gRPC collector listens on, such as `0.0.0.0:4317`. |
| `OPENSHELL_TEST_OTLP_ENDPOINT` | `<podman base>-otlp` | `otlp-support` | The collector endpoint in the gateway's `[openshell.gateway.otlp]`, which also enables the agent trace relay. Tests check that sandboxes never see it. |
| `OPENSHELL_TEST_SPIFFE_GATEWAY_LISTEN` | `<podman base>-spiffe` (`playbooks/spiffe.yaml`) | `spiffe-support` | The Unix socket the test's gateway Workload API listens on. The gateway's `OPENSHELL_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET` names it. |
| `OPENSHELL_TEST_SPIFFE_SUPERVISOR_LISTEN` | `<podman base>-spiffe` | `spiffe-support` | The TCP address the test's supervisor Workload API listens on, such as `0.0.0.0:17690`. The driver's `provider_spiffe_workload_api_socket` reaches it as `tcp:127.0.0.1:<port>`. |
| `OPENSHELL_TEST_ADDITIONAL_CA_CERT` | `<base>-additional-ca` (`playbooks/additional-ca.yaml`), which configures the gateway's `additional_ca_bundle` | `host-server-support` (`TestCa::from_env`) | The path of the CA certificate, in PEM, that the gateway trusts. |
| `OPENSHELL_TEST_ADDITIONAL_CA_KEY` | `<base>-additional-ca` | `host-server-support` (`TestCa::from_env`) | The path of that CA's private key, in PEM, readable by the test user. Tests sign server certificates with it. |
| `OPENSHELL_TEST_BASE_IMAGE` | Optional; you, for example to use a mirror | `testkit::base_image()` | The default sandbox image. Unset, it is `nvcr.io/nvidia/base/ubuntu:24.04`. |
| `OPENSHELL_TEST_PYTHON_IMAGE` | Optional; `e2e/rust/e2e-kubernetes.sh` and `e2e-vm.sh` set a pullable image | `testkit::python_image()` | The workload image for tests that run `python3`, curl, git or openssl. Unset, it is `openshell/e2e-python:dev`, which the tmachine installers load. |
| `OPENSHELL_TEST_UNSUPPORTED` | CI, from `tests/suites/conformance/unsupported.yaml` (`tasks/scripts/conformance-unsupported.sh`), and `e2e/support/conformance.sh` for the host lanes; the runner passes it to the tests | testkit programs | Tests the environment can't pass yet, as `<test>=<issue>` entries. See [Unsupported tests](../testkit/README.md#unsupported-tests). |
| `OPENSHELL_TEST_POSTGRES_URL` | `tasks/scripts/run-postgres-tests.sh` (`mise run test:rust:postgres`), or you | `openshell-server`'s PostgreSQL tests | A disposable PostgreSQL database. Never point it at one a gateway uses. |

Other `OPENSHELL_TEST_*` names are internal test hooks and are left out on
purpose: unit-test child-process markers, the re-entry markers in
`tests/support/environment.rs`, Nix guest-cache settings, `install.sh` test
hooks and crate test settings.

### Addresses the environment chooses

When a test must listen on an address the environment picked, because the
gateway or another service is configured to call it, the environment
publishes it as `OPENSHELL_TEST_<SERVICE>_LISTEN` and the test binds it, for
example with `HttpRecorder::builder().port(port)` from `host-server-support`.
The test never picks the address itself. Tests that bind the same address can't
run at the same time.
