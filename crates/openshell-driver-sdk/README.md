# openshell-driver-sdk

The narrow contract that compute drivers share with `OpenShell` core. It holds
the items that both a crate that stays in core (the gateway, the supervisor, the
Kubernetes driver) and the desktop drivers use, so each constant and type has
one definition.

`openshell-core` re-exports every module and item defined here, so existing
`openshell_core::...` paths keep resolving to the same definitions. Add an item
to this crate only when something that stays in core also needs it. Code used
only by the Docker, Podman, and VM drivers belongs in
`openshell-container-runtime`.

## Contents

- `proto`: the generated compute-driver contract (`compute_driver.proto` and the
  protos it imports) and the git-derived build `VERSION`.
- `sandbox_env`, `container_paths`, `driver_mounts`, `driver_utils`,
  `resource_admission`, `gpu`, `config`: the sandbox environment protocol and
  the validation shared by drivers and the supervisor.
- `jwt` (feature `jwt`), `extension_protocol`, `network_trust`, `policy`: tokens,
  extension negotiation, destination-trust bundles, and the sandbox workload
  identity limits.
- `error`, `paths`, `net`, `settings`, `telemetry`, `time`, `progress`,
  `image`, `sandbox_generation`, `proto_struct`,
  `external_driver_socket`, `e2fsprogs`: small helpers.
- `driver_contract`: re-export of `openshell-driver-contract`.

## Dependencies

The crate depends only on workspace crates and crates.io, and never on
`openshell-core`.

## Driver contract

The documents a driver hands to the supervisor and the sandbox boundary (the
runtime descriptor and the boundary configuration) are in
`openshell-driver-contract`, which this crate re-exports as `driver_contract`.
`sandbox_session`, `jwt::{CredentialEpoch, SessionRotation}` and
`paths::is_posix_absolute` keep resolving here as re-exports.
`jwt::SandboxLaunchAuthentication` and `jwt::SupervisorAuthBundle`, the gateway's
launch credentials, stay here with the JWT code. Their golden JSON examples are
in `tests/legacy_contract/examples/`, checked by `tests/legacy_jwt_documents.rs`.
