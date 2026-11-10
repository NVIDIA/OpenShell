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
  `image`, `sandbox_session`, `sandbox_generation`, `proto_struct`,
  `external_driver_socket`, `e2fsprogs`: small helpers.

## Dependencies

The crate depends only on workspace crates and crates.io, and never on
`openshell-core`.
