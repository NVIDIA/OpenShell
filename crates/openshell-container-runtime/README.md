# openshell-container-runtime

Code used only by the desktop compute drivers (Docker, Podman, and VM). It
moves with those drivers when they leave this repository.

Anything that `openshell-core` consumers (the gateway, supervisor, or the
Kubernetes driver) also use lives in `openshell-driver-sdk` instead. This crate
depends on the SDK and never on `openshell-core`.

## Contents

- `gpu`: CDI GPU inventory and selection, and VM specific-device validation.
- `local_api_socket`: container-runtime socket discovery helpers.
- `driver_utils`: supervisor image cache, tar extraction, ELF validation,
  SPIFFE socket mounts, and workspace-validation conditions.
- `resource_admission`: provenance labels for Docker and Podman containers.
- `network_trust`: destination-trust generation labels for Podman containers.
- `config`: defaults for the container drivers.
- `proto_struct`: the serde helper for driver configuration string lists.
