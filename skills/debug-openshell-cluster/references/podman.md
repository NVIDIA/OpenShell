# Podman-backed gateways

```bash
podman info
podman ps --filter name=openshell
podman logs <container> --tail=200
openshell status
```

Common findings:

- Podman socket unavailable: start or expose the user socket.
- Rootless networking unavailable: inspect Podman network configuration.
- Sandbox image missing or pull denied: verify image reference and registry credentials.
- Sandbox fails before readiness with an identity-resolution error: inspect the image's OCI `USER` and matching `/etc/passwd` and `/etc/group` entries, or explicitly set both process identity fields in policy. Numeric workload identities `1` through `4294967294` are accepted; root, the invalid identity sentinel, and missing identities are rejected.
- Supervisor cannot connect: check its gateway endpoint and gateway logs.
- Inspect both Podman containers for the sandbox: the `sandbox` isolation role
  must have network mode `none`; the `supervisor` role owns the gateway session
  and egress. Both run non-root with all capabilities dropped. Check the private
  channel volume and shared user-namespace mapping if authentication fails.
- If a sandbox fails before readiness, inspect its unprivileged enforcement
  probe and the companion supervisor's private health check. Do not add
  capabilities, attach a workload network, or disable the runtime seccomp
  profile. There is no sandbox nftables or nested-network setup to repair.
- On Linux, verify that the host-networked Podman supervisor can reach the
  gateway's primary loopback endpoint. On macOS, verify Podman Machine's
  host-loopback forwarding or configure an explicit `grpc_endpoint`.
- If `host.openshell.internal` does not resolve inside a workload, verify its
  `/etc/resolv.conf` contains `nameserver 127.0.0.53`. The Podman driver mounts
  that file from a per-sandbox secret and supplies the alias destination to the
  supervisor. Check `host_gateway_ip` only when the platform default
  (`127.0.0.1` on native Linux or `192.168.127.254` on macOS Podman Machine)
  does not reach the gateway host.

When `userns` is configured (e.g. `userns = "auto"` or `userns = "keep-id"`):

- Sandbox runtime delivery uses bind-mount fallback instead of image volumes because
  overlay mounts do not support `idmapped` mounts. The supervisor binary is
  extracted from the sandbox runtime image and cached at
  `$XDG_DATA_HOME/openshell/podman-supervisor/` (typically
  `~/.local/share/openshell/podman-supervisor/`).
- Stale cache: if the sandbox runtime image is updated but the cached binary is not
  refreshed, sandbox creation may fail with an ELF validation error or version
  mismatch. Remove the cache directory and retry.
- `auto` mode requires subuid/subgid ranges for the current user in
  `/etc/subuid` and `/etc/subgid`. If missing, Podman returns a user-namespace
  mapping error at container creation.
- `private` mode requires explicit `uidmap` and `gidmap` arrays in the TOML
  config. Without both, the gateway rejects the config at startup.
  Rootless Podman uses intermediate IDs (e.g. `uidmap = ["0:0:1", "1:1:65535"]`);
  rootful Podman uses absolute host IDs (e.g. `uidmap = ["0:1000:1", "1:100000:65536"]`).
- `nomap` (without hyphen) is accepted as input but canonicalized to `no-map`
  for Podman's API.
- A workload remains in `stopping` until Podman resorts to `SIGKILL`: inspect
  supervisor logs for `failed to signal entrypoint process group`. The
  supervisor must retain `CAP_KILL` so its root process can forward `SIGTERM`
  to a workload that runs as the sandbox user.
