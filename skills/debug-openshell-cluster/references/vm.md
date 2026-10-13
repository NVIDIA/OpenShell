# VM-backed gateways

Use the VM driver logs and host diagnostics available in the user's environment. Verify:

- The VM driver process is running and reachable by the gateway.
- The runtime rootfs exists and matches the expected architecture.
- `mke2fs` or `mkfs.ext4`, `debugfs`, and `e2fsck` from e2fsprogs are installed. Run `openshell-gateway config preflight` with the intended local VM configuration, service account, and environment to check the selected paths and versions before startup. A remote endpoint reports that host checks were not performed. Explicit `sandbox_uid`/`sandbox_gid` does not remove this prerequisite.
- A persisted overlay identity error is resolved from its owner marker, overlay
  upper layer, prepared rootfs, explicit config, or current image. Do not assign
  `10001:10001` unless the persisted state reports that legacy identity.
- Host virtualization support is enabled.
- The sandbox supervisor can establish its authenticated gateway session.

Then run:

```bash
openshell status
openshell logs <sandbox-name>
```

## Corporate upstream proxy

When VM sandbox egress routes through a corporate HTTP forward proxy, the
operator-owned settings live under `[openshell.drivers.vm]` and the gateway
forwards them to the `openshell-driver-vm` subprocess as `--upstream-proxy`,
`--upstream-no-proxy`, `--upstream-proxy-auth-file`,
`--upstream-proxy-auth-allow-insecure`,
`--upstream-proxy-connect-by-hostname`, and `--upstream-proxy-ca-bundle`. Both the gateway and
the driver validate them at startup, so any present-but-invalid value fails
closed with an error naming the key rather than reverting to a direct dial.
Confirm the configuration and the resulting driver argv first:

```bash
grep -A20 '^\[openshell.drivers.vm\]' <gateway.toml> | grep -E 'https_proxy|no_proxy|proxy_auth_file|proxy_auth_allow_insecure|proxy_connect_by_hostname|proxy_ca_bundle'
ps -o args= -p "$(pgrep -f openshell-driver-vm | head -n1)" | tr ' ' '\n' | grep -A1 -- '--upstream-proxy\|--upstream-no-proxy'
```

Both libkrun and QEMU guests are NIC-less. Proxy settings, credentials, and
private CA material stay with the host `openshell-supervisor`. For a proxy on
the gateway host, use `http://host.openshell.internal:<port>`; the supervisor
normalizes that name to host loopback. Inspect `supervisor.log` and
`supervisor.err.log` under the sandbox state directory for connection or
credential failures.
