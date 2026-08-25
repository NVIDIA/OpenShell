# Firecracker smoke test

This runner boots a real Firecracker VM, drives the RFC 0012 lifecycle from the
host, and verifies that the guest process leaf runs the admitted command through
the existing OpenShell process supervisor.

It does not use `sudo`, a TAP interface, a guest NIC, nftables, or
`CAP_NET_ADMIN`. The current login session must have read/write access to
`/dev/kvm`.

Default fixtures live in `/tmp/openshell-firecracker-e2e-fixtures`. Override
them with:

```shell
OPENSHELL_FIRECRACKER_BINARY=/path/to/firecracker \
OPENSHELL_FIRECRACKER_KERNEL_IMAGE=/path/to/vmlinux \
OPENSHELL_FIRECRACKER_ROOT_DISK=/path/to/root.ext4 \
mise run e2e:firecracker
```

The runner clones the root disk into a temporary directory and injects the
current `openshell-driver-firecracker` binary plus a one-time authenticated
guest configuration. It never modifies the source fixture.
