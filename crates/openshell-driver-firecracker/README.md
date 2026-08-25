# OpenShell Firecracker driver

`openshell-driver-firecracker` is an experimental host-side implementation of
the RFC 0012 Isolation Backend contract. It deliberately lives outside the
existing libkrun VM driver so the two runtimes can evolve independently.

The main OpenShell supervisor remains on the host. A private mode of the same
driver binary listens on the guest's virtio-vsock device and invokes the current
`openshell-supervisor-process` implementation only after the host advances the
boundary through `attach -> confirm -> start_agent`. The admitted policy crosses
that authenticated channel with the workload spec. The private protocol is not
a second public supervisor or agent API.

The prototype has no virtual NIC. This makes the network ceiling structurally
fail closed without TAP devices, nftables, `CAP_NET_ADMIN`, or `sudo`. Host
requirements are a Linux Firecracker binary and read/write access to `/dev/kvm`.

Current scope:

- boots an existing ext4 guest image with Firecracker;
- authenticates host-to-guest control over virtio-vsock;
- implements the RFC lifecycle and agent wait/signal operations;
- delegates guest process enforcement to the existing process supervisor leaf;
- provides an unprivileged KVM end-to-end smoke runner.

Exec, PTY, port forwarding, mediated guest egress, and per-connection binary
identity are intentionally deferred. The contract surfaces fail closed for
those operations. Code that might later become a shared VM helper is duplicated
here until a second consumer establishes a small, stable abstraction.

Run the smoke test with:

```shell
mise run e2e:firecracker
```

See `e2e/firecracker/README.md` for fixture overrides.
