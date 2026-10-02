# openshell-mxc-boundary

Windows-only library implementing the authenticated Sandbox Protocol inside an
MXC ProcessContainer, with a thin `openshell-windows-sandbox.exe` entrypoint.
The generic `openshell-sandbox` does not link this implementation. There is no
separate supervisor-relay executable.

The Windows release lane builds this executable alongside the gateway, CLI, and
host supervisor. It accepts `--bootstrap <PATH>` and `--log-level <LEVEL>`;
bootstrap configuration remains one-use and protected by the driver. On other
platforms, runtime execution returns a clear unsupported error.

The compute driver owns provisioning, filesystem/network policy mapping, ETW,
protected bootstrap material, and monitoring the host/boundary process pair.
This library owns Windows process launch and I/O, AppContainer confirmation,
authenticated lifecycle operations, retained output, and loopback forwarding.
The separate host supervisor owns policy evaluation, provider credentials, and
upstream networking. This library does not depend on the compute driver or the
supervisor implementation.

The library also owns the host-side `MxcRuntimeBackend`, registered under the
exact admission name `openshell-mxc`, and the MXC audit schema and its validator.
Windows supervisor composition selects this backend; it delegates transport
and common lifecycle validation to the shared Sandbox Protocol implementation.
The backend keeps evidence opaque and compares validated properties with the
confirmation; its default Linux validator rejects Windows evidence.

MXC adopts main's authenticated image-policy discovery and ordered provider
environment publication. Command-based MXC has no rootfs image policy to
discover. Publication generations prevent stale refreshes from replacing newer
credentials, independently of opaque provider revisions. Provider file delivery
is unsupported and rejected before process launch or environment replacement.
Structured shell exec intent and runtime helpers are also rejected explicitly;
they must not be silently treated as raw executable launches.

Dynamic service forwarding uses the shared protocol's `LoopbackConnect` request
and bidirectional stream. The boundary connects to the requested loopback port;
it does not launch a relay or connect back to a new gateway relay listener.
Non-loopback targets and port zero are rejected. Authentication and lifecycle
authorization precede dispatch to the forwarding operation.

This extraction preserves the current explicit-proxy network model. It does
not add transparent socket interception or a non-PSEC transport. The outer fence
still requires native ProcessContainer networking and permits all ports on
`127.0.0.1`; it is not isolation from unrelated host-loopback services.

Main requires explicit proof of no unmanaged egress path and verified
revocation. The current driver publishes no established outer-fence guarantees
because its configuration alone does not prove those properties. Confirmation
therefore remains fail-closed, including on an otherwise qualified PSEC host.

Unit tests exercise real Windows process launch, output retention, and a real
ephemeral TCP forwarding target. These tests do not qualify MXC enforcement;
that requires the real-MXC integration and E2E lanes on a supported host.
