# Sandbox runtime

`openshell-sandbox` owns the Linux workload isolation mechanisms and their kernel
qualification probes. The `linux` module contains seccomp notifications and child
filters, task-memory access, process-signal mediation, procfs descriptor lookup,
socket identity, Landlock qualification, and the workload launch thread.

`sandbox::linux` composes policy enforcement. The top-level `linux` module owns
the lower-level mechanisms used by that orchestration and the boundary server.
Unsafe kernel ABI, process-launch, and descriptor-ownership operations stay in
this runtime crate behind safe APIs where their contracts can be enforced.

The network broker retains source socket descriptors only while preparing a
workload endpoint. A successful connection or `listen` releases that reference;
the kernel then tracks the lifetime through workload-owned descriptors. Native
`accept` and repeated `listen` preserve the socket's loopback confinement. Closing
the last workload reference to a listener removes it without waiting for registry
collection. Broker source descriptors always use close-on-exec independently of
the workload's requested descriptor flags.

A boundary configured with `RuntimeInitiatedTlsTcp` binds no listener. It dials
only the driver-provided supervisor addresses, which must be concrete,
non-loopback, and share one port, and serves TLS and gRPC over that outbound
connection. It keeps one spare connection that the supervisor has not yet used
and dials a replacement when the supervisor starts HTTP/2 on it or the spare
closes. Live connections keep the same disconnect, freeze, and recovery-deadline
handling as listener mode, and the workload still cannot connect to the control
port.
