# Sandbox runtime

`openshell-sandbox` owns the Linux workload isolation mechanisms and their kernel
qualification probes. The `linux` module contains seccomp notifications and child
filters, task-memory access, process-signal mediation, procfs descriptor lookup,
socket identity, Landlock qualification, and the workload launch thread.

`sandbox::linux` composes policy enforcement. The top-level `linux` module owns
the lower-level mechanisms used by that orchestration and the boundary server.
Unsafe kernel ABI, process-launch, and descriptor-ownership operations stay in
this runtime crate behind safe APIs where their contracts can be enforced.
