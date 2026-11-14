# Windows runtime limitations

These limitations are documented by the pinned Windows source:

- Outer-fence guarantees are temporarily asserted for compatibility testing. Exclusive supervisor-mediated egress and live access revocation are unverified.
- Host-loopback access can expose unrelated host services. Use a trusted development host; successful tests and signatures do not establish a production-qualified isolation boundary.
- Only native MXC ProcessContainer is supported. Docker, Kubernetes, Podman, WSL, and VM backends are not provided by this kit.
- Foreground main-process attachment, ConPTY resize, and recovery of live MXC generations after gateway restart are unavailable. Create command workloads with --detach.
- Networked applications must support the authenticated explicit proxy and appropriate CA trust.
- A Windows version number does not establish MXC compatibility. The native capability probe must pass.
- This kit does not install an MSI, service, MXC, or Visual C++ runtime. Runtime keys and credentials are generated or supplied separately.

VALIDATION.md distinguishes passed checks, failures, and checks not performed for this package. Source SBOM data covers the broader repository and is not an exact inventory of dependencies linked into each Windows executable.

Native ARM64 Python 3.14.5 dependency installation could not obtain a stable grpcio wheel. The Python health example is not qualified for that interpreter. The host-side CLI and TypeScript examples passed.
