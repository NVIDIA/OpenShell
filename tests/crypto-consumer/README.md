# Library crypto consumer regression tests

Run `mise run rust:verify:library-crypto` from the repository root.

This independent Cargo workspace models an application importing OpenShell's
reusable libraries. Its lockfile is seeded from the product lockfile, but its
feature resolution excludes product executables and library dev dependencies.
The check inspects core without defaults, core with defaults, all core features,
SDK, and policy individually. None may pull in AWS-LC or Ring. It also checks
that product packages still select AWS-LC with their defaults disabled.

The `runtime` feature models a host that explicitly selects Ring for rcgen and
Rustls and RustCrypto for JWTs. This is a test-only backend adapter, not a
supported production Ring backend. It deliberately rejects primitives and PKI
operations that the test does not implement. Runtime probes exercise SDK TLS
with both trusted and untrusted CAs, OIDC client construction, core JWT issuance
and verification (including wrong-profile rejection), and policy serialization.
Separate test executables verify missing context initialization fails closed and
that TLS-only SDK use preserves an already installed host Rustls provider.

When changing dependency versions, refresh this lockfile alongside the root
lockfile. Do not add this fixture to the product workspace: that would allow
workspace feature unification to hide the regression this check detects.
