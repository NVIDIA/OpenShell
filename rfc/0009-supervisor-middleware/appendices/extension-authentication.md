# Appendix: Extension Authentication (Alpha)

> This is an appendix to the [RFC](../README.md). Please familiarize yourself with the RFC before reading this.

The RFC body left the authenticated-transport mechanism as follow-up protocol work: it required confidentiality plus authentication of the intended middleware service, described a phase 1 `allow_insecure` escape hatch, and deferred the phase 2 choice between mTLS, TLS plus explicit caller authentication, or an equivalent. This appendix records the mechanism that was actually built for alpha. It supersedes the body's transport-authentication and `allow_insecure` paragraphs; the rest of the body is unchanged.

Related: [protocol-extensions.md](protocol-extensions.md#middleware-authentication).

## What ships in alpha

Transport is HTTPS with either platform trust roots or an operator-provided CA bundle, with normal certificate and endpoint-hostname verification. A middleware endpoint must be reachable from every sandbox supervisor as well as the gateway, so a gateway-local Unix socket is not an option for this mechanism.

Caller identity is a short-lived Ed25519 JWT minted by the gateway's existing sandbox signing authority. The gateway attaches one to its own `Describe` and `ValidateConfig` calls; sandbox supervisors attach one to `Describe` and `EvaluateHttpRequest`. Both directions of the RFC's stated requirement are covered: TLS and the configured trust roots authenticate the middleware service to OpenShell, and the exact-audience JWT proves to the middleware that a gateway or a policy-authorized sandbox supervisor made the call.

## Claim contract

| Claim | Meaning |
|---|---|
| `iss` | Exactly `openshell-gateway:<gateway_id>`. |
| `aud` | The exact audience for one registration. Never a list. |
| `sub` | Gateway identity for gateway callers; `spiffe://openshell/sandbox/<id>` for supervisor callers. |
| `caller_kind` | `gateway` or `supervisor`. |
| `sandbox_id` | Present only for supervisor callers. |
| `jti` | Unique per token. OpenShell does not track it. |
| `iat`, `exp` | Bounded lifetime, at most one hour. |

The JOSE header carries `alg: EdDSA`, the signing `kid`, and `typ: openshell-ext+jwt`.

Explicit typing exists because extension tokens and sandbox-to-gateway admission tokens are signed by the same key and would otherwise be separated by audience alone. A verifier that requires this `typ` cannot accept a sandbox bootstrap credential even if it neglects to check `aud`. This is defense in depth for the most likely verifier mistake, not a replacement for audience validation.

## Authorization and distribution

Supervisors request credentials by operator registration name through the existing `RefreshSandboxToken` RPC, which already authenticates a sandbox principal. The gateway resolves each requested name against server-owned registration metadata and the sandbox's effective policy before minting; unknown, unselected, or duplicated names are rejected. Callers never choose an audience.

Because that resolution runs the full effective-policy composition, two bounds apply. Supervisors rotate only when a credential is missing or has passed four fifths of its lifetime rather than on every configuration poll, and the gateway caps how many minting requests a single sandbox may make per minute.

## Audience agreement

The audience is operator configuration on the OpenShell side and service configuration on the middleware side. A strict verifier rejects a mismatched token before dispatching `Describe`, so OpenShell may observe only an authentication failure.

A service may advertise the audience it verifies in the `expected_audience` field of its `Describe` manifest. After authenticated `Describe` succeeds, OpenShell compares that value against the configured one and rejects the registration on a mismatch. This is a post-authentication consistency assertion, not audience discovery. An empty field means the service does not advertise an audience and the check is skipped, so this is additive for existing services.

## Verification key distribution

The operator-provisioned public key or JWKS is the authoritative cold-start trust anchor. Deploy it alongside the extension service through the same trusted configuration path used for the gateway URL, expected gateway ID, and private CA. This lets a service verify its first authenticated call without trusting key material learned from that call's peer.

The gateway also publishes its public signing key as a single-key JWKS at `/.well-known/jwks.json`, and OIDC-shaped discovery metadata at `/.well-known/openid-configuration` carrying the expected `iss`, an absolute `jwks_uri`, and `EdDSA` as the only supported algorithm. After initial trust is established, extensions may use these endpoints for steady-state key refresh and operational convenience.

The discovery document is OIDC-shaped rather than OIDC-compliant, in the same way and for the same reason as the equivalent Kubernetes endpoint: `issuer` is the gateway identity, not the URL the document is served from. Verifiers compare `iss` against that value. Fetching the document does not establish gateway identity; the preconfigured gateway identity and authenticated TLS connection do. The well-known endpoints are therefore not a replacement for operator-provisioned first-contact trust.

## Compatibility

A registration may set `allow_insecure_transport = true`, which replaces the body's `allow_insecure` field with a clearer name and a wider meaning: it opts the registration out of extension authentication entirely. OpenShell attaches no credential, supervisors do not request one, the gateway refuses to mint one if asked, and a warning naming the registration is logged at every gateway startup.

This keeps plaintext registrations working for trusted local development and isolated research environments, and preserves compatibility for deployments configured before extension authentication existed. The body's intent that this be a temporary, auditable, prominently-warned escape hatch is retained.

## Residual risks

- **Bearer replay within the token lifetime.** Anything that obtains a token can use it until expiry. Short bounded lifetimes limit the window. `jti` identifies a token instance for correlation or future explicit revocation, but OpenShell reuses tokens across calls and does not track or revoke it. Per-request replay resistance requires request binding or proof of possession.
- **Shared signing key across two trust domains.** Extension credentials and sandbox admission credentials come from one key and one `kid`. They are separated by audience and `typ`, but extension-token issuance cannot be rotated or revoked independently of sandbox admission. A separate extension signing key is the natural next step and the `kid`-based design does not preclude it.
- **Single-key JWKS.** There is no overlap window, so key rotation is not yet a zero-downtime operation.
- **No channel binding.** mTLS or another proof-of-possession mechanism remains deferred hardening.

## Deferred

mTLS client authentication, multi-key rotation with an overlap window, replay resistance beyond short expiry, and per-runtime secret delivery are all out of scope for alpha and remain follow-up work.
