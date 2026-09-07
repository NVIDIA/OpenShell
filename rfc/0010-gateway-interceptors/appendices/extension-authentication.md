# Appendix: Extension Authentication (Alpha)

> This is an appendix to the [RFC](../README.md). Please familiarize yourself with the RFC before reading this.

The RFC body states that all gateway interceptor connections require authentication, leaves the model out of scope, and suggests implementations should support mTLS and bearer-token authentication. This appendix records the mechanism that was actually built for alpha. It supersedes that paragraph; the rest of the body is unchanged.

Gateway interceptors and supervisor middleware share one implementation. The full claim contract, authorization model, key distribution, and residual risks are documented once in [RFC 0009's appendix](../../0009-supervisor-middleware/appendices/extension-authentication.md). This appendix records only what differs for interceptors.

## What ships in alpha

The bearer-token half of the body's suggestion, not the mTLS half. The gateway attaches a short-lived, exact-audience Ed25519 JWT to `Describe`, `Evaluate`, and provider-profile snapshot calls. mTLS remains deferred hardening.

Interceptors are called only by the gateway, so every token carries `caller_kind: gateway` and no `sandbox_id`. There is no supervisor-side distribution path and no policy-based authorization step: the gateway mints its own credentials at startup from configuration and rotates them in place.

## Transport

Unlike middleware, interceptors keep the body's Unix domain socket option. A gateway-local socket is reachable by the only caller that exists, so both `https://` and `unix://` are accepted when gateway JWT signing is configured. HTTPS endpoints may pin an operator-provided CA bundle and retain normal hostname verification.

## Audience agreement

The audience defaults to `urn:openshell:extension:interceptor:<name>` and may be set explicitly per interceptor. An interceptor may advertise the audience it verifies in the `expected_audience` field of its `Describe` manifest. After authenticated `Describe` succeeds, the gateway treats that value as a consistency assertion and refuses to start when it differs from the configured audience. A strict verifier may reject an incorrect audience before returning the manifest, so this does not provide audience discovery.

Because the body already makes an unavailable service, invalid manifest, or unauthorized binding a startup failure, this fits the existing posture: interceptor configuration problems surface before the gateway serves traffic.

## Compatibility

An interceptor may set `allow_insecure_transport = true` to keep a plaintext `http://` endpoint with no credential attached. The gateway logs a warning naming the interceptor at every startup. This exists for local development and for deployments configured before extension authentication existed.

## Deferred

mTLS client authentication, multi-key rotation with an overlap window, and replay resistance beyond short expiry remain follow-up work, as recorded in RFC 0009's appendix.
