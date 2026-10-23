# openshell-spiffe

Dependency-light SPIFFE types shared by the gateway, `openshell-core`
configuration validation, and the supervisor. It has no cryptographic
implementation, SPIRE client, or `openshell-core` dependency, so core can
depend on it without a cycle.

## Contents

- `SandboxSpiffeIdPrefix` maps a gateway and sandbox to the stable identity
  `<prefix>/gateway/<gateway-id>/sandbox/<sandbox-id>`. Both IDs must already
  be SPIFFE path segments; nothing is encoded, so distinct IDs always map to
  distinct SPIFFE IDs. `SpiffeDelegationConfig::validate` in `openshell-core`
  uses it.
- `SandboxIdentityProvider` is the gateway's interface for obtaining a
  `SandboxJwtSvid` verified for that stable identity and one audience. The
  error is an associated type: the SPIRE adapter in `openshell-spire` uses the
  sanitized `TokenGrantFailure`. `SandboxJwtSvid` omits the token from `Debug`
  output.
- `workload_api_endpoint`, `trust_domain`, and `is_spiffe_path_segment` handle
  Workload API endpoints and SPIFFE ID parts.
- `parse_unverified_jwt_svid_claims` decodes JWT-SVID claims without checking
  the signature. Callers must verify the token separately before trusting
  them.
