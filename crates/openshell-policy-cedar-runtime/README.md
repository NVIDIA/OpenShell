# Cedar runtime adapter

Adapts `openshell-policy-cedar` to the contracts in
`openshell-policy-runtime-interface`. Owns Cedar request translation, routing,
provider-rule compilation, middleware snapshots, resolved-address authorization,
and staged configuration commits. It imports no supervisor networking code.

The supervisor's `policy_runtime` composition module constructs this backend
only with the `cedar` feature. Networking receives the shared policy handle and
does not select or inspect a Cedar implementation. The gateway's policy
validation remains composed through `openshell-policy`.
