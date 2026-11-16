# Policy runtime interface

Defines the policy backend, request evaluator, destination authorizer, and staged
reload contracts consumed by supervisor networking. Shared types hold parsed
request metadata, endpoint configuration, middleware snapshots, and generation
guards. This crate imports no policy engine or composition layer.

Backends implement `PolicyBackend`. The supervisor constructs one implementation
and passes a `PolicyEngine` handle to networking. A prepared reload validates
before service connections begin and commits policy, middleware, and credentials
together. Request and address authorizers remain bound to the policy generation
that admitted their connection. The relay keeps credentials and I/O state outside
the policy-visible `L7PolicyContext`.
