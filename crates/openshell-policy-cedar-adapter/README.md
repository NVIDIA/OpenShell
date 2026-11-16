# Cedar message adapter

Adapts the standalone Cedar engine to OpenShell protobuf messages. Owns
filesystem-grant conversion, TLS inspection overlap checks, and configured MCP
endpoint inventory shared by the gateway and runtime. It imports neither
`openshell-policy` nor supervisor networking.

`openshell-policy` composes the adapter's derived values with common validation.
Its public results contain messages, grants, and diagnostics rather than a
concrete Cedar engine. The Cedar runtime uses the adapter with its own loaded
engine; runtime protocol translation and provider-rule compilation stay in
`openshell-policy-cedar-runtime`.
