# OpenShell Sandbox Protocol backend

`OpenShellRuntimeBackend` implements the authenticated host side of the shared
Sandbox Protocol.

Backend implementations may inject a `BoundaryAuditValidator` to interpret
their opaque confirmation evidence. The default Linux validator rejects
incomplete or foreign evidence. Confirmation compares the asserted properties
with the properties derived by the selected validator; validator injection does
not bypass generation, session, resource, identity, or outer-fence checks.

Concrete platform validators belong to the implementing backend, not this
shared transport library.
