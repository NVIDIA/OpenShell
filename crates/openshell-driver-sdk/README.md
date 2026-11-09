# openshell-driver-sdk

The narrow contract that compute drivers share with `OpenShell` core. It holds
the items that both a crate that stays in core (the gateway, the supervisor, the
Kubernetes driver) and the desktop drivers use, so each constant and type has
one definition.

`openshell-core` re-exports every module and item defined here, so existing
`openshell_core::...` paths keep resolving to the same definitions. Add an item
to this crate only when something that stays in core also needs it.

The crate depends only on workspace crates and crates.io, and never on
`openshell-core`.
