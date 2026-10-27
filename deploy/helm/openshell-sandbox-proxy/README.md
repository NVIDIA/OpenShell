<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Optional sandbox application proxy

This standalone chart deploys the discovery-driven TLS passthrough proxy. It
requires an enabled supervisor app listener, accepted advertisements, the service
discovery API, and an existing identity authorized for one explicit workspace.

```shell
helm upgrade --install app-proxy ./deploy/helm/openshell-sandbox-proxy \
  --namespace openshell \
  --set gatewayEndpoint=https://openshell.openshell.svc:8080 \
  --set workspace=default \
  --set gatewayCASecret=discovery-ca \
  --set tokenSecret=discovery-token \
  --set image.tag=YOUR_VERSION
```

The CA Secret uses `ca.crt`; the token Secret uses `token`. Set
`clientIdentitySecret` for a Secret containing discovery `tls.crt` and `tls.key`.
These are discovery credentials, not the application TLS private key. Secret
volumes use directory mounts so rotations are visible on reconnect.

The Service exposes port 443 and forwards to the nonroot proxy's port 8443.
Attach your TLS-passthrough ingress and configure application DNS/public origin
separately. `/readyz` on port 9091 checks discovery availability; `/healthz` checks
process liveness, and `/metrics` reports connection counters. Two replicas are
deployed by default, each with its own cache. No Kubernetes API access is needed.

Provide NetworkPolicy permitting discovery and supervisor app connections and
restrict direct supervisor ingress if your edge applies application access
controls. Configure discovery-only credentials through the gateway's certificate
grant mapping. Shared-supervisor publication still requires the HA integration. See the
[proxy README](../../../crates/openshell-sandbox-proxy/README.md) for limits and
cache/expiry behavior.

Select exactly one workspace mode: existing `workspace: team-a`,
`workspaces: [team-a, team-b]`, or `allWorkspaces: true`. Match the mounted
client identity to an administrator-managed discovery grant for that scope.
A platform grant can still be used by a proxy configured for a narrower set.
The gateway rejects partially authorized selections; cache/connection limits
apply to the combined view, not independently to each workspace.
