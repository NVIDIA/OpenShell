# SPIFFE Token Grant Demo

This example validates provider dynamic token grants using SPIFFE JWT-SVIDs.
It mirrors the PR 1781 alpha/beta flow without configuring OpenShell gateway
OIDC authentication.

The demo deploys three in-cluster workloads:

| Workload | Purpose |
|---|---|
| `token-issuer` | Accepts a SPIFFE JWT-SVID client assertion and returns a short-lived demo access token |
| `alpha` | Requires a bearer token with audience and scope `alpha` |
| `beta` | Requires a bearer token with audience and scope `beta` |

The OpenShell provider profile in `provider-profile.yaml` configures a dynamic
credential with `token_grant`. When a sandbox curls `alpha` or `beta`, the
sandbox supervisor fetches a JWT-SVID from the SPIFFE Workload API, exchanges it
at `token-issuer`, and injects the returned access token into the outbound HTTP
request.

## Prerequisites

- A Kubernetes OpenShell dev cluster.
- SPIRE enabled for provider token grants.
- OpenShell configured with the Kubernetes ServiceAccount supervisor bootstrap
  path. Gateway end-user OIDC is not required for this demo.
- `providers_v2_enabled=true` on the target gateway.

For the Helm dev environment, deploy with the SPIRE releases and
`ci/values-spire.yaml` enabled in `deploy/helm/openshell/skaffold.yaml`.

## Deploy Workloads

From the repository root:

```bash
KUBECONFIG=kubeconfig kubectl apply -k examples/spiffe-token-grant-demo/k8s
KUBECONFIG=kubeconfig kubectl rollout restart deployment/token-issuer deployment/alpha deployment/beta
KUBECONFIG=kubeconfig kubectl rollout status deployment/token-issuer
KUBECONFIG=kubeconfig kubectl rollout status deployment/alpha
KUBECONFIG=kubeconfig kubectl rollout status deployment/beta
```

## Register Provider And Test

Port-forward the local gateway in one terminal:

```bash
KUBECONFIG=kubeconfig kubectl port-forward -n openshell svc/openshell 8097:8080
```

Then run:

```bash
export XDG_CONFIG_HOME=/private/tmp/openshell-spiffe-token-demo-config
export GATEWAY=http://127.0.0.1:8097

openshell --gateway-endpoint "$GATEWAY" settings set \
  --global --key providers_v2_enabled --value true --yes

openshell --gateway-endpoint "$GATEWAY" provider profile import \
  -f examples/spiffe-token-grant-demo/provider-profile.yaml

openshell --gateway-endpoint "$GATEWAY" provider create \
  --name spiffe-token-demo \
  --type spiffe-token-demo \
  --credential access_token=unused

openshell --gateway-endpoint "$GATEWAY" sandbox create \
  --name spiffe-token-demo \
  --provider spiffe-token-demo \
  --keep \
  --no-tty \
  -- echo "sandbox ready"

openshell --gateway-endpoint "$GATEWAY" sandbox exec \
  --name spiffe-token-demo \
  --no-tty \
  -- curl -sS http://alpha.default.svc.cluster.local/

openshell --gateway-endpoint "$GATEWAY" sandbox exec \
  --name spiffe-token-demo \
  --no-tty \
  -- curl -sS http://beta.default.svc.cluster.local/
```

Expected output includes endpoint-specific token claims:

```text
alpha called with path /:
  aud: alpha, account
  scope: alpha profile email
  azp: spiffe://openshell.local/openshell/sandbox/<sandbox-id>

beta called with path /:
  aud: beta, account
  scope: beta profile email
  azp: spiffe://openshell.local/openshell/sandbox/<sandbox-id>
```

The protected services also write proof-of-life logs when they accept a call:

```bash
KUBECONFIG=kubeconfig kubectl logs deployment/alpha --tail=20
KUBECONFIG=kubeconfig kubectl logs deployment/beta --tail=20
```

Example log lines:

```text
alpha accepted request path=/ aud="alpha, account" scope="alpha profile email" client_id=spiffe://openshell.local/openshell/sandbox/<sandbox-id>
beta accepted request path=/ aud="beta, account" scope="beta profile email" client_id=spiffe://openshell.local/openshell/sandbox/<sandbox-id>
```

## Automated Demo

`demo.sh` applies the workloads, registers the provider profile, creates a
sandbox, curls alpha and beta, prints the alpha/beta pod logs, and deletes the
sandbox with `openshell` on exit. It leaves the Kubernetes demo workloads in
place.

```bash
KUBECONFIG=kubeconfig bash examples/spiffe-token-grant-demo/demo.sh
```

## Cleanup

Delete the sandbox through OpenShell:

```bash
openshell --gateway-endpoint "$GATEWAY" sandbox delete spiffe-token-demo
```

Delete the demo workloads with Kubernetes:

```bash
KUBECONFIG=kubeconfig kubectl delete -k examples/spiffe-token-grant-demo/k8s
```
