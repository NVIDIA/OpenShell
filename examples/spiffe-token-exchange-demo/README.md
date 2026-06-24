# SPIFFE Token Exchange Demo

This example validates provider dynamic token exchange using SPIFFE JWT-SVIDs.
It runs alongside `examples/spiffe-token-grant-demo` but exercises the
`token_exchange` grant type instead of `client_credentials`.

The demo deploys three in-cluster workloads:

| Workload | Purpose |
|---|---|
| `token-exchange-issuer` | Issues a demo user subject token, performs the gateway intermediate token exchange, and performs the supervisor final token exchange |
| `alpha-exchange` | Requires a final bearer token with audience and scope `alpha` |
| `beta-exchange` | Requires a final bearer token with audience and scope `beta` |

The OpenShell provider profile in `provider-profile.yaml` declares a stored
`subject_token` credential and a runtime `access_token` credential with
`token_grant.grant_type: token_exchange`.

The profile declares exact Kubernetes service hostnames for `alpha-exchange`
and `beta-exchange`. It intentionally does not set `allowed_ips`, because
cluster service CIDRs vary across Kubernetes installations.

When a sandbox curls `alpha-exchange` or `beta-exchange`:

1. The supervisor fetches its SPIFFE JWT-SVID.
2. The supervisor asks the gateway for an intermediate token.
3. The gateway verifies the supervisor SVID, fetches its own gateway JWT-SVID,
   and exchanges the stored provider `subject_token` at `token-exchange-issuer`.
   The requested intermediate audience is the supervisor SPIFFE ID.
4. The supervisor exchanges the intermediate token at the same token endpoint
   for the final alpha/beta access token.
5. The supervisor injects that final token into the outbound HTTP request.

## Prerequisites

- A Kubernetes OpenShell dev cluster.
- SPIRE enabled for provider token grants and gateway token exchange.
- Gateway and supervisor access to SPIRE OIDC/JWKS discovery.
- OpenShell configured with the Kubernetes ServiceAccount supervisor bootstrap
  path.
- `providers_v2_enabled=true` on the target gateway.
- Local `curl`, `python3`, `openssl`, `nc`, `kubectl`, and `openshell`.
- A registered and logged-in CLI gateway. The script uses `GATEWAY_NAME`, then
  `OPENSHELL_GATEWAY`, then the active OpenShell gateway selection.

For the Helm dev environment, deploy with the SPIRE releases and
`ci/values-spire.yaml` enabled in `deploy/helm/openshell/skaffold.yaml`.

The demo assumes these SPIFFE ID prefixes:

| Identity | Prefix |
|---|---|
| Gateway | `spiffe://openshell.local/ns/openshell/sa/` |
| Supervisor | `spiffe://openshell.local/openshell/sandbox/` |

Override `GATEWAY_TRUST_DOMAIN_PREFIX` or `SUPERVISOR_TRUST_DOMAIN_PREFIX` in
`k8s/workloads.yaml` if your development cluster uses different SPIFFE IDs.

The demo issuer fetches SPIRE JWKS from the in-cluster OIDC discovery service
to verify JWT-SVID signatures. The issuer pod runs a `spiffe-helper` sidecar
that writes the SPIFFE bundle into a shared volume. The Node issuer uses that
bundle as `SPIRE_JWKS_CA_FILE` when fetching JWKS over HTTPS.

## Kubeconfig And Mise

The repository `mise.toml` sets `KUBECONFIG` to the repo-local `kubeconfig`
when your shell activates the OpenShell directory. If you are testing against a
different cluster, run these commands from outside the repository and pass the
target kubeconfig explicitly.

```bash
export OPENSHELL_REPO=/path/to/OpenShell
export DEMO_KUBECONFIG=/path/to/your/kubeconfig
export OPENSHELL_GATEWAY=local
```

## Deploy Workloads

From a directory outside the repository:

```bash
ACCESS_TOKEN_SECRET="$(openssl rand -hex 32)"
KUBECONFIG="$DEMO_KUBECONFIG" kubectl -n default create secret generic openshell-spiffe-token-exchange-demo \
  --from-literal=access-token-secret="$ACCESS_TOKEN_SECRET" \
  --dry-run=client \
  -o yaml | KUBECONFIG="$DEMO_KUBECONFIG" kubectl apply -f -
KUBECONFIG="$DEMO_KUBECONFIG" kubectl apply -k "$OPENSHELL_REPO/examples/spiffe-token-exchange-demo/k8s"
KUBECONFIG="$DEMO_KUBECONFIG" kubectl -n default rollout restart deployment/token-exchange-issuer deployment/alpha-exchange deployment/beta-exchange
KUBECONFIG="$DEMO_KUBECONFIG" kubectl -n default rollout status deployment/token-exchange-issuer --timeout=180s
KUBECONFIG="$DEMO_KUBECONFIG" kubectl -n default rollout status deployment/alpha-exchange --timeout=180s
KUBECONFIG="$DEMO_KUBECONFIG" kubectl -n default rollout status deployment/beta-exchange --timeout=180s
```

## Register Provider And Test

Port-forward the local gateway in one terminal:

```bash
KUBECONFIG="$DEMO_KUBECONFIG" kubectl port-forward -n openshell svc/openshell 8097:8080
```

Copy the Helm-generated TLS client bundle into the CLI config used for this
demo. This uses the same gateway name as `OPENSHELL_GATEWAY`.

```bash
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/openshell/gateways/${OPENSHELL_GATEWAY}/mtls"
KUBECONFIG="$DEMO_KUBECONFIG" kubectl -n openshell get secret openshell-client-tls \
  -o jsonpath='{.data.ca\.crt}' | base64 -d > "${XDG_CONFIG_HOME:-$HOME/.config}/openshell/gateways/${OPENSHELL_GATEWAY}/mtls/ca.crt"
KUBECONFIG="$DEMO_KUBECONFIG" kubectl -n openshell get secret openshell-client-tls \
  -o jsonpath='{.data.tls\.crt}' | base64 -d > "${XDG_CONFIG_HOME:-$HOME/.config}/openshell/gateways/${OPENSHELL_GATEWAY}/mtls/tls.crt"
KUBECONFIG="$DEMO_KUBECONFIG" kubectl -n openshell get secret openshell-client-tls \
  -o jsonpath='{.data.tls\.key}' | base64 -d > "${XDG_CONFIG_HOME:-$HOME/.config}/openshell/gateways/${OPENSHELL_GATEWAY}/mtls/tls.key"
```

Port-forward the token exchange issuer in another terminal and fetch a demo
subject token:

```bash
KUBECONFIG="$DEMO_KUBECONFIG" kubectl port-forward -n default svc/token-exchange-issuer 18080:80
SUBJECT_TOKEN="$(
  curl -fsS http://127.0.0.1:18080/demo-subject-token |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])'
)"
```

Then run:

```bash
export GATEWAY=https://127.0.0.1:8097

openshell --gateway "$OPENSHELL_GATEWAY" --gateway-endpoint "$GATEWAY" settings set \
  --global --key providers_v2_enabled --value true --yes

openshell --gateway "$OPENSHELL_GATEWAY" --gateway-endpoint "$GATEWAY" provider profile import \
  -f "$OPENSHELL_REPO/examples/spiffe-token-exchange-demo/provider-profile.yaml"

openshell --gateway "$OPENSHELL_GATEWAY" --gateway-endpoint "$GATEWAY" provider create \
  --name spiffe-token-exchange-demo \
  --type spiffe-token-exchange-demo \
  --credential "subject_token=${SUBJECT_TOKEN}"

openshell --gateway "$OPENSHELL_GATEWAY" --gateway-endpoint "$GATEWAY" sandbox create \
  --name spiffe-token-exchange-demo \
  --provider spiffe-token-exchange-demo \
  --keep \
  --no-tty \
  -- echo "sandbox ready"

openshell --gateway "$OPENSHELL_GATEWAY" --gateway-endpoint "$GATEWAY" sandbox exec \
  --name spiffe-token-exchange-demo \
  --no-tty \
  -- curl -sS http://alpha-exchange.default.svc.cluster.local/

openshell --gateway "$OPENSHELL_GATEWAY" --gateway-endpoint "$GATEWAY" sandbox exec \
  --name spiffe-token-exchange-demo \
  --no-tty \
  -- curl -sS http://beta-exchange.default.svc.cluster.local/
```

Expected output includes the demo user as the token subject and the sandbox
SPIFFE ID as the authorized party/client:

```text
alpha called with path /:
  sub: demo-user
  aud: alpha, account
  scope: alpha profile email
  azp: spiffe://openshell.local/openshell/sandbox/<sandbox-id>
  client_id: spiffe://openshell.local/openshell/sandbox/<sandbox-id>

beta called with path /:
  sub: demo-user
  aud: beta, account
  scope: beta profile email
  azp: spiffe://openshell.local/openshell/sandbox/<sandbox-id>
  client_id: spiffe://openshell.local/openshell/sandbox/<sandbox-id>
```

The token issuer logs both token exchange phases:

```bash
KUBECONFIG="$DEMO_KUBECONFIG" kubectl -n default logs deployment/token-exchange-issuer --tail=40
```

Example log lines:

```text
issued intermediate token for user=demo-user audience=spiffe://openshell.local/openshell/sandbox/<sandbox-id>
issued final token for user=demo-user audience=alpha client=spiffe://openshell.local/openshell/sandbox/<sandbox-id>
issued final token for user=demo-user audience=beta client=spiffe://openshell.local/openshell/sandbox/<sandbox-id>
```

## Automated Demo

`demo.sh` applies the workloads, fetches a demo subject token, registers the
provider profile, creates a sandbox, curls alpha/beta, and deletes the sandbox
with `openshell` on exit. It leaves the Kubernetes demo workloads in place and
prints diagnostics only when the run fails.

```bash
cd /tmp
KUBECONFIG="$DEMO_KUBECONFIG" bash "$OPENSHELL_REPO/examples/spiffe-token-exchange-demo/demo.sh"
```

The script reuses your normal OpenShell CLI config so it can load the stored
OIDC token for `OPENSHELL_GATEWAY`. If you set `ISOLATED_CONFIG=1`, register
and log in to the gateway in that isolated config before running the demo.

## Cleanup

Delete the sandbox through OpenShell:

```bash
openshell --gateway "$OPENSHELL_GATEWAY" --gateway-endpoint "$GATEWAY" sandbox delete spiffe-token-exchange-demo
```

Delete the demo workloads with Kubernetes:

```bash
KUBECONFIG="$DEMO_KUBECONFIG" kubectl delete -k "$OPENSHELL_REPO/examples/spiffe-token-exchange-demo/k8s"
```
