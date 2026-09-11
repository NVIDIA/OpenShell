#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Compare the frozen schema-v1 and current schema-v2 Kubernetes driver against
# one explicitly supplied, disposable kind cluster. Gateway processes run on
# the host so the same cluster and candidate-owned oracle exercise both schemas.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASELINE_SHA="${OPENSHELL_PARITY_BASELINE_SHA:-74960ebfaeec4673885089ed995fad902459749f}"
CANDIDATE_SHA="${OPENSHELL_PARITY_CANDIDATE_SHA:-$(git -C "${ROOT}" rev-parse HEAD)}"
BASELINE_ROOT="${OPENSHELL_PARITY_BASELINE_ROOT:-}"
BASELINE_GATEWAY="${OPENSHELL_PARITY_BASELINE_GATEWAY:-}"
CANDIDATE_GATEWAY="${OPENSHELL_PARITY_CANDIDATE_GATEWAY:-}"
CLI="${OPENSHELL_PARITY_CLI:-}"
ARTIFACT_MANIFEST="${OPENSHELL_PARITY_ARTIFACT_MANIFEST:-}"
KUBECONFIG_PATH="${OPENSHELL_PARITY_KUBECONFIG:-}"
KUBE_CONTEXT="${OPENSHELL_PARITY_KUBE_CONTEXT:-}"
HOST_GATEWAY_IP="${OPENSHELL_PARITY_HOST_GATEWAY_IP:-}"
RUN_ID="${OPENSHELL_PARITY_RUN_ID:-$(date +%s)-$$}"
OUT="${OPENSHELL_PARITY_OUTPUT_DIR:-${ROOT}/target/parity/step8-kubernetes-${CANDIDATE_SHA:0:8}}"
SANDBOX_IMAGE="${OPENSHELL_PARITY_KUBERNETES_SANDBOX_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base:latest}"
SUPERVISOR_IMAGE="${OPENSHELL_PARITY_KUBERNETES_SUPERVISOR_IMAGE:-ghcr.io/nvidia/openshell/supervisor:latest}"
RUNTIME_CLASS="openshell-parity-runc-${RUN_ID}"

fail() {
  echo "ERROR: Kubernetes option parity: $*" >&2
  exit 1
}

kctl() {
  kubectl --kubeconfig "${KUBECONFIG_PATH}" --context "${KUBE_CONTEXT}" "$@"
}

pick_port() {
  python3 -I - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("0.0.0.0", 0))
    print(sock.getsockname()[1])
PY
}

write_config() {
  local variant=$1
  local path=$2
  local namespace=$3
  local port=$4
  local run_dir=$5
  local gateway_id="step8-${variant}-${RUN_ID}"
  local pull_policy

  if [ "${variant}" = baseline ]; then
    pull_policy=IfNotPresent
    cat >"${path}" <<EOF
[openshell]
version = 1

[openshell.gateway]
name = "${gateway_id}"
bind_address = "0.0.0.0:${port}"
disable_tls = true
compute_drivers = ["kubernetes"]
default_image = "${SANDBOX_IMAGE}"
supervisor_image = "${SUPERVISOR_IMAGE}"
client_tls_secret_name = "parity-client-tls"
service_account_name = "parity-sandbox"
host_gateway_ip = "${HOST_GATEWAY_IP}"
enable_user_namespaces = false
sa_token_ttl_secs = 600

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "${run_dir}/jwt/signing.pem"
public_key_path = "${run_dir}/jwt/public.pem"
kid_path = "${run_dir}/jwt/kid"
gateway_id = "${gateway_id}"
ttl_secs = 3600

[openshell.drivers.kubernetes]
namespace = "${namespace}"
workspace_mode = "shared"
gateway_id = "${gateway_id}"
image_pull_policy = "${pull_policy}"
image_pull_secrets = ["parity-pull-secret"]
supervisor_image_pull_policy = "${pull_policy}"
supervisor_sideload_method = "init-container"
topology = "combined"
grpc_endpoint = "http://host.openshell.internal:${port}"
ssh_socket_path = "/run/openshell/parity-kubernetes-ssh.sock"
workspace_default_storage_size = "64Mi"
workspace_storage_class = "standard"
default_runtime_class_name = "${RUNTIME_CLASS}"
app_armor_profile = "Unconfined"
sandbox_uid = 1000
sandbox_gid = 1000
EOF
  else
    pull_policy=if_not_present
    cat >"${path}" <<EOF
[openshell]
version = 2

[openshell.gateway]
name = "${gateway_id}"
bind_address = "0.0.0.0:${port}"
disable_tls = true
compute_driver = "kubernetes"

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "${run_dir}/jwt/signing.pem"
public_key_path = "${run_dir}/jwt/public.pem"
kid_path = "${run_dir}/jwt/kid"
gateway_id = "${gateway_id}"
ttl_secs = 3600

[openshell.drivers.kubernetes]
namespace = "${namespace}"
workspace_mode = "shared"
gateway_id = "${gateway_id}"
default_image = "${SANDBOX_IMAGE}"
image_pull_policy = "${pull_policy}"
image_pull_secrets = ["parity-pull-secret"]
service_account_name = "parity-sandbox"
supervisor_image = "${SUPERVISOR_IMAGE}"
supervisor_image_pull_policy = "${pull_policy}"
supervisor_sideload_method = "init-container"
topology = "combined"
grpc_endpoint = "http://host.openshell.internal:${port}"
ssh_socket_path = "/run/openshell/parity-kubernetes-ssh.sock"
client_tls_secret_name = "parity-client-tls"
host_gateway_ip = "${HOST_GATEWAY_IP}"
enable_user_namespaces = false
sa_token_ttl_secs = 600
workspace_default_storage_size = "64Mi"
workspace_storage_class = "standard"
default_runtime_class_name = "${RUNTIME_CLASS}"
app_armor_profile = "Unconfined"
sandbox_uid = 1000
sandbox_gid = 1000
EOF
  fi
}

if [ "${1:-}" = --print-config ]; then
  variant="${2:-}"
  case "${variant}" in baseline|candidate) ;; *) fail "--print-config requires baseline or candidate" ;; esac
  HOST_GATEWAY_IP="${HOST_GATEWAY_IP:-169.254.1.2}"
  RUNTIME_CLASS=openshell-parity-runc-print
  write_config "${variant}" /dev/stdout openshell-parity-print 18080 /tmp/openshell-parity-print
  exit 0
fi

[ -n "${BASELINE_ROOT}" ] || fail "OPENSHELL_PARITY_BASELINE_ROOT is required"
[ -x "${BASELINE_GATEWAY}" ] || fail "baseline gateway is not executable: ${BASELINE_GATEWAY}"
[ -x "${CANDIDATE_GATEWAY}" ] || fail "candidate gateway is not executable: ${CANDIDATE_GATEWAY}"
[ -x "${CLI}" ] || fail "candidate CLI is not executable: ${CLI}"
[ -f "${KUBECONFIG_PATH}" ] || fail "private kubeconfig does not exist: ${KUBECONFIG_PATH}"
[ -n "${HOST_GATEWAY_IP}" ] || fail "OPENSHELL_PARITY_HOST_GATEWAY_IP is required; host routing is never guessed"
case "${KUBE_CONTEXT}" in kind-openshell-parity-*) ;; *) fail "refusing non-parity context: ${KUBE_CONTEXT:-<unset>}" ;; esac
[[ "${BASELINE_SHA}" =~ ^[0-9a-f]{40}$ ]] || fail "baseline SHA must be a full lowercase SHA-1"
[[ "${CANDIDATE_SHA}" =~ ^[0-9a-f]{40}$ ]] || fail "candidate SHA must be a full lowercase SHA-1"
[[ "${RUN_ID}" =~ ^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$ ]] || fail "run ID must be a lowercase DNS label of at most 32 characters"
[[ "${SANDBOX_IMAGE}" =~ ^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,254}$ ]] || fail "sandbox image contains unsafe characters"
[[ "${SUPERVISOR_IMAGE}" =~ ^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,254}$ ]] || fail "supervisor image contains unsafe characters"
python3 -I - "${HOST_GATEWAY_IP}" <<'PY'
import ipaddress, sys
value=ipaddress.ip_address(sys.argv[1])
if value.version != 4:
    raise SystemExit("host gateway IP must be IPv4")
PY
[ "$(git -C "${BASELINE_ROOT}" rev-parse HEAD)" = "${BASELINE_SHA}" ] || fail "baseline worktree is not ${BASELINE_SHA}"
[ "$(git -C "${ROOT}" rev-parse HEAD)" = "${CANDIDATE_SHA}" ] || fail "candidate worktree is not ${CANDIDATE_SHA}"
[ "$(kubectl --kubeconfig "${KUBECONFIG_PATH}" config current-context)" = "${KUBE_CONTEXT}" ] || fail "private kubeconfig current context differs from requested parity context"
[ "$(kctl -n kube-system get configmap openshell-parity-guard -o jsonpath='{.data.context}')" = "${KUBE_CONTEXT}" ] || fail "cluster lacks the matching provisioning-time parity guard"
[ "$(kctl -n kube-system get configmap openshell-parity-guard -o jsonpath='{.data.purpose}')" = schema-v2-capability-parity ] || fail "cluster parity guard has the wrong purpose"
kctl get nodes -o name | grep -q '^node/openshell-parity-' || fail "requested context is not the dedicated OpenShell parity cluster"
[ "$(kctl get crd sandboxes.agents.x-k8s.io -o jsonpath='{.status.conditions[?(@.type=="Established")].status}')" = True ] || fail "Agent Sandbox CRD is not established"
[ -f "${ARTIFACT_MANIFEST}" ] || fail "OPENSHELL_PARITY_ARTIFACT_MANIFEST is required"
python3 -I - "${ARTIFACT_MANIFEST}" "${BASELINE_SHA}" "${CANDIDATE_SHA}" "${BASELINE_GATEWAY}" "${CANDIDATE_GATEWAY}" "${CLI}" <<'PY'
import hashlib, pathlib, sys, tomllib
manifest=tomllib.load(open(sys.argv[1],'rb'))
expected={'baseline_commit':sys.argv[2],'candidate_commit':sys.argv[3]}
for key, value in expected.items():
    if manifest.get(key) != value:
        raise SystemExit(f'artifact manifest {key} does not match')
for key, path in zip(('baseline_gateway_sha256','candidate_gateway_sha256','candidate_cli_sha256'),sys.argv[4:]):
    digest=hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
    if manifest.get(key) != digest:
        raise SystemExit(f'artifact manifest {key} does not match supplied binary')
PY

PARITY_ROOT="$(realpath -m "${ROOT}/target/parity")"
OUT="$(realpath -m "${OUT}")"
case "${OUT}" in "${PARITY_ROOT}"/step8-kubernetes-*) ;; *) fail "output must be a step8-kubernetes-* directory below ${PARITY_ROOT}" ;; esac
[ ! -L "${OUT}" ] || fail "output directory must not be a symlink"
rm -rf --one-file-system "${OUT}"
umask 077
mkdir -p "${OUT}/raw"
cp "${ARTIFACT_MANIFEST}" "${OUT}/artifact-manifest.toml"
printf '%s\n' "${BASELINE_SHA}" >"${OUT}/baseline.sha"
printf '%s\n' "${CANDIDATE_SHA}" >"${OUT}/candidate.sha"
printf '%s\n' "${KUBE_CONTEXT}" >"${OUT}/context"

runtime_class_created=false
cleanup_cluster_fixture() {
  local status=$?
  local cleanup_status=0
  set +e
  if ${runtime_class_created}; then
    kctl delete runtimeclass "${RUNTIME_CLASS}" --ignore-not-found --wait=true --timeout=120s >/dev/null 2>&1
    cleanup_status=$?
  fi
  set -e
  if [ "${status}" -eq 0 ] && [ "${cleanup_status}" -ne 0 ]; then
    echo "ERROR: failed to confirm RuntimeClass cleanup" >&2
    exit 1
  fi
  exit "${status}"
}
trap cleanup_cluster_fixture EXIT
cat <<EOF | kctl create -f - >/dev/null
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: ${RUNTIME_CLASS}
handler: runc
EOF
runtime_class_created=true

run_variant() (
  set -euo pipefail
  local variant=$1
  local gateway=$2
  local namespace="openshell-parity-${variant}-${RUN_ID}"
  local sandbox="k8s-${variant:0:1}-${RUN_ID: -6}"
  local resource="default--${sandbox}"
  local run_dir="${OUT}/raw/${variant}"
  local config="${run_dir}/gateway.toml"
  local port
  local gateway_pid=
  local registered_endpoint
  local namespace_created=false
  mkdir -p "${run_dir}/jwt" "${run_dir}/xdg-config/openshell/gateways/parity" "${run_dir}/xdg-state" "${run_dir}/xdg-data"

  cleanup_variant() {
    local status=$?
    local cleanup_status=0
    set +e
    if [ -n "${gateway_pid}" ]; then
      kill "${gateway_pid}" >/dev/null 2>&1 || true
      wait "${gateway_pid}" >/dev/null 2>&1 || true
    fi
    rm -f "${run_dir}/jwt/signing.pem" "${run_dir}/client.key"
    if ${namespace_created}; then
      kctl delete namespace "${namespace}" --ignore-not-found --wait=true --timeout=120s >"${run_dir}/namespace-delete.log" 2>&1
      cleanup_status=$?
    fi
    set -e
    if [ "${status}" -eq 0 ] && [ "${cleanup_status}" -ne 0 ]; then
      echo "ERROR: ${variant} namespace cleanup was not confirmed" >&2
      exit 1
    fi
    exit "${status}"
  }
  trap cleanup_variant EXIT

  openssl genpkey -algorithm ED25519 -out "${run_dir}/jwt/signing.pem" >/dev/null 2>&1
  openssl pkey -in "${run_dir}/jwt/signing.pem" -pubout -out "${run_dir}/jwt/public.pem" >/dev/null 2>&1
  printf 'step8-%s\n' "${variant}" >"${run_dir}/jwt/kid"
  openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=step8-parity-client" \
    -keyout "${run_dir}/client.key" -out "${run_dir}/client.crt" -days 1 >/dev/null 2>&1

  kctl create namespace "${namespace}" >"${run_dir}/namespace-create.log"
  namespace_created=true
  kctl -n "${namespace}" create serviceaccount parity-sandbox >"${run_dir}/service-account.log"
  kctl -n "${namespace}" create secret generic parity-pull-secret \
    --type=kubernetes.io/dockerconfigjson --from-literal=.dockerconfigjson='{"auths":{}}' >"${run_dir}/pull-secret.log"
  kctl -n "${namespace}" create secret generic parity-client-tls \
    --from-file=ca.crt="${run_dir}/client.crt" \
    --from-file=tls.crt="${run_dir}/client.crt" \
    --from-file=tls.key="${run_dir}/client.key" >"${run_dir}/client-tls-secret.log"

  port="$(pick_port)"
  write_config "${variant}" "${config}" "${namespace}" "${port}" "${run_dir}"
  KUBECONFIG="${KUBECONFIG_PATH}" \
    XDG_CONFIG_HOME="${run_dir}/xdg-config" XDG_STATE_HOME="${run_dir}/xdg-state" XDG_DATA_HOME="${run_dir}/xdg-data" \
    OPENSHELL_DB_URL="sqlite:${run_dir}/gateway.db" \
    "${gateway}" --config "${config}" >"${run_dir}/gateway.log" 2>&1 &
  gateway_pid=$!
  listener_ready=false
  for _ in $(seq 1 60); do
    if ! kill -0 "${gateway_pid}" >/dev/null 2>&1; then
      fail "${variant} gateway exited before binding; see ${run_dir}/gateway.log"
    fi
    if python3 -I - "${port}" <<'PY'
import socket, sys
try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=.2):
        pass
except OSError:
    raise SystemExit(1)
PY
    then
      listener_ready=true
      break
    fi
    sleep 0.5
  done
  ${listener_ready} || fail "${variant} gateway did not bind within 30 seconds"

  registered_endpoint="http://127.0.0.1:${port}"
  cat >"${run_dir}/xdg-config/openshell/gateways/parity/metadata.json" <<EOF
{"name":"parity","gateway_endpoint":"${registered_endpoint}","is_remote":false,"gateway_port":${port},"auth_mode":"plaintext"}
EOF
  printf parity >"${run_dir}/xdg-config/openshell/active_gateway"

  XDG_CONFIG_HOME="${run_dir}/xdg-config" XDG_STATE_HOME="${run_dir}/xdg-state" XDG_DATA_HOME="${run_dir}/xdg-data" \
    timeout 360 "${CLI}" sandbox create --name "${sandbox}" --cpu 250m --memory 128Mi --detach \
    >"${run_dir}/create.log" 2>&1
  XDG_CONFIG_HOME="${run_dir}/xdg-config" XDG_STATE_HOME="${run_dir}/xdg-state" XDG_DATA_HOME="${run_dir}/xdg-data" \
    timeout 60 "${CLI}" sandbox exec --name "${sandbox}" --no-tty -- \
    sh -c 'printf step8-kubernetes-exec' >"${run_dir}/exec.log" 2>&1
  grep -q 'step8-kubernetes-exec' "${run_dir}/exec.log" || fail "${variant} callback exec marker missing"

  kctl -n "${namespace}" get sandbox "${resource}" -o json >"${run_dir}/sandbox.json"
  kctl -n "${namespace}" get pod "${resource}" -o json >"${run_dir}/pod.json"
  kctl -n "${namespace}" get pvc "workspace-${resource}" -o json >"${run_dir}/pvc.json"

  python3 -I - "${run_dir}" "${SANDBOX_IMAGE}" "${SUPERVISOR_IMAGE}" "${HOST_GATEWAY_IP}" "${RUNTIME_CLASS}" <<'PY'
import json, pathlib, sys
def check(condition, message):
    if not condition:
        raise RuntimeError(message)
run=pathlib.Path(sys.argv[1]); sandbox_image, supervisor_image, host_ip, runtime_class=sys.argv[2:]
pod=json.loads((run/'pod.json').read_text()); pvc=json.loads((run/'pvc.json').read_text()); sb=json.loads((run/'sandbox.json').read_text())
spec=pod['spec']; agent=next(c for c in spec['containers'] if c['name']=='agent'); env={x['name']:x.get('value','') for x in agent.get('env',[])}
inits={c['name']:c for c in spec.get('initContainers',[])}; install=inits['openshell-supervisor-install']
vols={v['name']:v for v in spec.get('volumes',[])}; mounts={m['name']:m for m in agent.get('volumeMounts',[])}
hosts={(h, a['ip']) for a in spec.get('hostAliases',[]) for h in a.get('hostnames',[])}
check(pod['status']['phase']=='Running','Pod is not Running')
conditions={c['type']:c['status'] for c in sb.get('status',{}).get('conditions',[])}
check(conditions.get('Ready')=='True','Sandbox Ready condition is not true')
check(agent['image']==sandbox_image and agent['imagePullPolicy']=='IfNotPresent','sandbox image or pull policy differs')
check(install['image']==supervisor_image and install['imagePullPolicy']=='IfNotPresent','supervisor image or pull policy differs')
check([x['name'] for x in spec.get('imagePullSecrets',[])]==['parity-pull-secret'],'image pull Secret differs')
check(spec['serviceAccountName']=='parity-sandbox','ServiceAccount differs')
check(env['OPENSHELL_ENDPOINT'].startswith('http://host.openshell.internal:'),'callback endpoint differs')
check(env['OPENSHELL_SSH_SOCKET_PATH']=='/run/openshell/parity-kubernetes-ssh.sock','SSH socket differs')
check(env['OPENSHELL_SANDBOX_UID']=='1000' and env['OPENSHELL_SANDBOX_GID']=='1000','sandbox identity differs')
check(('host.openshell.internal',host_ip) in hosts and ('host.docker.internal',host_ip) in hosts,'host aliases differ')
check(spec['runtimeClassName']==runtime_class and spec.get('hostUsers',True) is not False,'RuntimeClass or user namespace posture differs')
check(agent['securityContext']['appArmorProfile']['type']=='Unconfined','AppArmor profile differs')
check(agent['resources']['requests']=={'cpu':'250m','memory':'128Mi'},'resource requests differ')
check(agent['resources']['limits']=={'cpu':'250m','memory':'128Mi'},'resource limits differ')
check(vols['openshell-sa-token']['projected']['sources'][0]['serviceAccountToken']['expirationSeconds']==600,'ServiceAccount token TTL differs')
check(vols['openshell-client-tls']['secret']['secretName']=='parity-client-tls','client TLS Secret differs')
check(mounts['openshell-client-tls']['readOnly'] is True,'client TLS mount is not read-only')
check(pvc['status']['phase']=='Bound' and pvc['spec']['storageClassName']=='standard','PVC phase or StorageClass differs')
check(pvc['spec']['resources']['requests']['storage']=='64Mi','PVC storage request differs')
labels=sb['metadata']['labels']
for key in ('openshell.ai/sandbox-id','openshell.ai/sandbox-name','openshell.ai/sandbox-workspace','openshell.ai/gateway-id','openshell.ai/managed-by'):
    check(labels.get(key),f'managed label {key} missing')
observed_sideload='init-container' if 'openshell-supervisor-install' in inits else 'unknown'
observed_topology='combined' if [c['name'] for c in spec['containers']]==['agent'] else 'other'
observed_workspace_mode='shared' if pvc['metadata']['namespace']==pod['metadata']['namespace'] and pvc['metadata']['name'].startswith('workspace-default--') else 'other'
check(observed_sideload=='init-container','supervisor sideload method differs')
check(observed_topology=='combined','supervisor topology differs')
check(observed_workspace_mode=='shared','workspace placement differs')
normalized={
 'scenario':'kubernetes-core-options','pod_phase':'Running','sandbox_ready':True,
 'sandbox_image':agent['image'],'sandbox_image_pull_policy':agent['imagePullPolicy'],
 'image_pull_secrets':['parity-pull-secret'],'service_account':'parity-sandbox',
 'supervisor_image':install['image'],'supervisor_image_pull_policy':install['imagePullPolicy'],
 'supervisor_sideload_method':observed_sideload,'topology':observed_topology,
 'callback_endpoint_host':'host.openshell.internal','callback_exec':True,
 'ssh_socket_path':env['OPENSHELL_SSH_SOCKET_PATH'],'client_tls_secret':'parity-client-tls',
 'host_gateway_ip':host_ip,'sa_token_ttl_secs':600,'runtime_class_handler':'runc',
 'enable_user_namespaces':False,'app_armor_profile':'Unconfined','sandbox_uid':1000,'sandbox_gid':1000,
 'workspace_mode':observed_workspace_mode,'workspace_storage':'64Mi','workspace_storage_class':'standard','pvc_phase':'Bound',
 'cpu':'250m','memory':'128Mi','managed_labels':True,
}
(run.parent.parent/f'{run.name}.normalized.json').write_text(json.dumps(normalized,sort_keys=True,separators=(',',':'))+'\n')
PY

  XDG_CONFIG_HOME="${run_dir}/xdg-config" XDG_STATE_HOME="${run_dir}/xdg-state" XDG_DATA_HOME="${run_dir}/xdg-data" \
    timeout 60 "${CLI}" sandbox delete "${sandbox}" >"${run_dir}/delete.log" 2>&1
  for _ in $(seq 1 60); do
    if ! kctl -n "${namespace}" get sandbox "${resource}" >/dev/null 2>&1 \
      && ! kctl -n "${namespace}" get pod "${resource}" >/dev/null 2>&1 \
      && ! kctl -n "${namespace}" get pvc "workspace-${resource}" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  ! kctl -n "${namespace}" get sandbox "${resource}" >/dev/null 2>&1 || fail "${variant} Sandbox remained after delete"
  ! kctl -n "${namespace}" get pod "${resource}" >/dev/null 2>&1 || fail "${variant} Pod remained after delete"
  ! kctl -n "${namespace}" get pvc "workspace-${resource}" >/dev/null 2>&1 || fail "${variant} PVC remained after delete"
)

set +e
run_variant baseline "${BASELINE_GATEWAY}"
baseline_status=$?
run_variant candidate "${CANDIDATE_GATEWAY}"
candidate_status=$?
set -e

baseline_success=false; candidate_success=false
[ "${baseline_status}" -eq 0 ] && baseline_success=true
[ "${candidate_status}" -eq 0 ] && candidate_success=true
parity=false; classification=regression; accepted=false
if ${baseline_success} && ${candidate_success} && [ -f "${OUT}/baseline.normalized.json" ] && [ -f "${OUT}/candidate.normalized.json" ]; then
  if cmp -s "${OUT}/baseline.normalized.json" "${OUT}/candidate.normalized.json"; then
    parity=true; classification=pass; accepted=true
  fi
fi
cat >"${OUT}/comparison.json" <<EOF
{"baseline_commit":"${BASELINE_SHA}","candidate_commit":"${CANDIDATE_SHA}","baseline_success":${baseline_success},"candidate_success":${candidate_success},"parity":${parity},"classification":"${classification}","accepted":${accepted}}
EOF

if ! ${accepted}; then
  fail "paired Kubernetes option oracle failed; see ${OUT}/comparison.json and ${OUT}/raw"
fi
cat "${OUT}/comparison.json"
