#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT}/e2e/parity/kubernetes-options.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

OPENSHELL_PARITY_HOST_GATEWAY_IP=169.254.1.2 bash "${SCRIPT}" --print-config baseline >"${TMP}/baseline.toml"
OPENSHELL_PARITY_HOST_GATEWAY_IP=169.254.1.2 bash "${SCRIPT}" --print-config candidate >"${TMP}/candidate.toml"
python3 -I - "${TMP}/baseline.toml" "${TMP}/candidate.toml" <<'PY'
import sys, tomllib
def check(condition, message):
    if not condition:
        raise RuntimeError(message)
baseline=tomllib.load(open(sys.argv[1],'rb'))['openshell']
candidate=tomllib.load(open(sys.argv[2],'rb'))['openshell']
check(baseline['version']==1 and candidate['version']==2,'schema versions differ')
check(baseline['gateway']['compute_drivers']==['kubernetes'],'baseline selector differs')
check(candidate['gateway']['compute_driver']=='kubernetes','candidate selector differs')
shared={'default_image','supervisor_image','client_tls_secret_name','service_account_name','host_gateway_ip','enable_user_namespaces','sa_token_ttl_secs'}
check(shared <= baseline['gateway'].keys(),'baseline inherited fields missing')
check(shared.isdisjoint(candidate['gateway'].keys()),'candidate leaked driver fields into gateway table')
check(shared <= candidate['drivers']['kubernetes'].keys(),'candidate driver fields missing')
b=dict(baseline['drivers']['kubernetes']); b.update({key:baseline['gateway'][key] for key in shared})
c=dict(candidate['drivers']['kubernetes'])
for projection in (b,c):
    projection['gateway_id']='<isolated-gateway-id>'
    projection['grpc_endpoint']='http://host.openshell.internal:<isolated-port>'
    for field in ('image_pull_policy','supervisor_image_pull_policy'):
        projection[field]={'IfNotPresent':'if_not_present'}.get(projection[field],projection[field])
check(b==c,'schema-independent Kubernetes option projections differ')
PY

: >"${TMP}/kubeconfig"
set +e
OPENSHELL_PARITY_BASELINE_ROOT="${TMP}/not-a-worktree" \
OPENSHELL_PARITY_BASELINE_GATEWAY=/bin/true \
OPENSHELL_PARITY_CANDIDATE_GATEWAY=/bin/true \
OPENSHELL_PARITY_CLI=/bin/true \
OPENSHELL_PARITY_KUBECONFIG="${TMP}/kubeconfig" \
OPENSHELL_PARITY_KUBE_CONTEXT=default/external-production-cluster \
OPENSHELL_PARITY_HOST_GATEWAY_IP=169.254.1.2 \
bash "${SCRIPT}" >"${TMP}/unsafe.out" 2>&1
status=$?
set -e
[ "${status}" -ne 0 ]
grep -F 'refusing non-parity context' "${TMP}/unsafe.out" >/dev/null

echo "Kubernetes option parity deterministic tests passed."
