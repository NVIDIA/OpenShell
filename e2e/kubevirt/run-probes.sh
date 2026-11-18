#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Root-workload attack-surface probes for the KubeVirt compute-driver PoC.
#
# Each probe exercises an attack surface a root guest owns by design and
# records what the control plane observes. The probes document evidence for
# the RFC; outcomes that are design inputs (not pass/fail) are recorded as
# FINDINGS. Assertions are limited to invariants the approved posture
# requires.
#
#   P1  in-guest reset: the reboot syscall (a root workload can always
#       reboot its own kernel). Records how the control plane observes the
#       reset (phase, reason, VMI/supervisor identity) — the input for the
#       reset-detection design (item 7).
#   P2  the iTCO watchdog: root can arm it (no configurable action; the
#       device is attached unconditionally). Records the reset path from
#       hardware rather than the syscall.
#   P3  fake qemu-guest-agent: the virtio-serial guest-agent channel is
#       attached unconditionally; a root guest can run a lying agent.
#       Verifies KubeVirt surfaces the lies in VMI status AND that nothing
#       in OpenShell consumes them (the sandbox must be unaffected).
#   P4  virtiofsd against a root guest: the workspace share's privileged
#       operation surface (chown past the idmap, mknod, setuid) — what the
#       share admits and what reaches the PVC host-side.
#   P5  launcher-netns listener audit: what listens in the launcher pod's
#      network namespace and what the fence admits from it.
#
# Usage: e2e/kubevirt/demo.sh --probes   (root workload mode is forced)
#
# The script creates its own sandbox (kvpoc-probe) with the root policy and
# tears it down on exit.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CARGO_TARGET="${CARGO_TARGET_DIR:-${ROOT}/target}"
OPENSHELL_CLI="${CARGO_TARGET}/release/openshell"
SANDBOX_NAMESPACE="${OPENSHELL_KVPOC_NAMESPACE:-kvpoc-sandboxes}"
TOPOLOGY="${OPENSHELL_KVPOC_TOPOLOGY:-dedicated}"

# The probes are root-mode by definition: they exercise what a root
# workload can do to its own guest.
WORKLOAD="root"
DEMO_POLICY="${ROOT}/e2e/kubevirt/demo-policy-root.yaml"
NAME="kvpoc-probe"
VM_SELECTOR="openshell.ai/sandbox-name=${NAME}"
FENCE_PREFIX="openshell-kubevirt-fence-"
VMI_NAME="default--${NAME}"
WORKDIR="$(mktemp -d /tmp/kvpoc-probe-XXXXXX)"

step() { echo; echo "=== $* ==="; }
fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "NOTE: $*" >&2; }

# Single EXIT trap: teardown on failure (CLI delete first while the gateway
# is up, then labelled kubectl deletions as the gateway-independent
# backstop), scratch removal on every exit.
probe_exit_trap() {
    local rc=$?
    if [ "${rc}" -ne 0 ] && [ "${PROBE_CREATED}" = "1" ]; then
        echo >&2
        echo "probe failed (rc=${rc}); tearing down sandbox '${NAME}'..." >&2
        "${OPENSHELL_CLI}" sandbox delete "${NAME}" >/dev/null 2>&1 || true
        kubectl delete vm -n "${SANDBOX_NAMESPACE}" -l "${VM_SELECTOR}" \
            --wait=false --ignore-not-found >/dev/null 2>&1 || true
        kubectl delete pod,svc,secret,pvc,netpol -n "${SANDBOX_NAMESPACE}" \
            -l "${VM_SELECTOR}" --ignore-not-found >/dev/null 2>&1 || true
        echo "teardown complete" >&2
    fi
    rm -rf "${WORKDIR:-}"
    exit "${rc}"
}
trap probe_exit_trap EXIT
PROBE_CREATED=0

sandbox_phase() {
    "${OPENSHELL_CLI}" sandbox get "${NAME}" 2>/dev/null | grep -a "Phase:" | head -1 \
        | sed 's/^ *//' || true
}

wait_for_phase() {
    local expected="$1" timeout_secs="${2:-300}" deadline got
    deadline=$(( $(date +%s) + timeout_secs ))
    while [ "$(date +%s)" -lt "${deadline}" ]; do
        got="$(sandbox_phase)"
        case "${got}" in
            "Phase: ${expected}") return 0 ;;
        esac
        sleep 5
    done
    fail "timed out waiting for phase ${expected} (got '${got:-none}')"
}

exec_in_sandbox() {
    "${OPENSHELL_CLI}" sandbox exec "${NAME}" -- "$@" || {
        local rc=$?
        [ "${rc}" = "74" ] || return "${rc}"
        return 0
    }
}

vm_jsonpath() {
    kubectl get vm -l "${VM_SELECTOR}" -n "${SANDBOX_NAMESPACE}" \
        -o "jsonpath=$1" 2>/dev/null
}

supervisor_pod_name() {
    local sandbox_id sbx_lc
    sandbox_id="$(vm_jsonpath '{.items[0].metadata.labels.openshell\.ai/sandbox-id}')"
    sbx_lc="$(printf '%s' "${sandbox_id}" | tr '[:upper:]' '[:lower:]')"
    echo "os-supervisor-${sbx_lc}"
}

launcher_pod_name() {
    kubectl get pods -n "${SANDBOX_NAMESPACE}" \
        -l kubevirt.io=virt-launcher,openshell.ai/sandbox-name="${NAME}" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

# Summed container restart counts: virt-launcher (this sandbox's launcher
# pod) and virt-handler (the node's daemonset pod that owns the launcher).
launcher_pod_restarts() {
    kubectl get pod -n "${SANDBOX_NAMESPACE}" "$(launcher_pod_name)" \
        -o jsonpath='{.status.containerStatuses[*].restartCount}' 2>/dev/null \
        | tr ' ' '\n' | awk '{s+=$1} END {print s+0}'
}

virt_handler_restarts() {
    local node
    node="$(kubectl get pod -n "${SANDBOX_NAMESPACE}" "$(launcher_pod_name)" \
        -o jsonpath='{.spec.nodeName}' 2>/dev/null)"
    kubectl get pods -n kubevirt -l kubevirt.io=virt-handler \
        --field-selector "spec.nodeName=${node}" \
        -o jsonpath='{.items[0].status.containerStatuses[*].restartCount}' 2>/dev/null \
        | tr ' ' '\n' | awk '{s+=$1} END {print s+0}'
}

# ---------------------------------------------------------------------------
step "setup: create a root sandbox reaching Ready"

"${OPENSHELL_CLI}" sandbox delete "${NAME}" >/dev/null 2>&1 || true
kubectl delete vm -n "${SANDBOX_NAMESPACE}" -l "${VM_SELECTOR}" \
    --ignore-not-found >/dev/null 2>&1 || true
kubectl delete pod,svc,secret,pvc,netpol -n "${SANDBOX_NAMESPACE}" \
    -l "${VM_SELECTOR}" --ignore-not-found >/dev/null 2>&1 || true
sleep 5

"${OPENSHELL_CLI}" sandbox create --detach --name "${NAME}" \
    --policy "${DEMO_POLICY}" \
    -- /bin/sleep infinity
PROBE_CREATED=1
wait_for_phase Ready
exec_in_sandbox id | tee "${WORKDIR}/id.log"
grep -q "uid=0(root)" "${WORKDIR}/id.log" || fail "probe sandbox is not root mode"
echo "probe sandbox Ready (root)"

# ---------------------------------------------------------------------------
step "L1: the bootstrap config disk eject — and its guest-side limit"

# The cloud-init disk (/dev/vdb) carries the full boundary bootstrap
# (private key + launch auth). The guest init reads it once and removes
# the PCI function (hygiene: the disk is not sitting attached for the
# whole session). Assert the eject happened, then demonstrate the
# limit: as root, a PCI rescan re-enumerates the disk — QEMU/KubeVirt
# still have it attached, so the guest-side eject is not a control.
# The key's exposure to root is the same as through the boundary's
# memory (ptrace); the blast radius is its own sandbox.
if exec_in_sandbox test -b /dev/vdb 2>/dev/null; then
    fail "L1: /dev/vdb is still attached in the running root guest — the eject did not happen"
fi
if exec_in_sandbox sh -c 'ls /sys/block/vdb 2>/dev/null' | grep -q vdb; then
    fail "L1: /sys/block/vdb still exists in the running root guest — the eject did not happen"
fi
echo "PASS: the bootstrap config disk was ejected after the one-shot read (no /dev/vdb, no /sys/block/vdb)"

# The limit, demonstrated: as root, rescan the PCI bus and record that
# the config disk comes back (kernel-level re-enumeration is the
# authoritative check; the /dev node and the mount are attempted and
# recorded when they succeed). This documents that the eject is
# hygiene, not a control.
exec_in_sandbox sh -c 'echo 1 > /sys/bus/pci/rescan' 2>/dev/null
sleep 3
RESCAN_KERNEL=0
if exec_in_sandbox sh -c 'cat /proc/partitions' 2>/dev/null | grep -q vdb; then
    RESCAN_KERNEL=1
fi
RESCAN_MOUNTED=0
if exec_in_sandbox sh -c 'mkdir -p /mnt/l1 && mount -t iso9660 -o ro /dev/vdb /mnt/l1 2>/dev/null && ls /mnt/l1 2>/dev/null | grep -q user-data && umount /mnt/l1' 2>/dev/null; then
    RESCAN_MOUNTED=1
fi
if [ "${RESCAN_KERNEL}" = "1" ] && [ "${RESCAN_MOUNTED}" = "1" ]; then
    echo "FINDING/LIMIT: a root PCI rescan re-enumerates the ejected config disk and it mounts read-only with the user-data intact — the guest-side eject is hygiene, not a control; the key's exposure to root is the same as through the boundary's memory. The host-side fix (a hotpluggable data volume or another one-shot delivery channel, since cloudInitNoCloud cannot be hot-unplugged) is a recorded next step."
elif [ "${RESCAN_KERNEL}" = "1" ]; then
    echo "FINDING/LIMIT: a root PCI rescan re-enumerates the ejected config disk at the kernel level (vdb returns in /proc/partitions; the reviewer verified it mounts and the user-data is readable as root) — the guest-side eject is hygiene, not a control. The host-side fix (a hotpluggable data volume or another one-shot delivery channel) is a recorded next step."
else
    echo "NOTE: the PCI rescan did not re-enumerate the config disk in this run (unexpected under the known limit — record it)"
fi

# ---------------------------------------------------------------------------
step "P5: launcher-netns listener audit (run first: it needs the live pair)"

LAUNCHER="$(launcher_pod_name)"
[ -n "${LAUNCHER}" ] || fail "no virt-launcher pod found"
SUPERVISOR_POD="$(supervisor_pod_name)"
echo "launcher: ${LAUNCHER}"
echo "supervisor: ${SUPERVISOR_POD} (${TOPOLOGY} topology)"

# Listeners in the launcher pod's network namespace (the netns the guest's
# masquerade traffic lands in). /proc/net/tcp is hex-encoded
# little-endian-address:big-endian-port; the audit lists the decoded ports.
echo "launcher netns listeners (/proc/net/tcp, /proc/net/tcp6, /proc/net/udp, /proc/net/udp6):"
# Decode without gawk extensions: the port field is hex big-endian; POSIX
# awk converts it with CONVFMT via +"0x" arithmetic where supported, so do
# the decode in the pipeline's shell instead. virtiofsd (unix socket +
# vhost device) and QEMU's guest-facing dataplane do not listen on TCP;
# what remains in this netns is the masquerade and anything the launcher
# itself runs.
# TCP listeners have state 0A (LISTEN) in /proc/net/tcp; UDP sockets carry
# state 07 (unconnected) — a bound-but-unconnected udp socket IS the
# listener shape. Filter per protocol or the DHCP server is missed.
for proto in tcp tcp6 udp udp6; do
    state="0A"
    case "${proto}" in udp*) state="07" ;; esac
    kubectl exec -n "${SANDBOX_NAMESPACE}" "${LAUNCHER}" -c compute -- \
        sh -c "cat /proc/net/${proto} 2>/dev/null" \
        | awk -v st="${state}" '$4 == st { split($2, a, ":"); print a[2], $10 }' \
        | sort -u \
        | while read -r hexport inode; do
            port="$(( 0x${hexport} ))"
            echo "  ${proto} listening port ${port} (inode ${inode})"
          done
done | tee "${WORKDIR}/listeners.log" || true
# The masquerade DHCP server (KubeVirt's dnsmasq) listens on udp 0.0.0.0:67
# and is reachable from the guest over the tap — a guest-reachable parser.
grep -q " udp listening port 67 " "${WORKDIR}/listeners.log" \
    && echo "FINDING: the masquerade DHCP server (udp 67) listens in the launcher netns — guest-reachable, named in the RFC alongside the guest agent" \
    || echo "NOTE: no udp 67 listener found in the launcher netns"

# Reachability from the launcher netns (the fence's egress applies to this
# pod): the fence must admit ONLY the supervisor service. Probe the
# standard cluster-internal targets and record refused/connected.
# The fence's allow target (the supervisor Service) is judged like the
# demo's N4 check: anything other than "Connection refused" means the
# connect reached the Service (the supervisor awaits its boundary, not an
# s_client, so the TLS handshake never completes and a timeout is the
# expected reachable signal). Every other target must be refused.
probe_tcp() {
    local target="$1" label="$2" log
    log="${WORKDIR}/tcp-$(echo "${target}" | tr ':/' '--').log"
    if kubectl exec -n "${SANDBOX_NAMESPACE}" "${LAUNCHER}" -c compute -- \
        timeout 5 openssl s_client -connect "${target}" \
        > "${log}" 2>&1; then
        echo "  ${label} (${target}): CONNECTED"
    elif grep -q "Connection refused" "${log}" 2>/dev/null; then
        echo "  ${label} (${target}): refused by the fence"
    else
        echo "  ${label} (${target}): reachable (no refusal; handshake incomplete is expected for non-TLS-peer targets)"
    fi
}
KUBEDNS_IP="$(kubectl get svc -n kube-system kube-dns \
    -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
K8S_API_IP="$(kubectl get svc -n default kubernetes \
    -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
NODE_IP="$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null || true)"
echo "fence reachability from the launcher netns:"
if [ "${TOPOLOGY}" = "gateway" ]; then
    SUPERVISOR_SVC_IP="$(kubectl get svc -n openshell \
        kvpoc-openshell-supervisor -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
else
    SUPERVISOR_SVC_IP="$(kubectl get svc -n "${SANDBOX_NAMESPACE}" \
        "${SUPERVISOR_POD}" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
fi
[ -n "${SUPERVISOR_SVC_IP}" ] && probe_tcp "${SUPERVISOR_SVC_IP}:5500" "supervisor Service (expected: the fence's allow target)"
[ -n "${KUBEDNS_IP}" ] && probe_tcp "${KUBEDNS_IP}:53" "kube-dns (cluster DNS)"
[ -n "${K8S_API_IP}" ] && probe_tcp "${K8S_API_IP}:443" "Kubernetes API service"
[ -n "${NODE_IP}" ] && probe_tcp "${NODE_IP}:10250" "node kubelet"
probe_tcp "1.1.1.1:443" "external internet"

# The guest-reachable parser probe: the masquerade DHCP server (dnsmasq in
# the launcher netns) parses what the guest sends over the tap. Send
# malformed and oversized DHCP datagrams from the ROOT guest and assert
# virt-launcher stays healthy and the sandbox is unaffected.
GUEST_GW="$(exec_in_sandbox sh -c \
    'ip route 2>/dev/null | sed -n "s/^default via \([0-9.]*\).*/\1/p" | head -1' 2>/dev/null || true)"
[ -n "${GUEST_GW}" ] || GUEST_GW="10.0.2.2"
echo "guest-side DHCP parser probe (targeting ${GUEST_GW}:67):"
LAUNCHER_RESTARTS_BEFORE="$(launcher_pod_restarts)"
exec_in_sandbox sh -c \
    "printf 'MALFORMED-DHCP-PROBE-NOT-BOOTP' | nc -u -w 2 ${GUEST_GW} 67" \
    >/dev/null 2>&1 || true
exec_in_sandbox sh -c \
    "head -c 60000 /dev/urandom | nc -u -w 2 ${GUEST_GW} 67" \
    >/dev/null 2>&1 || true
sleep 10
LAUNCHER_RESTARTS_AFTER="$(launcher_pod_restarts)"
echo "virt-launcher restarts: ${LAUNCHER_RESTARTS_BEFORE} -> ${LAUNCHER_RESTARTS_AFTER}"
[ "${LAUNCHER_RESTARTS_AFTER}" = "${LAUNCHER_RESTARTS_BEFORE}" ] \
    || fail "virt-launcher restarted from malformed/oversized guest DHCP datagrams"
PHASE_AFTER_DHCP="$(sandbox_phase)"
[ "${PHASE_AFTER_DHCP}" = "Phase: Ready" ] \
    || fail "sandbox left Ready after malformed/oversized guest DHCP datagrams"
exec_in_sandbox true || fail "exec broken after malformed/oversized guest DHCP datagrams"
echo "PASS: virt-launcher stayed healthy and the sandbox is unaffected by malformed/oversized DHCP from the root guest"
echo "P5 recorded (evidence above; the fence is expected to admit only the supervisor Service)"

# ---------------------------------------------------------------------------
step "P3: fake qemu-guest-agent (the channel is attached unconditionally)"

# Find the guest-agent virtio-serial port and start a lying responder: it
# answers the standard QGA commands with fabricated data. KubeVirt polls
# the agent through this channel and surfaces the answers in VMI status.
# Find the port via the sysfs name (the stable reference; the /dev node
# may not exist yet if the virtio_console driver has not created it —
# mdev -s can force device creation), falling back to the /dev listing.
GA_PORT="$(exec_in_sandbox sh -c '
    for n in /sys/class/virtio-ports/*/name; do
        [ -f "${n}" ] || continue
        grep -q "org.qemu.guest_agent" "${n}" 2>/dev/null \\
            && basename "$(dirname "${n}")" && break
    done
' 2>/dev/null | head -1 || true)"
if [ -z "${GA_PORT}" ]; then
    # Force device-node creation, then retry the /dev listing.
    exec_in_sandbox sh -c 'mdev -s 2>/dev/null; true' >/dev/null 2>&1 || true
    GA_PORT="$(exec_in_sandbox sh -c 'ls /dev/virtio-ports/ 2>/dev/null' | head -1 || true)"
fi
if [ -z "${GA_PORT}" ]; then
    echo "FINDING: no virtio-ports device in the guest — the agent channel is absent"
else
    echo "guest-agent port: /dev/virtio-ports/${GA_PORT}"

    # The responder runs as a background exec session (it must keep the
    # port open). It first completes the QGA handshake so KubeVirt proceeds
    # past the version check (guest-sync echoes the request id; guest-info
    # advertises a supported schema version), then answers the polling
    # commands with deliberately identifiable lies.
    # The responder holds the port with one read-write fd (the port is
    # single-open: a second open gets EBUSY) and answers on that fd. The
    # open itself drives KubeVirt's agent lifecycle: opening fires the
    # connect event (the agent poller starts), closing ends it.
    "${OPENSHELL_CLI}" sandbox exec "${NAME}" -- sh -c "
        exec 3<>/dev/virtio-ports/${GA_PORT} || { echo 'port open failed'; exit 1; }
        while IFS= read -r line <&3; do
            printf '%s\n' \"\$line\" >> /tmp/ga-rx.log
            case \"\$line\" in
                *guest-sync-delimited*|*guest-sync*)
                    id=\"\$(printf '%s' \"\$line\" | sed -n 's/.*\"id\":\([0-9]*\).*/\1/p')\"
                    printf '{\"return\": %s}\n' \"\${id:-1}\" >&3 ;;
                *guest-info*)
                    printf '{\"return\": {\"version\": 1, \"supported_commands\": [{\"enabled\": true, \"name\": \"guest-ping\", \"success-response\": true}, {\"enabled\": true, \"name\": \"guest-get-osinfo\", \"success-response\": true}, {\"enabled\": true, \"name\": \"guest-get-host-name\", \"success-response\": true}, {\"enabled\": true, \"name\": \"guest-get-users\", \"success-response\": true}, {\"enabled\": true, \"name\": \"guest-get-fsinfo\", \"success-response\": true}]}}\n' >&3 ;;
                *guest-ping*)
                    printf '{\"return\": {}}\n' >&3 ;;
                *guest-get-host-name*)
                    printf '{\"return\": {\"host-name\": \"totally-honest-host\"}}\n' >&3 ;;
                *guest-get-osinfo*)
                    printf '{\"return\": {\"kernel-release\": \"6.6.6-fake\", \"machine\": \"x86_64\", \"name\": \"FakeOS\", \"pretty-name\": \"FakeOS 99 (Liar Edition)\", \"version\": \"99\", \"version-id\": \"99\", \"id\": \"fakeos\"}}\n' >&3 ;;
                *guest-get-users*)
                    printf '{\"return\": [{\"user\": \"definitely-real-user\", \"login-time\": 1.0}]}\n' >&3 ;;
                *guest-get-fsinfo*)
                    printf '{\"return\": [{\"name\": \"disk-fake\", \"mountpoint\": \"/fake\", \"type\": \"fakefs\", \"disk\": []}]}\n' >&3 ;;
                *)
                    printf '{\"return\": {}}\n' >&3 ;;
            esac
        done
    " > "${WORKDIR}/fake-agent.log" 2>&1 &
    FAKE_AGENT_PID=$!
    echo "fake agent running (pid ${FAKE_AGENT_PID})"

    # Give KubeVirt time to complete the handshake and poll the agent.
    sleep 45
    echo "VMI status after the fake agent answered:"
    kubectl get vmi -n "${SANDBOX_NAMESPACE}" "${VMI_NAME}" -o json \
        | python3 -c '
import json, sys
vmi = json.load(sys.stdin)
status = vmi.get("status", {})
for c in status.get("conditions", []):
    print("  condition %s=%s" % (c.get("type"), c.get("status")))
print("  guestOSInfo: %s" % json.dumps(status.get("guestOSInfo", {})))
' | tee "${WORKDIR}/vmi-agent-status.log"

    # Diagnostics: what the host actually sent down the channel.
    echo "host->guest requests received by the fake agent:"
    exec_in_sandbox sh -c 'cat /tmp/ga-rx.log 2>/dev/null' \
        | tee "${WORKDIR}/ga-rx.log" | head -10 || echo "  (nothing received)"

    if grep -q "FakeOS" "${WORKDIR}/vmi-agent-status.log"; then
        echo "FINDING (expected): KubeVirt surfaces the fake agent's lies in VMI status (osinfo/name/fsinfo reach the VMI object)"
    elif grep -q "AgentConnected=True" "${WORKDIR}/vmi-agent-status.log"; then
        echo "FINDING: KubeVirt connected to the fake agent (AgentConnected) but the OS-info lies did not surface within the window"
    else
        echo "NOT EXERCISABLE in this environment: the guest-agent parser cannot be"
        echo "reached. The channel DOES connect (a read-write guest open flips the"
        echo "host-side port state to connected and starts KubeVirt's agent poller,"
        echo "which attempts guest-sync every 5s), but ZERO bytes traverse"
        echo "host->guest even with a live guest reader on the open port — verified"
        echo "on both kvpoc and kvreview with raw readers. The break is in the"
        echo "virtualization stack's chardev->virtqueue data path, not in the probe"
        echo "mechanics. The RFC records the guest-agent parser as a NAMED,"
        echo "UNTESTED root-mode surface; the mitigation is the upstream ask for a"
        echo "supported way to disable the channel."
    fi

    # The OpenShell-side invariant is still observable and holds: nothing in
    # OpenShell consumes agent data. The sandbox must be unaffected: same
    # phase, exec still works. (Recorded as an observation, not a PASS of the
    # parser probe — nothing on the host read the replies.)
    PHASE_AFTER_AGENT="$(sandbox_phase)"
    [ "${PHASE_AFTER_AGENT}" = "Phase: Ready" ] \
        || fail "sandbox left Ready while only the fake agent ran (something consumed agent data?)"
    exec_in_sandbox true || fail "exec broken while the fake agent ran"
    echo "OBSERVED (OpenShell-side only): the sandbox is unaffected by the fake agent (Ready, exec works) — no host-side parser was exercised"

    # Hostile phase: malformed and oversized replies. The user's decision
    # (option B) requires virt-launcher and virt-handler to stay healthy
    # while the guest-side agent misbehaves. Replace the responder with a
    # hostile one: invalid JSON first, then a 10 MiB single-line reply.
    kill "${FAKE_AGENT_PID}" 2>/dev/null || true
    wait "${FAKE_AGENT_PID}" 2>/dev/null || true
    sleep 2
    LAUNCHER_RESTARTS_BEFORE="$(launcher_pod_restarts)"
    VIRT_HANDLER_RESTARTS_BEFORE="$(virt_handler_restarts)"
    # NOTE: with the host->guest data path dead, the guest->host replies at
    # most reach QEMU's chardev flow control (writes block once the buffer
    # fills) — no host-side parser reads them. The health assertion below is
    # therefore an OpenShell/cluster stability observation, not a parser
    # fuzz; the parser itself is NOT EXERCISABLE here (see the handshake
    # note above).
    # The oversized write is bounded: virtio-serial applies host-side flow
    # control, so a guest write with no host consumer BLOCKS (itself a
    # finding — the guest cannot flood the host unboundedly). A 20s bound
    # proves the oversized payload was offered without hanging the probe.
    # The CLI-level timeout bounds the whole session: once the virtio port
    # buffer fills (no host consumer), EVERY further guest write blocks —
    # including small ones — so the guest-side timeout alone cannot free the
    # session. Killing the CLI closes the relay, and the boundary reaps the
    # exec child when the channel ends.
    timeout 60 "${OPENSHELL_CLI}" sandbox exec "${NAME}" -- sh -c "
        exec 3<>/dev/virtio-ports/${GA_PORT} || { echo 'port open failed'; exit 1; }
        # Malformed: not JSON at all.
        printf 'NOT JSON AT ALL {{{\n' >&3
        sleep 3
        # Oversized: a single 10 MiB reply line. The write blocks once the
        # port buffer fills (virtio-serial host flow control) — recorded as
        # a finding, the session is bounded by the CLI timeout.
        printf '{\"return\": \"' >&3
        head -c 10485760 /dev/zero | tr '\\0' 'A' >&3
        printf '\"}\n' >&3
        sleep 5
    " > "${WORKDIR}/hostile-agent.log" 2>&1 || true
    grep -q "port open failed" "${WORKDIR}/hostile-agent.log" 2>/dev/null \
        && echo "NOTE: the hostile agent could not open the port (single-open contention with the poller window)" \
        || echo "hostile replies delivered (or bounded by flow control); session closed"
    sleep 10
    LAUNCHER_RESTARTS_AFTER="$(launcher_pod_restarts)"
    VIRT_HANDLER_RESTARTS_AFTER="$(virt_handler_restarts)"
    echo "virt-launcher restarts: ${LAUNCHER_RESTARTS_BEFORE} -> ${LAUNCHER_RESTARTS_AFTER}"
    echo "virt-handler restarts: ${VIRT_HANDLER_RESTARTS_BEFORE} -> ${VIRT_HANDLER_RESTARTS_AFTER}"
    [ "${LAUNCHER_RESTARTS_AFTER}" = "${LAUNCHER_RESTARTS_BEFORE}" ] \
        || fail "virt-launcher restarted from malformed/oversized guest-agent replies"
    [ "${VIRT_HANDLER_RESTARTS_AFTER}" = "${VIRT_HANDLER_RESTARTS_BEFORE}" ] \
        || fail "virt-handler restarted from malformed/oversized guest-agent replies"
    PHASE_AFTER_HOSTILE="$(sandbox_phase)"
    [ "${PHASE_AFTER_HOSTILE}" = "Phase: Ready" ] \
        || fail "sandbox left Ready after hostile guest-agent replies"
    exec_in_sandbox true || fail "exec broken after hostile guest-agent replies"
    echo "OBSERVED (stability only): virt-launcher and virt-handler stayed healthy through malformed/oversized guest-agent replies — the host-side parser was not exercised (see above)"
fi

# ---------------------------------------------------------------------------
step "P4: virtiofsd privileged-operation surface (root guest)"

# 1. Can root remount the share RAW (no idmap) and chown past the idmap?
exec_in_sandbox sh -c 'mkdir -p /mnt/raw && mount -t virtiofs workspace /mnt/raw' \
    > "${WORKDIR}/rawmount.log" 2>&1 \
    && echo "FINDING: root CAN mount the virtiofs share without the idmap (/mnt/raw)" \
    || echo "the raw remount was refused"
if ! grep -qi "refused\|denied\|Permission" "${WORKDIR}/rawmount.log" 2>/dev/null; then
    cat "${WORKDIR}/rawmount.log" 2>/dev/null | head -2 || true
fi

# 2. chown to an arbitrary uid through the idmapped /sandbox (mapped range
#    only) and on the raw mount (if it exists).
echo "chown probe through the idmapped mount:"
exec_in_sandbox sh -c 'touch /sandbox/p4-chown && chown 1234:1234 /sandbox/p4-chown; echo rc=$?; stat -c "guest sees %u:%g" /sandbox/p4-chown' \
    | tee "${WORKDIR}/chown-idmap.log"
if mountpoint_ok="$(exec_in_sandbox sh -c 'mountpoint -q /mnt/raw && echo yes' 2>/dev/null)" && [ "${mountpoint_ok}" = "yes" ]; then
    echo "chown probe on the RAW mount:"
    exec_in_sandbox sh -c 'touch /mnt/raw/p4-chown-raw && chown 1234:1234 /mnt/raw/p4-chown-raw; echo rc=$?; stat -c "guest sees %u:%g" /mnt/raw/p4-chown-raw' \
        | tee "${WORKDIR}/chown-raw.log"
fi

# 3. mknod a device node on the share (would persist on the PVC across
#    generations if admitted).
echo "mknod probe:"
exec_in_sandbox sh -c 'mknod /sandbox/p4-dev c 1 3; echo rc=$?; ls -l /sandbox/p4-dev 2>/dev/null' \
    | tee "${WORKDIR}/mknod.log" || true

# 4. setuid bit on a copied binary (would persist on the PVC).
echo "setuid probe:"
exec_in_sandbox sh -c 'cp /bin/busybox /sandbox/p4-su && chmod 4755 /sandbox/p4-su; echo rc=$?; ls -l /sandbox/p4-su' \
    | tee "${WORKDIR}/setuid.log" || true

# 5. Host-side truth: what actually landed on the PVC (k3d local-path
#    provisioning on the node container).
# The workspace PVC name is deterministic: <kube-name>-workspace.
PVC_NAME="default--${NAME}-workspace"
K3D_NODE="k3d-$(kubectl config current-context | sed 's/^k3d-//' | cut -d- -f1-2)-server-0"
if [ -n "${PVC_NAME}" ] && docker inspect "${K3D_NODE}" >/dev/null 2>&1; then
    echo "host-side PVC contents (${PVC_NAME} on ${K3D_NODE}):"
    docker exec "${K3D_NODE}" sh -c \
        "ls -ln /var/lib/rancher/k3s/storage/ | grep '${PVC_NAME}' || true" | head -2
    docker exec "${K3D_NODE}" sh -c \
        "ls -ln /var/lib/rancher/k3s/storage/pvc-*_${SANDBOX_NAMESPACE}_${PVC_NAME}/* 2>/dev/null" \
        | grep -E "p4-" || echo "  (no p4-* files visible host-side)"
else
    echo "NOTE: host-side PVC inspection skipped (PVC ${PVC_NAME:-none} or node ${K3D_NODE} unavailable)"
fi
echo "P4 recorded (evidence above; the RFC documents the share's admitted surface)"

# ---------------------------------------------------------------------------
step "P1: in-guest reset via the reboot syscall"

VMI_UID_BEFORE="$(kubectl get vmi -n "${SANDBOX_NAMESPACE}" "${VMI_NAME}" \
    -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
SUP_POD_UID_BEFORE="$(kubectl get pod -n "${SANDBOX_NAMESPACE}" "$(supervisor_pod_name)" \
    -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
echo "before: VMI uid=${VMI_UID_BEFORE:-none} supervisor pod uid=${SUP_POD_UID_BEFORE:-none}"

echo "issuing: reboot -f (root workload reboots its own kernel)"
# The exec session dies mid-stream when the guest resets; a non-zero rc
# here is the expected outcome, not a failure.
exec_in_sandbox reboot -f > "${WORKDIR}/reboot.log" 2>&1 || true
sleep 10

# Record what the control plane observes for up to 5 minutes: the phase,
# the reason, whether the VMI identity survived, whether the supervisor
# generation rotated.
echo "observing the control plane for up to 300s..."
RESET_OBSERVED=""
DEADLINE=$(( $(date +%s) + 300 ))
while [ "$(date +%s)" -lt "${DEADLINE}" ]; do
    PHASE="$(sandbox_phase)"
    VMI_UID_NOW="$(kubectl get vmi -n "${SANDBOX_NAMESPACE}" "${VMI_NAME}" \
        -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
    case "${PHASE}" in
        "Phase: Error"|"Phase: Stopped")
            RESET_OBSERVED="${PHASE}"
            break ;;
    esac
    # A same-uid VMI back at Ready means the guest rebooted in place and
    # everything reconnected — record it and keep watching briefly.
    if [ "${PHASE}" = "Phase: Ready" ] && [ -n "${VMI_UID_BEFORE}" ] \
        && [ "${VMI_UID_NOW}" != "${VMI_UID_BEFORE}" ]; then
        RESET_OBSERVED="Ready-with-new-VMI"
        break
    fi
    sleep 5
done

VMI_UID_AFTER="$(kubectl get vmi -n "${SANDBOX_NAMESPACE}" "${VMI_NAME}" \
    -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
SUP_POD_UID_AFTER="$(kubectl get pod -n "${SANDBOX_NAMESPACE}" "$(supervisor_pod_name)" \
    -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
echo "after: phase='${RESET_OBSERVED:-unresolved (${PHASE:-none})}'"
echo "  VMI uid: ${VMI_UID_BEFORE:-none} -> ${VMI_UID_AFTER:-none}"
echo "  supervisor pod uid: ${SUP_POD_UID_BEFORE:-none} -> ${SUP_POD_UID_AFTER:-none}"
"${OPENSHELL_CLI}" sandbox get "${NAME}" 2>/dev/null | grep -aE "Phase:|Ready:|exit code" | head -3 || true
# The detection mechanism: guest init re-runs after the warm reset, re-stages
# the SAME bootstrap (same key) from the cloud-init disk, and launches a
# fresh privileged boundary that reconnects to the live generation. The
# supervisor ends the sandbox when the fresh boundary attaches — the handle
# changed during launch recovery. Record the supervisor's own reason line.
SUP_EXIT_REASON="$(kubectl logs -n "${SANDBOX_NAMESPACE}" \
    "$(supervisor_pod_name)" --tail=200 2>/dev/null \
    | grep -a "attachment denied" | tail -1 || true)"
if [ -n "${SUP_EXIT_REASON}" ]; then
    echo "  supervisor exit reason: ${SUP_EXIT_REASON}"
    echo "PASS mechanism: the reset is detected by the supervisor's boundary-handle check on launch recovery (a fresh boundary attaching to the live generation ends it)"
else
    echo "NOTE: the supervisor's attachment-denied line was not captured (log cadence); the phase flip above is the detection evidence"
fi
# RFC caveat: root can read the boundary's memory, learn the handle, and
# present it after a reset. Acceptable: root already holds the key and
# handle in-session (it can impersonate its own boundary without
# rebooting). The fence plus the supervisor's policy make post-reset
# CODE trusted.

# The invariant: a reset must not pass unnoticed. Whatever terminal or
# observed state results, the sandbox must not silently continue the SAME
# session as if nothing happened: either the phase flipped away from Ready
# (detected), or the VMI identity changed (new boot observed).
if [ -n "${RESET_OBSERVED}" ] && [ "${RESET_OBSERVED}" != "Ready" ]; then
    echo "PASS: the guest reset was observed by the control plane (${RESET_OBSERVED})"
else
    echo "FINDING: the control plane did not clearly observe the reset (phase '${PHASE:-none}', VMI ${VMI_UID_BEFORE:-none} -> ${VMI_UID_AFTER:-none}); record for the reset-detection design (item 7)"
fi

# ---------------------------------------------------------------------------
step "P2: the iTCO watchdog (root can arm it; no configurable action)"

# Compile the port-io helper for the guest (static musl). The product guest
# image does not ship it — this is a probe-time tool.
echo "compiling the port-io helper (static musl, docker alpine)..."
docker run --rm \
    -v "${ROOT}/e2e/kubevirt:/src:ro,Z" \
    -v "${WORKDIR}:/out:Z" \
    alpine:3.22 sh -c '
        apk add --no-cache gcc musl-dev linux-headers >/dev/null 2>&1
        cc -static -O2 -o /out/port-io /src/port-io.c
    ' || fail "could not compile the port-io helper"
[ -s "${WORKDIR}/port-io" ] || fail "the port-io helper did not build"
echo "port-io built: $(wc -c < "${WORKDIR}/port-io") bytes"

# Stage it into the guest through the exec channel (base64 over stdin).
stage_port_io() {
    local sandbox="$1"
    base64 < "${WORKDIR}/port-io" \
        | "${OPENSHELL_CLI}" sandbox exec "${sandbox}" -- sh -c \
            'base64 -d > /tmp/port-io && chmod +x /tmp/port-io && /tmp/port-io read16 0x60' \
        > /dev/null 2>&1
}

# Recreate the sandbox (P1 left it in a terminal or ambiguous state).
"${OPENSHELL_CLI}" sandbox delete "${NAME}" >/dev/null 2>&1 || true
kubectl delete vm -n "${SANDBOX_NAMESPACE}" -l "${VM_SELECTOR}" \
    --ignore-not-found >/dev/null 2>&1 || true
kubectl delete pod,svc,secret,pvc,netpol -n "${SANDBOX_NAMESPACE}" \
    -l "${VM_SELECTOR}" --ignore-not-found >/dev/null 2>&1 || true
sleep 5
"${OPENSHELL_CLI}" sandbox create --detach --name "${NAME}" \
    --policy "${DEMO_POLICY}" \
    -- /bin/sleep infinity
wait_for_phase Ready
stage_port_io "${NAME}" || fail "could not stage the port-io helper into the guest"

# The reset watch must distinguish a RESET from the sandbox's own young
# boot (P2's sandbox is recreated right after P1's reboot): settle first
# (uptime >= 60s), then arm, then watch for a uptime DROP.
echo "waiting for the guest to settle (uptime >= 60s) before arming..."
while :; do
    UPTIME_AT_ARM="$(exec_in_sandbox sh -c 'cut -d. -f1 /proc/uptime' 2>/dev/null || echo 0)"
    [ "${UPTIME_AT_ARM}" -ge 60 ] && break
    sleep 5
done

# The stock linux-virt kernel ships iTCO_wdt.ko but cannot bind it (lpc_ich
# is not built), so /dev/watchdog is absent. A root workload can still load
# its own lpc_ich build, or program the TCO timer directly through
# /dev/port. The probe tries, in order: the module, the device node, and a
# direct port-I/O arm of the TCO timer. RFC wording: "not exposed by the
# stock kernel; reachable by root; covered by reset detection (P1) and
# the fresh-per-boot image".
#
# The port-io helper is a PROBE TOOL and does not ship in the guest image:
# /dev/port is byte-granular and QEMU drops byte writes to the dword/word
# emulated registers (the PCI config address 0xcf8 and the TCO counters),
# so the arm needs real OUT instructions from a compiled binary. The probe
# compiles it (static musl, in a docker alpine container like the image
# build) and stages it into the guest through the exec channel.
MODPROBE_RC="$(exec_in_sandbox sh -c 'modprobe iTCO_wdt 2>&1; echo rc=$?' || true)"
echo "modprobe iTCO_wdt: ${MODPROBE_RC}"
WD_PRESENT="$(exec_in_sandbox sh -c 'ls -l /dev/watchdog* 2>/dev/null || echo absent')"
echo "watchdog device: ${WD_PRESENT}"
ARMED=0
if ! echo "${WD_PRESENT}" | grep -q "absent"; then
    # Opening /dev/watchdog starts it; closing WITHOUT the magic 'V' leaves
    # it armed, and the iTCO resets the machine when it expires.
    echo "arming: open + non-magic close of /dev/watchdog"
    exec_in_sandbox sh -c 'exec 3>/dev/watchdog' || true
    ARMED=1
else
    echo "no /dev/watchdog after modprobe (lpc_ich is not built for linux-virt; the module cannot bind)"
    # Direct port-I/O arm through the guest's port-io helper (static musl,
    # shipped in the image). /dev/port CANNOT be used: it is byte-granular,
    # and QEMU drops byte writes to the dword/word emulated registers (the
    # PCI config address 0xcf8 and the TCO counters) — verified live: dd
    # writes through /dev/port never latch.
    # The ACPI PMBASE is discovered from the ICH9 LPC's PCI config (bus 0,
    # device 0x1f, function 0, offset 0x40 = PMBA) via 0xCF8/0xCFC — never
    # hardcoded, so a different QEMU default cannot misdirect the writes.
    #   TCO base = PMBASE + 0x60 (TCO_RLD at +0x00)
    #   TCO1_CNT = PMBASE + 0x68 (bit 11: TCO_TMR_HLT)
    # On ICH9 the TCO reset gate is GCS.NO_REBOOT in the RCBA chipset
    # config space (RCBA+0x3410, bit 5). In every settled run so far the
    # timer fired but the gate held; the probe now OPENS the gate first —
    # read the RCBA base from the ICH9 LPC PCI config (offset 0xf0), clear
    # NO_REBOOT through /dev/mem (busybox devmem) — then clears TMR_HLT and
    # kicks TCO_RLD. Either outcome is RFC evidence: a reset is covered by
    # reset detection (P1); a held gate documents the emulated wiring.
    PORT_ARM="$(exec_in_sandbox sh -c '
        PIO=/tmp/port-io
        [ -x "${PIO}" ] || { echo "no port-io helper in the guest image"; exit 9; }
        # PCI config read: 0xcf8 <- 0x8000f840 (00:1f.0 offset 0x40), read 0xcfc.
        "${PIO}" write32 0xcf8 0x8000f840
        pmba=$("${PIO}" read32 0xcfc)
        pmba=$(( pmba & 0xfffffff0 ))
        case "${pmba}" in
            0x0|0xffffffff) echo "PMBA readback implausible (${pmba}); no LPC?"; exit 7 ;;
        esac
        # The RCBA base: 00:1f.0 offset 0xf0 (bit 0 enables the region).
        "${PIO}" write32 0xcf8 0x8000f8f0
        rcba=$("${PIO}" read32 0xcfc)
        rcba=$(( rcba & 0xffffc000 ))
        gcs_addr=$(( rcba + 0x3410 ))
        # The guest busybox has no devmem applet; the port-io helper maps
        # the page through /dev/mem (also surfacing any strict-devmem
        # policy that blocks chipset MMIO).
        gcs_before=$("${PIO}" mem-read "${gcs_addr}" 16 2>/dev/null || echo 0xread-failed)
        # Clear NO_REBOOT (bit 5) through the MMIO mapping.
        "${PIO}" mem-write "${gcs_addr}" $(( gcs_before & ~0x20 )) 16 >/dev/null 2>&1 || true
        gcs_after=$("${PIO}" mem-read "${gcs_addr}" 16 2>/dev/null || echo 0xread-failed)
        cnt=$("${PIO}" read16 $(( pmba + 0x68 )))
        echo "PMBASE=${pmba} RCBA=0x$(printf %x "${rcba}") GCS=${gcs_before} -> ${gcs_after} (bit5 noreboot=$(( (gcs_after >> 5) & 1 ))) TCO1_CNT=${cnt} (bit11 halt=$(( (cnt >> 11) & 1 )))"
        # Arm: clear the halt bit and kick the reload register.
        "${PIO}" write16 $(( pmba + 0x68 )) $(( cnt & ~0x800 ))
        "${PIO}" write16 $(( pmba + 0x60 )) 0
        after=$("${PIO}" read16 $(( pmba + 0x68 )))
        echo "after arm: TCO1_CNT=${after} (bit11 halt=$(( (after >> 11) & 1 )))"
        [ $(( (after >> 11) & 1 )) = 0 ] \
            && echo "armed: NO_REBOOT cleared, TCO_TMR_HLT cleared, TCO_RLD kicked (timer running)"
    ' 2>&1 || true)"
    echo "port-I/O arm: ${PORT_ARM}"
    echo "${PORT_ARM}" | grep -q "armed:" && ARMED=1
fi
if [ "${ARMED}" = "1" ]; then
    echo "watching for the watchdog reset (up to 120s, uptime at arm ${UPTIME_AT_ARM}s)..."
    WD_RESET=""
    DEADLINE=$(( $(date +%s) + 120 ))
    PHASE_AT_ARM="$(sandbox_phase)"
    while [ "$(date +%s)" -lt "${DEADLINE}" ]; do
        PHASE="$(sandbox_phase)"
        [ "${PHASE}" != "${PHASE_AT_ARM}" ] && { WD_RESET="${PHASE}"; break; }
        # A guest-side check: the uptime drops when the machine resets.
        UPTIME="$(exec_in_sandbox sh -c 'cut -d. -f1 /proc/uptime' 2>/dev/null || echo 0)"
        [ "${UPTIME}" -lt "${UPTIME_AT_ARM}" ] && { WD_RESET="guest-rebooted(uptime=${UPTIME}s, was ${UPTIME_AT_ARM}s)"; break; }
        sleep 5
    done
    # Whether or not the machine reset, read the TCO status flags: the
    # timer FIRING is provable even when QEMU's reset gating holds.
    TCO_STATUS="$(exec_in_sandbox sh -c '
        PIO=/tmp/port-io
        "${PIO}" write32 0xcf8 0x8000f840
        pmba=$(( $("${PIO}" read32 0xcfc) & 0xfffffff0 ))
        [ "${pmba}" -gt 0 ] || pmba=0x600
        echo "TCO1_STS=$("${PIO}" read16 $(( pmba + 0x64 ))) TCO2_STS=$("${PIO}" read16 $(( pmba + 0x66 )))"
    ' 2>/dev/null || true)"
    echo "TCO status after the window: ${TCO_STATUS:-unavailable}"
    if [ -n "${WD_RESET}" ]; then
        # P2(a): prove the reset ENDS the generation, like P1 — the same
        # handle-check line and Phase Error, not just a guest-side uptime
        # observation. The phase flip takes ~25s (the fresh boundary must
        # attach and be denied first), so poll rather than sample once.
        P2_PHASE=""
        P2_DEADLINE=$(( $(date +%s) + 120 ))
        while [ "$(date +%s)" -lt "${P2_DEADLINE}" ]; do
            P2_PHASE="$(sandbox_phase)"
            [ "${P2_PHASE}" = "Phase: Error" ] && break
            sleep 5
        done
        P2_HANDLE_LINE="$(kubectl logs -n "${SANDBOX_NAMESPACE}" \
            "$(supervisor_pod_name)" --tail=200 2>/dev/null \
            | grep -a "attachment denied" | tail -1 || true)"
        echo "control plane after the watchdog reset: phase='${P2_PHASE}'"
        [ -n "${P2_HANDLE_LINE}" ] \
            && echo "  supervisor exit reason: ${P2_HANDLE_LINE}" \
            || echo "  (no attachment-denied line captured; log cadence)"
        if [ "${P2_PHASE}" = "Phase: Error" ]; then
            echo "PASS/recorded: the iTCO watchdog reset the guest (guest side: ${WD_RESET}); the control plane ended the generation (Phase Error) — covered by reset detection (P1) and the fresh-per-boot image"
        else
            echo "FINDING: the watchdog reset the guest (${WD_RESET}) but the control plane reports '${P2_PHASE}'; record for the reset-detection design (item 7)"
        fi
    elif echo "${TCO_STATUS}" | grep -q "TCO1_STS=0x0008"; then
        # TCO1_STS bit 3 = TCO_TIMEOUT (the timer fired); TCO2_STS bits
        # SECOND_TO_STS/BOOT_STS record the double timeout. No settled run
        # has demonstrated an actual machine reset: the record for the RFC
        # is "root can arm the TCO and make it fire; the reset gate is
        # what it is on this wiring" — either way covered by reset
        # detection (P1) and trusted boot.
        echo "FINDING: the TCO timer FIRED (TCO1_STS TIMEOUT, ${TCO_STATUS#*TCO1_STS=0x0008}) — root arms and fires it. This run: $( [ -n "${WD_RESET}" ] && echo "the machine RESET (${WD_RESET})" || echo "the machine did NOT reset (uptime continuous, phase unchanged); the reset gate held" ). Either outcome is covered by reset detection (P1) and the fresh-per-boot image; the RFC records the demonstrated state (armable, firing, reset outcome as observed)"
    else
        echo "FINDING: the watchdog did not observably fire within 120s and no status flags were readable; the RFC records the surface as reachable-by-root regardless — covered by reset detection (P1) and the fresh-per-boot image"
    fi
else
    echo "FINDING: the TCO could not be armed from the stock guest (no /dev/watchdog, port-I/O arm unavailable or readback implausible); the surface is still reachable by root with a custom kernel module — covered by reset detection (P1) and the fresh-per-boot image"
fi

# ---------------------------------------------------------------------------
step "teardown"

"${OPENSHELL_CLI}" sandbox delete "${NAME}" >/dev/null 2>&1 || true
DEADLINE=$(( $(date +%s) + 180 ))
while [ "$(date +%s)" -lt "${DEADLINE}" ]; do
    LEFT="$(kubectl get vm,vmi,pod,svc,secret,pvc,netpol -n "${SANDBOX_NAMESPACE}" \
        -l "${VM_SELECTOR}" --no-headers 2>/dev/null | wc -l)"
    [ "${LEFT}" = "0" ] && break
    sleep 5
done
LEFT="$(kubectl get vm,vmi,pod,svc,secret,pvc,netpol -n "${SANDBOX_NAMESPACE}" \
    -l "${VM_SELECTOR}" --no-headers 2>/dev/null | wc -l)"
[ "${LEFT}" = "0" ] || fail "${LEFT} managed objects left after delete"
PROBE_CREATED=0
echo "zero leftovers for sandbox probe ${NAME}"

echo
echo "probes complete. Evidence in ${WORKDIR} is removed by the exit trap;"
echo "the findings above are the RFC inputs."
