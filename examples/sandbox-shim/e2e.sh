#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# End-to-end checks through a real gateway, supervisor, and guest:
#
#   ./e2e.sh <firecracker|gvisor> <privileged|nonprivileged>
#
# Takes the same environment as run.sh. Set SHIM_E2E_SKIP_INTERNET=1 to skip
# the allowed-egress check when the host has no internet access.
# shellcheck disable=SC2016 # guest scripts are single-quoted on purpose; they expand inside the sandbox.
# shellcheck disable=SC2012 # ls only lists the driver-generated vm-/gv- state directories.
set -euo pipefail

substrate="${1:-}"
privilege="${2:-}"
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
repo_dir="$(cd ../.. && pwd)"
openshell="$repo_dir/target/debug/openshell"
export SHIM_PORT="${SHIM_PORT:-18781}"
export OPENSHELL_GATEWAY_ENDPOINT="http://127.0.0.1:$SHIM_PORT"
state_file="$(mktemp /tmp/sbx-shim-e2e.XXXXXX)"
# Firecracker mediates every socket natively; gVisor uses the CONNECT proxy.
policy="policy.yaml"
[[ "$substrate" == firecracker ]] && policy="policy-firecracker.yaml"
export SHIM_STATE_FILE="$state_file"

./run.sh "$substrate" "$privilege" > "$state_file.run.log" 2>&1 &
runner=$!
cleanup() {
  kill "$runner" 2>/dev/null || true
  wait "$runner" 2>/dev/null || true
  rm -f "$state_file"
}
trap cleanup EXIT

for ((i=0; i<600; i++)); do
  [[ -s "$state_file" ]] && break
  if ! kill -0 "$runner" 2>/dev/null; then cat "$state_file.run.log" >&2; exit 1; fi
  sleep 1
done
state="$(cat "$state_file")"
for ((i=0; i<60; i++)); do
  "$openshell" sandbox list > /dev/null 2>&1 && break
  sleep 1
done

failures=0
pass() { printf 'PASS %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1"; failures=$((failures + 1)); }
expect() { # name, haystack, needle
  if grep -qF -- "$3" <<<"$2"; then pass "$1"; else fail "$1 (missing: $3)"; printf '%s\n' "$2" | sed 's/^/    | /'; fi
}
expect_re() { # name, haystack, extended regex
  if grep -qE -- "$3" <<<"$2"; then pass "$1"; else fail "$1 (no match: $3)"; fi
}
# Directory and log of the most recently started guest.
latest_guest() { ls -td "$state"/vm-* "$state"/gv-* 2>/dev/null | head -1 || true; }
guest_log() {
  local dir
  dir="$(latest_guest)"
  [[ -n "$dir" ]] && cat "$dir"/console.log "$dir"/guest.log 2>/dev/null || true
}

# Run one command as the sandbox main process; prints output, then EXIT=<code>.
run_main() {
  local name="$1"; shift
  local output code=0
  output="$(timeout 300 "$openshell" sandbox create --name "$name" --no-keep --no-tty \
    --no-auto-providers --policy "$policy" -- "$@" 2>&1)" || code=$?
  printf '%s\nEXIT=%s\n' "$output" "$code"
  for ((i=0; i<60; i++)); do
    "$openshell" sandbox get "$name" > /dev/null 2>&1 || break
    sleep 1
  done
}

# 1. Output, exit status, substrate, identity, and a subprocess tree.
if [[ "$substrate" == firecracker ]]; then kernel_marker="6.1."; else kernel_marker="gvisor"; fi
if [[ "$privilege" == privileged ]]; then
  identity_script='echo uid=$(id -u); cat /proc/self/uid_map; grep CapEff /proc/self/status;
    mkdir -p /tmp/m && mount -t tmpfs none /tmp/m && echo mount-ok;
    touch /tmp/owned && chown 123:456 /tmp/owned && stat -c owner=%u:%g /tmp/owned'
  identity_script="$identity_script; mkdir /new-top-level && rmdir /new-top-level && echo top-level-write-ok"
  identity_checks=("uid-is-namespace-root:uid=0" "uid-map:100000" "mount-ok" "owner=123:456"
    "writable own rootfs:top-level-write-ok")
else
  identity_script='echo uid=$(id -u); grep NoNewPrivs /proc/self/status; touch /usr/should-fail 2>&1 || echo write-denied'
  identity_checks=("uid:uid=10001" "NoNewPrivs:	1" "write-denied")
fi
out="$(run_main basic /bin/bash -c "cat /proc/version; $identity_script;
  sh -c 'sh -c \"echo child-of-\\\$PPID\"';
  echo to-stderr >&2; exit 7")"
expect "main process exit code propagates" "$out" "EXIT=7"
expect "runs inside $substrate" "$out" "$kernel_marker"
expect "stderr is streamed" "$out" "to-stderr"
expect "subprocess tree runs" "$out" "child-of-"
for check in "${identity_checks[@]}"; do
  expect "$privilege identity: ${check%%:*}" "$out" "${check#*:}"
done

# 2. Networking.
if [[ "$substrate" == firecracker ]]; then
  # Native mediation: no proxy settings; every socket goes through the broker.
  dns_probe="$(cat <<'PY'
import socket, struct
def query(qid):
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
def answers(r):
    count, i, out = struct.unpack(">H", r[6:8])[0], 12, []
    while r[i]: i += r[i] + 1
    i += 5
    for _ in range(count):
        i += 2 if r[i] & 0xC0 == 0xC0 else 0
        kind, _, _, length = struct.unpack(">HHIH", r[i:i + 10]); i += 10
        if kind == 1: out.append(socket.inet_ntoa(r[i:i + length]))
        i += length
    return out
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(10)
u.sendto(query(1), ("127.0.0.53", 53)); print("dns-udp=" + ",".join(answers(u.recv(4096))))
t = socket.create_connection(("127.0.0.53", 53), timeout=10); m = query(2)
t.sendall(struct.pack(">H", len(m)) + m); n = struct.unpack(">H", t.recv(2))[0]; r = b""
while len(r) < n: r += t.recv(n - len(r))
print("dns-tcp=" + ",".join(answers(r)))
try:
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("8.8.8.8", 53)); print("udp-external=sent")
except OSError as e: print("udp-external-denied=%d" % e.errno)
PY
)"
  net_script='
  env | grep -qi "^[a-z_]*proxy=" && echo proxy-env-set || echo no-proxy-env
  python3 -c "$0"
  getent hosts example.com | sed "s/^/getent=/"
  curl -sS -o /dev/null -w "allowed=%{http_code}\n" --max-time 30 https://example.com 2>&1
  curl -sS -o /dev/null -w "plain-http=%{http_code}\n" --max-time 30 http://example.com 2>&1
  curl -sS -o /dev/null -w "ip-granted=%{http_code}\n" --max-time 30 http://1.1.1.1/ 2>&1
  curl -sS -o /dev/null --max-time 20 http://1.0.0.1/ 2>&1 | head -1 | sed "s/^/ip-denied=/"
  curl -sS -o /dev/null --max-time 20 https://github.com 2>&1 | head -1 | sed "s/^/denied-host=/"
  echo | timeout 20 openssl s_client -connect example.com:443 2>&1 | grep -o "Permission denied" | head -1 | sed "s/^/wrong-binary=/"
  (python3 -m http.server 8088 --bind 127.0.0.1 > /dev/null 2>&1 &) ; sleep 2
  curl -sS -o /dev/null -w "loopback-server=%{http_code}\n" --max-time 10 http://127.0.0.1:8088/ 2>&1'
  out="$(run_main net /bin/bash -c "$net_script" "$dns_probe")"
  expect "no proxy settings" "$out" "no-proxy-env"
  expect_re "UDP DNS answered by policy DNS" "$out" "dns-udp=198\.18\."
  expect_re "TCP DNS answered by policy DNS" "$out" "dns-tcp=198\.18\."
  expect_re "libc resolver uses the relay" "$out" "getent=198\.18\."
  expect "external UDP is refused" "$out" "udp-external-denied=89"
  if [[ "${SHIM_E2E_SKIP_INTERNET:-0}" == 1 ]]; then
    echo "SKIP allowed egress (SHIM_E2E_SKIP_INTERNET=1)"
  else
    expect "native HTTPS allowed" "$out" "allowed=200"
    expect "native plain HTTP allowed" "$out" "plain-http=200"
    expect_re "granted IP literal allowed" "$out" "ip-granted=(200|301)"
  fi
  expect "ungranted IP literal denied" "$out" "ip-denied=curl: (7)"
  expect "disallowed host denied" "$out" "denied-host=curl: (7)"
  expect "disallowed binary (openssl) denied for allowed host" "$out" "wrong-binary=Permission denied"
  expect "workload loopback listener reachable" "$out" "loopback-server=200"
else
  net_script='
  code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 30 https://example.com 2>&1); echo "allowed=$code"
  curl -sS -o /dev/null --max-time 30 https://github.com 2>&1 | head -1 | sed "s/^/denied-host=/"
  echo | openssl s_client -proxy 127.0.0.1:3128 -connect example.com:443 2>&1 | grep -o "403" | head -1 | sed "s/^/wrong-binary=/"
  curl -sS -o /dev/null --noproxy "*" --max-time 10 https://example.com 2>&1 | head -1 | sed "s/^/bypass=/"
  curl -sS -o /dev/null --noproxy "*" --max-time 10 https://93.184.215.14 2>&1 | head -1 | sed "s/^/bypass-ip=/"'
  out="$(run_main net /bin/bash -c "$net_script")"
  if [[ "${SHIM_E2E_SKIP_INTERNET:-0}" == 1 ]]; then
    echo "SKIP allowed egress (SHIM_E2E_SKIP_INTERNET=1)"
  else
    expect "allowed host via supervisor relay" "$out" "allowed=200"
  fi
  expect "disallowed host denied" "$out" "CONNECT tunnel failed, response 403"
  expect "disallowed binary (openssl) denied for allowed host" "$out" "wrong-binary=403"
  expect "direct DNS has no route" "$out" "bypass=curl: (6)"
  expect "direct IP has no route" "$out" "bypass-ip=curl: (7)"
fi

# 3. The workload cannot reach or alter the shim's control paths.
adversarial_script='
  [ -e /run/openshell ] && echo adv-FAIL-run-openshell || echo adv-no-run-openshell
  [ -e /init ] && echo adv-FAIL-init || echo adv-no-shim-binary
  for p in /proc/[0-9]*; do
    tr "\0" " " < "$p/cmdline" 2>/dev/null | grep -q "^/init serve " && shim="${p#/proc/}"
  done
  echo "shim-pid=${shim:-none}"
  ls "/proc/$shim/root/" > /dev/null 2>&1 && echo adv-FAIL-shim-root || echo adv-shim-root-denied
  cat "/proc/$shim/environ" > /dev/null 2>&1 && echo adv-FAIL-shim-environ || echo adv-shim-environ-denied
  kill -0 "$shim" 2> /dev/null && echo adv-FAIL-signal-shim || echo adv-signal-shim-denied
  touch /etc/openshell-tls/planted 2> /dev/null && echo adv-FAIL-ca-dir || echo adv-ca-dir-readonly
  mount -o remount,bind,rw /etc/openshell-tls 2> /dev/null && echo remounted-rw
  (echo tampered >> /etc/openshell-tls/ca-bundle.pem) 2> /dev/null \
    && echo adv-FAIL-ca-modified || echo adv-ca-unmodifiable'
if [[ "$substrate" == firecracker ]]; then
  # Paths around the inherited networking listener are refused.
  adversarial_script="$adversarial_script"'
  python3 - <<"PY"
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
arm = os.uname().machine == "aarch64"
calls = {"io_uring": (425, 1, ctypes.create_string_buffer(120)), "ptrace": (117 if arm else 101, 0, 0, 0, 0),
         "process_vm_readv": (270 if arm else 310, 1, 0, 0, 0, 0, 0), "pidfd_getfd": (438, 0, 0, 0),
         "bpf": (280 if arm else 321, 0, 0, 0)}
for name, args in calls.items():
    ok = libc.syscall(*args) == -1 and ctypes.get_errno() == 1
    print(("adv-%s-denied" if ok else "adv-FAIL-%s") % name)
PY'
fi
out="$(run_main adversarial /bin/bash -c "$adversarial_script")"
for marker in adv-no-run-openshell adv-no-shim-binary adv-shim-root-denied adv-shim-environ-denied \
  adv-signal-shim-denied adv-ca-dir-readonly adv-ca-unmodifiable; do
  expect "management path: $marker" "$out" "$marker"
done
expect_re "management path: shim process found" "$out" "shim-pid=[0-9]+"
if [[ "$substrate" == firecracker ]]; then
  for marker in io_uring ptrace process_vm_readv pidfd_getfd bpf; do
    expect "listener bypass: $marker" "$out" "adv-$marker-denied"
  done
fi
if grep -q "adv-FAIL" <<<"$out"; then fail "management path: no adv-FAIL markers"; printf '%s\n' "$out" | sed 's/^/    | /'; fi

# 3b. Exec and PTY processes are launched like the main process.
if [[ "$substrate" == firecracker ]]; then
  "$openshell" sandbox create --name execs --detach --no-tty --no-auto-providers \
    --policy "$policy" -- sleep 600 > /dev/null 2>&1 || true
  for ((i=0; i<90; i++)); do
    timeout 60 "$openshell" sandbox exec -n execs --no-tty -- true > /dev/null 2>&1 && break
    sleep 2
  done
  out="$(timeout 120 "$openshell" sandbox exec -n execs --no-tty --no-login-shell -- \
    curl -sS -o /dev/null -w "exec-http=%{http_code}\n" --max-time 30 http://example.com 2>&1 || true)"
  out="$out
$(timeout 120 "$openshell" sandbox exec -n execs --tty --no-login-shell -- bash -c '
  echo "pty=$(tty)"
  curl -sS -o /dev/null -w "pty-http=%{http_code}\n" --max-time 30 http://example.com
  python3 -c "import ctypes;l=ctypes.CDLL(None,use_errno=True);l.syscall(425,1,ctypes.create_string_buffer(120));print(\"pty-io_uring-errno=%d\" % ctypes.get_errno())"' 2>&1 || true)"
  "$openshell" sandbox delete execs > /dev/null 2>&1 || true
  for ((i=0; i<60; i++)); do
    "$openshell" sandbox get execs > /dev/null 2>&1 || break
    sleep 1
  done
  expect "exec process is mediated" "$out" "exec-http=200"
  expect "PTY exec has a terminal" "$out" "pty=/dev/pts/"
  expect "PTY exec process is mediated" "$out" "pty-http=200"
  expect "PTY exec process is hardened" "$out" "pty-io_uring-errno=1"
fi

# 4. Optional development workloads (SHIM_E2E_DEV=1 with a rootfs that has
#    gcc, Docker static binaries, /opt/offline-images/alpine-3.22.tar, and claude).
if [[ "${SHIM_E2E_DEV:-0}" == 1 ]]; then
  dev_script='
    cat > /sandbox/t.c <<"C"
#include <stdio.h>
int main(void) { printf("c-program=%d\n", 6 * 7); return 0; }
C
    gcc -O2 -o /sandbox/t /sandbox/t.c && /sandbox/t
    HOME=/sandbox timeout 60 claude --version 2>&1 | head -1 | sed "s/^/claude=/"'
  if [[ "$privilege" == privileged ]]; then
    dev_script="$dev_script"'
    mkdir -p /var/lib/docker && mount -t tmpfs tmpfs /var/lib/docker
    unshare --net dockerd --iptables=false --ip6tables=false --bridge=none \
      --storage-driver=vfs > /tmp/dockerd.log 2>&1 &
    for i in $(seq 1 60); do docker info > /dev/null 2>&1 && break; sleep 1; done
    docker load -i /opt/offline-images/alpine-3.22.tar
    docker run --rm --network=host alpine:3.22 sh -c "echo nested-container=\$(cat /etc/alpine-release)"
    echo "docker-exit=$?"'
    if [[ "$substrate" == firecracker ]]; then
      dev_script="$dev_script"'
    timeout 300 docker pull alpine:3.21 > /tmp/pull.log 2>&1; echo "pull-exit=$?"
    docker run --rm --network=host alpine:3.21 cat /etc/alpine-release | sed "s/^/pulled-alpine=/"
    docker run --rm --network=host alpine:3.22 sh -c "wget -q -O /dev/null -S http://example.com/ 2>&1 | head -1 | sed s/^/nested-http=/; wget -q -O /dev/null http://1.1.1.1/ 2>&1 | head -1 | sed s/^/nested-ip=/"'
    fi
  fi
  out="$(run_main dev /bin/bash -c "$dev_script")"
  expect "C program compiles and runs" "$out" "c-program=42"
  expect_re "claude --version starts" "$out" "claude=[0-9]+\.[0-9]+"
  if [[ "$privilege" == privileged ]]; then
    expect "nested Docker loads the offline image" "$out" "Loaded image: alpine:3.22"
    expect_re "nested Docker runs a container" "$out" "nested-container=3\.22"
    expect "nested docker run exit status" "$out" "docker-exit=0"
    if [[ "$substrate" == firecracker ]]; then
      expect "dockerd pulls online through mediation" "$out" "pull-exit=0"
      expect_re "pulled image runs" "$out" "pulled-alpine=3\.21"
      expect "nested container egress allowed by its nested-root identity" "$out" "nested-http=  HTTP/1.1 200"
      expect "nested container denied a destination granted only to curl" "$out" "nested-ip=wget: can't connect to remote host (1.1.1.1): Permission denied"
    fi
  fi
fi

# 5. Abruptly losing the supervisor ends the workload and the guest.
previous="$(latest_guest)"
"$openshell" sandbox create --name lost --detach --no-tty --no-auto-providers \
  --policy "$policy" -- /bin/bash -c 'sleep 600 & sleep 600' > /dev/null 2>&1 || true
for ((i=0; i<120; i++)); do
  current="$(latest_guest)"
  [[ "$current" != "$previous" ]] && guest_log | grep -q "main process started" && break
  sleep 1
done
if [[ "$current" != "$previous" ]] && guest_log | grep -q "main process started"; then
  sleep 2
  # Abrupt loss: a graceful SIGTERM makes the supervisor terminate the boundary itself.
  kill -KILL "$(cat "$state/supervisor.pid")"
  for ((i=0; i<60; i++)); do
    guest_log | grep -q "serve exited" && break
    sleep 1
  done
  log="$(guest_log)"
  expect "supervisor loss detected in guest" "$log" "boundary ending (supervisor connection lost)"
  expect_re "workload killed on supervisor loss" "$log" \
    "killed the delegated workload cgroup|signalled [1-9][0-9]* workload processes"
  expect "guest stops after supervisor loss" "$log" "serve exited"
  for ((i=0; i<30; i++)); do
    grep -q "exited; stopping the guest" "$state/driver.log" && break
    sleep 1
  done
  expect "host driver tears down the guest" "$(cat "$state/driver.log")" "exited; stopping the guest"
else
  fail "detached sandbox did not start"
fi
"$openshell" sandbox delete lost > /dev/null 2>&1 || true

echo "state and logs: $state"
if ((failures)); then
  echo "$failures check(s) failed for $substrate/$privilege"
  exit 1
fi
echo "all checks passed for $substrate/$privilege"
