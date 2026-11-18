#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Run the stock-gVisor ptrace mediation probes.

    uv run --no-project run.py linux  [PROBE ...]  # host Linux reference, invoking user
    uv run --no-project run.py direct [PROBE ...]  # stock runsc, tracer is sandbox root
    uv run --no-project run.py raw                 # stock runsc + SecCheck raw collector (rawevent)

Exit status is nonzero if any probe fails or times out. Logs go to
$GV_LOG_DIR (default /tmp/shim-gvisor-validation-logs).
"""

import json
import os
import pathlib
import shlex
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
HOST = HERE / "host"
REPO = HERE.parents[3]
PROBES = HERE / "probes"
LOG_DIR = pathlib.Path(os.environ.get("GV_LOG_DIR", "/tmp/shim-gvisor-validation-logs"))
BIN_DIR = LOG_DIR / "bin"
RUNSC_DIR = pathlib.Path(os.environ.get("SHIM_RUNSC_DIR", "/tmp/openshell-gvisor-prototype-runtime"))
ROOTFS = pathlib.Path(os.environ.get("SHIM_ROOTFS_DIR", "/tmp/openshell-shim-tools/dev-rootfs"))
HELPER = os.environ.get("SHIM_HELPER_IMAGE", "buildpack-deps:26.04")
LABEL = "openshell-gvisor-validation"
CFLAGS = ["-std=gnu11", "-O2", "-g", "-pthread", "-Wall", "-Wextra", "-Werror",
          "-Wshadow", "-Wformat=2"]


def log(message):
    print(f"[gv-validate] {message}", flush=True)


def all_probes():
    return sorted(p.stem for p in PROBES.glob("*.c"))


def build(names):
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    for name in names:
        command = ["gcc", *CFLAGS, "-static", str(PROBES / f"{name}.c"), "-o", str(BIN_DIR / name)]
        subprocess.run(command, check=True)
    log(f"built {' '.join(names)} with {' '.join(CFLAGS)} -static")


def run_logged(name, command, timeout, **kwargs):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    path = LOG_DIR / f"{name}.log"
    started = time.monotonic()
    with path.open("w") as out:
        out.write("# " + shlex.join(command)[:4000] + "\n")
        out.flush()
        try:
            code = subprocess.run(command, stdout=out, stderr=subprocess.STDOUT,
                                  timeout=timeout, **kwargs).returncode
        except subprocess.TimeoutExpired:
            code = "timeout"
    text = path.read_text()
    for line in text.splitlines():
        if line.startswith(("RESULT ", "SUMMARY ")):
            print("   " + line, flush=True)
    ok = code == 0 and "SUMMARY failures=0" in text
    log(f"{name}: exit={code} {'ok' if ok else 'FAILED'} "
        f"({time.monotonic() - started:.1f}s) log={path}")
    return ok


def linux(names):
    build(names)
    return [run_logged(f"linux-{n}", [str(BIN_DIR / n)], timeout=300) for n in names]


def oci_config(argv, raw=False):
    caps = ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER",
            "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE", "CAP_NET_RAW", "CAP_NET_ADMIN", "CAP_SYS_CHROOT",
            "CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_MKNOD", "CAP_AUDIT_WRITE",
            "CAP_SETFCAP", "CAP_SYS_RESOURCE"]

    def tmpfs(dst, mode):
        return {"destination": dst, "type": "tmpfs", "source": "tmpfs",
                "options": ["nosuid", "nodev", f"mode={mode}"]}

    # Same capability set, namespaces, and mounts as the shim's gVisor guest
    # (examples/sandbox-shim/src/guest.rs), with the probe directory at /mnt
    # instead of the shim's control paths. No credentials or sockets are
    # mounted. Mount points must already exist: the rootfs bind is read-only
    # and runsc's memory overlay holds all writes.
    return {
        "ociVersion": "1.0.2",
        "hostname": "gv-validate",
        "process": {
            "user": {"uid": 0, "gid": 0},
            "args": argv,
            "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "HOME=/root"] + (["GV_RAW_CHANNEL=/srv/tracer.sock"] if raw else []),
            "cwd": "/",
            "capabilities": dict.fromkeys(
                ("bounding", "effective", "permitted", "inheritable"), caps),
        },
        "root": {"path": "/src/rootfs", "readonly": False},
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
             "options": ["nosuid", "mode=755"]},
            {"destination": "/dev/pts", "type": "devpts", "source": "devpts",
             "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"]},
            {"destination": "/dev/shm", "type": "tmpfs", "source": "shm",
             "options": ["nosuid", "nodev", "mode=1777"]},
            {"destination": "/sys", "type": "sysfs", "source": "sysfs",
             "options": ["nosuid", "noexec", "nodev", "ro"]},
            {"destination": "/sys/fs/cgroup", "type": "cgroup", "source": "cgroup",
             "options": ["nosuid", "noexec", "nodev"]},
            tmpfs("/tmp", "1777"),
            tmpfs("/run", "755"),
            {"destination": "/mnt", "type": "bind", "source": "/src/probe",
             "options": ["rbind", "ro"]},
        ] + ([
            # Private channel dir inside the helper, like the shim's
            # /bundle-chan. The guest tracer binds its listener here and
            # runsc --host-uds=create gives the collector the host side.
            {"destination": "/srv", "type": "bind", "source": "/bundle-chan",
             "options": ["rbind", "rw"]},
        ] if raw else []),
        "linux": {"namespaces": [{"type": t} for t in
                                 ("pid", "network", "ipc", "uts", "mount")]},
    }


def require_mountpoints(dirs):
    # The rootfs is bound read-only, so bind-mount targets must already exist.
    # Do not create them here: the rootfs belongs to the caller.
    missing = [d for d in dirs if not (ROOTFS / d).is_dir()]
    if missing:
        sys.exit(f"rootfs {ROOTFS} lacks mount point(s) {missing}; create them in your copy")


def direct(names):
    require_mountpoints(["mnt"])
    build(names)
    runsc = RUNSC_DIR / "runsc"
    if not runsc.exists():
        sys.exit(f"runsc not found: {runsc}")
    results = []
    for name in names:
        container = f"gv-validate-{os.getpid()}-{name}"
        config = json.dumps(oci_config(["/mnt/" + name]))
        script = ("set -eu; mkdir -p /bundle; cat > /bundle/config.json <<'EOF'\n" + config +
                  "\nEOF\nexec /gvisor/runsc --root=/tmp/runsc --ignore-cgroups "
                  "--in-sandbox-cgroup=v2 --network=none --platform=systrap "
                  "--overlay2=root:memory run --bundle=/bundle sandbox\n")
        command = [
            "docker", "run", "--rm", "--name", container, "--label", f"{LABEL}={os.getpid()}",
            "--network", "none", "--cap-add", "SYS_ADMIN", "--cap-add", "SYS_PTRACE",
            "--security-opt", "seccomp=unconfined", "--security-opt", "apparmor=unconfined",
            "--mount", f"type=bind,src={RUNSC_DIR},dst=/gvisor,readonly",
            "--mount", f"type=bind,src={ROOTFS},dst=/src/rootfs,readonly",
            "--mount", f"type=bind,src={BIN_DIR},dst=/src/probe,readonly",
            "--entrypoint", "/bin/sh", HELPER, "-c", script,
        ]
        try:
            results.append(run_logged(f"direct-{name}", command, timeout=600))
        finally:
            subprocess.run(["docker", "rm", "-f", container], capture_output=True)
    return results


# Raw syscall point for arm64 gettid with root-namespace thread id and task
# start time. ignore_setup_error stays false, so runsc fails if it cannot
# connect the sink. The Sentry only warns if the session itself is bad
# (runsc/boot/loader.go), so the tracer also requires a token round trip.
POD_INIT = {
    "trace_session": {
        "name": "Default",
        "points": [{"name": "syscall/sysno/178/enter",
                    "context_fields": ["thread_id", "task_start_time"]}],
        "sinks": [{"name": "remote",
                   "config": {"endpoint": "/run/gv-sink.sock", "retries": 3}}],
    }
}


def raw(names):
    """Run rawevent with a host-side SecCheck collector in the same helper.

    The collector listens on a helper-private SEQPACKET path that runsc
    connects to during setup, then connects into the guest tracer's channel
    created through --host-uds=create. Neither the sink path nor the
    collector is visible inside the sandbox.
    """
    names = names or ["rawevent"]
    require_mountpoints(["srv", "mnt"])
    build(names)
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(["gcc", *CFLAGS, "-static", str(HOST / "collector.c"), "-o",
                    str(BIN_DIR / "collector")], check=True)
    selftest_ok = run_logged("raw-collector-selftest", [str(BIN_DIR / "collector"), "--selftest"],
                             timeout=60)
    runsc = RUNSC_DIR / "runsc"
    if not runsc.exists():
        sys.exit(f"runsc not found: {runsc}")
    results = []
    for name in names:
        container = f"gv-validate-raw-{os.getpid()}-{name}"
        config = json.dumps(oci_config(["/mnt/" + name], raw=True))
        script = (
            "set -eu; mkdir -p /bundle /bundle-chan /run\n"
            "cat > /bundle/config.json <<'EOF'\n" + config + "\nEOF\n"
            "cat > /bundle/pod_init.json <<'EOF'\n" + json.dumps(POD_INIT) + "\nEOF\n"
            "/src/probe/collector /run/gv-sink.sock /bundle-chan/tracer.sock &\n"
            "collector=$!\n"
            "for i in $(seq 100); do [ -S /run/gv-sink.sock ] && break; sleep 0.05; done\n"
            "rc=0; /gvisor/runsc --root=/tmp/runsc --ignore-cgroups --in-sandbox-cgroup=v2 "
            "--network=none --platform=systrap --host-uds=create --overlay2=root:memory "
            "--debug --debug-log=/tmp/rl/ "
            "--pod-init-config=/bundle/pod_init.json run --bundle=/bundle sandbox || rc=$?\n"
            "[ $rc = 0 ] || grep -hiE 'panic|fatal|error|seccheck|sink' /tmp/rl/*boot* | tail -40\n"
            "wait $collector || rc=1\n"
            "exit $rc\n")
        command = [
            "docker", "run", "--rm", "--name", container, "--label", f"{LABEL}={os.getpid()}",
            "--network", "none", "--cap-add", "SYS_ADMIN", "--cap-add", "SYS_PTRACE",
            "--security-opt", "seccomp=unconfined", "--security-opt", "apparmor=unconfined",
            "--mount", f"type=bind,src={RUNSC_DIR},dst=/gvisor,readonly",
            "--mount", f"type=bind,src={ROOTFS},dst=/src/rootfs,readonly",
            "--mount", f"type=bind,src={BIN_DIR},dst=/src/probe,readonly",
            "--entrypoint", "/bin/sh", HELPER, "-c", script,
        ]
        try:
            results.append(run_logged(f"raw-{name}", command, timeout=900))
        finally:
            subprocess.run(["docker", "rm", "-f", container], capture_output=True)
    return [selftest_ok, *results]


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("linux", "direct", "raw"):
        sys.exit(__doc__)
    names = sys.argv[2:] or ([] if sys.argv[1] == "raw" else all_probes())
    results = {"linux": linux, "direct": direct, "raw": raw}[sys.argv[1]](names)
    failed = results.count(False)
    log(f"{sys.argv[1]}: {len(results) - failed} ok, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
