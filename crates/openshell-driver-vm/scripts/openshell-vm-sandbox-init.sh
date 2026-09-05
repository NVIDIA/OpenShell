#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Minimal init for sandbox VMs. Runs as PID 1 inside the guest, mounts the
# essential filesystems, optionally loads NVIDIA GPU drivers, then execs the
# portable VM sandbox. Workload networking crosses the authenticated
# boundary channel; the VM does not receive a network interface.

set -euo pipefail

# libkrun consumes this driver-owned switch before exec'ing this script as
# PID 1. Do not leak the runtime control into the supervisor or workloads.
unset KRUN_INIT_PID1

BOOT_START=$(date +%s%3N 2>/dev/null || date +%s)
SANDBOX_OWNER_NORMALIZED_MARKER="/opt/openshell/.sandbox-owner-normalized"

GPU_ENABLED="${GPU_ENABLED:-false}"

ts() {
    local now
    now=$(date +%s%3N 2>/dev/null || date +%s)
    local elapsed=$((now - BOOT_START))
    printf "[%d.%03ds] %s\n" $((elapsed / 1000)) $((elapsed % 1000)) "$*"
}

mount_initial_fs() {
    mount -t proc proc /proc 2>/dev/null || true
    mount -t sysfs sysfs /sys 2>/dev/null || true
    mount -t tmpfs tmpfs /tmp 2>/dev/null || true
    mount -t tmpfs tmpfs /run 2>/dev/null || true
    mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
}

bind_mount_into_newroot() {
    local source="$1"
    local target="/newroot${source}"

    mkdir -p "$target" 2>/dev/null || true
    mount --rbind "$source" "$target" 2>/dev/null \
        || mount --bind "$source" "$target" 2>/dev/null \
        || true
}

root_path() {
    local path="$1"
    printf '%s%s\n' "${ROOT_PREFIX:-}" "$path"
}

sandbox_owner() {
    sandbox_owner_from_passwd "$(root_path /etc/passwd)"
}

sandbox_owner_for_root() {
    local root="$1"
    sandbox_owner_from_passwd "$root/etc/passwd"
}

sandbox_owner_from_passwd() {
    local passwd_path name uid gid rest
    passwd_path="$1"
    if [ -f "$passwd_path" ]; then
        while IFS=: read -r name _ uid gid rest; do
            _="${rest:-}"
            if [ "$name" = "sandbox" ] \
                && [[ "$uid" =~ ^[0-9]+$ ]] \
                && [[ "$gid" =~ ^[0-9]+$ ]]; then
                printf '%s:%s\n' "$uid" "$gid"
                return
            fi
        done < "$passwd_path"
    fi

    printf '10001:10001\n'
}

source_overlay_env_if_present() {
    local env_file="/overlay/upper/srv/openshell-env.sh"
    if [ -f "$env_file" ]; then
        # shellcheck source=/dev/null
        source "$env_file"
    fi
}

ensure_target_runtime() {
    local image_root="$1"

    mkdir -p \
        "$image_root/srv" \
        "$image_root/opt/openshell/bin" \
        "$image_root/sandbox" \
        "$image_root/etc"

    cp /srv/openshell-vm-sandbox-init.sh "$image_root/srv/openshell-vm-sandbox-init.sh"
    chmod 0755 "$image_root/srv/openshell-vm-sandbox-init.sh"

    if [ -x /opt/openshell/bin/openshell-sandbox ]; then
        cp /opt/openshell/bin/openshell-sandbox "$image_root/opt/openshell/bin/openshell-sandbox"
        chmod 0755 "$image_root/opt/openshell/bin/openshell-sandbox"
    fi
    if [ -d /opt/openshell/bin/openshell-runtime ]; then
        rm -rf "$image_root/opt/openshell/bin/openshell-runtime"
        cp -a /opt/openshell/bin/openshell-runtime "$image_root/opt/openshell/bin/openshell-runtime"
    fi

    touch "$image_root/etc/passwd" "$image_root/etc/group" "$image_root/etc/shadow" "$image_root/etc/gshadow"
    if ! grep -q '^sandbox:' "$image_root/etc/group" 2>/dev/null; then
        printf 'sandbox:x:10001:\n' >> "$image_root/etc/group"
    fi
    if ! grep -q '^sandbox:' "$image_root/etc/gshadow" 2>/dev/null; then
        printf 'sandbox:!::\n' >> "$image_root/etc/gshadow"
    fi
    if ! grep -q '^sandbox:' "$image_root/etc/passwd" 2>/dev/null; then
        printf 'sandbox:x:10001:10001:OpenShell Sandbox:/sandbox:/bin/sh\n' >> "$image_root/etc/passwd"
    fi
    if ! grep -q '^sandbox:' "$image_root/etc/shadow" 2>/dev/null; then
        printf 'sandbox:!:20123:0:99999:7:::\n' >> "$image_root/etc/shadow"
    fi
    local owner
    local owner_normalized=0
    owner="$(sandbox_owner_for_root "$image_root")"
    if chown -R "$owner" "$image_root/sandbox" 2>/dev/null; then
        owner_normalized=1
    elif chown -R 10001:10001 "$image_root/sandbox" 2>/dev/null; then
        owner_normalized=1
    fi
    chmod 0755 "$image_root/sandbox"
    if [ "$owner_normalized" -eq 1 ]; then
        mkdir -p "$image_root/opt/openshell"
        printf '1\n' > "$image_root${SANDBOX_OWNER_NORMALIZED_MARKER}"
    fi
}

prepare_guest_image_rootfs() {
    local payload_dir="/overlay/config/openshell-image"
    local image_root="/overlay/image-rootfs"
    local partial_root="/overlay/image-rootfs.partial"
    local source

    [ -d "$payload_dir" ] || return 0

    source="$(cat "$payload_dir/source" 2>/dev/null || true)"
    ts "preparing sandbox image rootfs in guest (${source:-unknown})"

    rm -rf "$image_root" "$partial_root"

    case "$source" in
        local-docker)
            mkdir -p "$image_root"
            tar -xpf "$payload_dir/source-rootfs.tar" -C "$image_root"
            ;;
        oci-layout)
            if [ ! -x /opt/openshell/bin/umoci ]; then
                ts "FATAL: umoci not found in VM bootstrap image"
                exit 1
            fi
            /opt/openshell/bin/umoci raw unpack \
                --image "$payload_dir/oci:openshell" \
                "$partial_root"
            if [ ! -d "$partial_root/rootfs" ]; then
                ts "FATAL: umoci unpack did not produce rootfs directory"
                exit 1
            fi
            mv "$partial_root/rootfs" "$image_root"
            rm -rf "$partial_root"
            ;;
        *)
            ts "FATAL: unknown guest image payload source: ${source:-missing}"
            exit 1
            ;;
    esac

    ensure_target_runtime "$image_root"
    if [ -f "$payload_dir/identity" ]; then
        cp "$payload_dir/identity" "$image_root/.openshell-rootfs-variant"
    fi
    rm -rf "$payload_dir"
}

exec_supervisor_in_newroot() {
    local chroot_bin
    local bootstrap="/.openshell-bootstrap"
    local supervisor="${bootstrap}/opt/openshell/bin/openshell-sandbox"
    local loader
    local lib_path

    for chroot_bin in /usr/sbin/chroot /usr/bin/chroot /sbin/chroot /bin/chroot; do
        [ -x "$chroot_bin" ] || continue

        if [ -x "/newroot${supervisor}" ]; then
            for loader in \
                "${bootstrap}/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" \
                "${bootstrap}/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" \
                "${bootstrap}/lib64/ld-linux-x86-64.so.2" \
                "${bootstrap}/lib/ld-linux-x86-64.so.2" \
                "${bootstrap}/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1" \
                "${bootstrap}/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1" \
                "${bootstrap}/lib/ld-linux-aarch64.so.1" \
                "${bootstrap}/lib64/ld-linux-aarch64.so.1"; do
                if [ -x "/newroot${loader}" ]; then
                    lib_path="${bootstrap}/lib:${bootstrap}/lib64:${bootstrap}/usr/lib:${bootstrap}/usr/lib64:${bootstrap}/lib/aarch64-linux-gnu:${bootstrap}/lib/x86_64-linux-gnu:${bootstrap}/usr/lib/aarch64-linux-gnu:${bootstrap}/usr/lib/x86_64-linux-gnu"
                    exec "$chroot_bin" /newroot "$loader" --library-path "$lib_path" "$supervisor" "$@"
                fi
            done
            exec "$chroot_bin" /newroot "$supervisor" "$@"
        fi

        if [ -x /newroot/opt/openshell/bin/openshell-sandbox ]; then
            exec "$chroot_bin" /newroot /opt/openshell/bin/openshell-sandbox "$@"
        fi
    done

    ts "FATAL: unable to exec openshell-sandbox in guest rootfs"
    exit 1
}

setup_overlay_root() {
    ts "setting up writable overlay root"
    mount_initial_fs

    if [ ! -b /dev/vdb ]; then
        ts "FATAL: writable overlay disk /dev/vdb not found"
        exit 1
    fi

    mkdir -p /overlay /lower /newroot /image-cache
    mount -o remount,ro / 2>/dev/null || true
    mount -t ext4 -o rw /dev/vdb /overlay
    mkdir -p /overlay/upper /overlay/work
    source_overlay_env_if_present

    if [ "${OPENSHELL_VM_INIT_MODE:-sandbox}" = "image-prep" ]; then
        prepare_guest_image_rootfs
        sync
        if ! umount /overlay; then
            ts "FATAL: failed to unmount /overlay cleanly after image-prep; refusing to produce a dirty image-cache disk"
            exit 1
        fi
        ts "image-prep complete"
        exit 0
    fi

    mount --bind / /lower
    mount -o remount,bind,ro /lower 2>/dev/null || true

    local lower_root="/lower"
    if [ -b /dev/vdc ]; then
        mount -t ext4 -o ro,noload /dev/vdc /image-cache
        if [ -d /image-cache/image-rootfs ]; then
            lower_root="/image-cache/image-rootfs"
            ts "using prepared image rootfs lowerdir"
        else
            ts "FATAL: prepared image disk missing /image-rootfs"
            exit 1
        fi
    fi

    mount -t overlay overlay \
        -o lowerdir="$lower_root",upperdir=/overlay/upper,workdir=/overlay/work \
        /newroot
    mkdir -p /newroot/.openshell-bootstrap
    mount --bind /lower /newroot/.openshell-bootstrap

    # GPU setup runs against the bootstrap runtime and its mounted /dev, /proc,
    # and /run before those filesystems are mirrored into the target root.
    if [ "${GPU_ENABLED}" = "true" ]; then
        setup_gpu || ts "WARNING: GPU init failed; continuing without GPU"
    fi

    bind_mount_into_newroot /proc
    bind_mount_into_newroot /sys
    bind_mount_into_newroot /tmp
    bind_mount_into_newroot /dev
    bind_mount_into_newroot /run

    ROOT_PREFIX="/newroot"
    run_post_overlay_setup
}

create_gpu_device_nodes_mknod() {
    # Mode 666 is intentional: single-tenant microVM with the VM itself as the
    # isolation boundary. The sandbox user is the only non-root user.
    local nv_major
    nv_major=$(awk '$2 == "nvidia" {print $1}' /proc/devices 2>/dev/null || true)
    if [ -n "$nv_major" ]; then
        mknod -m 666 /dev/nvidiactl c "$nv_major" 255 2>/dev/null || true

        local gpu_count=0
        if [ -d /proc/driver/nvidia/gpus ]; then
            for gpu_dir in /proc/driver/nvidia/gpus/*/; do
                [ -d "$gpu_dir" ] || continue
                mknod -m 666 "/dev/nvidia${gpu_count}" c "$nv_major" "$gpu_count" 2>/dev/null || true
                gpu_count=$((gpu_count + 1))
            done
        fi
        if [ "$gpu_count" -eq 0 ]; then
            mknod -m 666 /dev/nvidia0 c "$nv_major" 0 2>/dev/null || true
        fi

        local modeset_major
        modeset_major=$(awk '$2 == "nvidia-modeset" {print $1}' /proc/devices 2>/dev/null || true)
        if [ -n "$modeset_major" ]; then
            mknod -m 666 /dev/nvidia-modeset c "$modeset_major" 254 2>/dev/null || true
        fi

        local uvm_major
        uvm_major=$(awk '$2 == "nvidia-uvm" {print $1}' /proc/devices 2>/dev/null || true)
        if [ -n "$uvm_major" ]; then
            mknod -m 666 /dev/nvidia-uvm c "$uvm_major" 0 2>/dev/null || true
            mknod -m 666 /dev/nvidia-uvm-tools c "$uvm_major" 1 2>/dev/null || true
        fi

        local caps_major
        caps_major=$(awk '$2 == "nvidia-caps" {print $1}' /proc/devices 2>/dev/null || true)
        if [ -n "$caps_major" ]; then
            mkdir -p /dev/nvidia-caps 2>/dev/null || true
            mknod -m 666 /dev/nvidia-caps/nvidia-cap1 c "$caps_major" 1 2>/dev/null || true
            mknod -m 666 /dev/nvidia-caps/nvidia-cap2 c "$caps_major" 2 2>/dev/null || true
        fi

        ts "GPU device nodes created via mknod (${gpu_count} GPU(s), major=${nv_major})"
    else
        ts "WARNING: 'nvidia' not in /proc/devices; device nodes unavailable"
    fi
}

setup_gpu() {
    ts "GPU_ENABLED=true — initializing GPU passthrough"

    if ! command -v modprobe >/dev/null 2>&1; then
        ts "FATAL: modprobe not found; cannot load nvidia kernel modules"
        return 1
    fi

    # Stage GSP firmware to tmpfs so module loading reads it from a stable
    # early-boot path.
    if [ -d /lib/firmware/nvidia ]; then
        ts "staging GPU firmware to tmpfs"
        mkdir -p /run/firmware/nvidia
        cp -a /lib/firmware/nvidia/* /run/firmware/nvidia/ 2>/dev/null || true
        if [ -e /sys/module/firmware_class/parameters/path ]; then
            echo /run/firmware > /sys/module/firmware_class/parameters/path
        fi
    fi

    ts "loading nvidia kernel modules"
    modprobe nvidia || { ts "FATAL: modprobe nvidia failed"; return 1; }
    modprobe nvidia_uvm 2>/dev/null || true
    modprobe nvidia_modeset 2>/dev/null || true

    rm -rf /run/firmware 2>/dev/null || true

    if command -v nvidia-smi >/dev/null 2>&1; then
        ts "running nvidia-smi to create device nodes and validate GPU"
        local smi_rc=0
        nvidia-smi >/dev/null 2>&1 || smi_rc=$?
        if [ "$smi_rc" -eq 0 ]; then
            nvidia-smi -L 2>/dev/null | while read -r line; do ts "  $line"; done
            ts "GPU initialization successful"
        else
            ts "WARNING: nvidia-smi failed (exit ${smi_rc}); falling back to mknod"
            create_gpu_device_nodes_mknod
        fi
    else
        ts "nvidia-smi not found; creating device nodes via mknod"
        create_gpu_device_nodes_mknod
    fi
}

setup_sandbox_workdir() {
    local sandbox_dir
    local owner
    local current_owner
    sandbox_dir="$(root_path /sandbox)"
    owner="$(sandbox_owner)"
    mkdir -p "$sandbox_dir"
    current_owner="$(stat -c '%u:%g' "$sandbox_dir" 2>/dev/null || true)"
    if [ "$current_owner" != "$owner" ] \
        || [ ! -f "$(root_path "$SANDBOX_OWNER_NORMALIZED_MARKER")" ]; then
        if ! chown -R "$owner" "$sandbox_dir" 2>/dev/null; then
            chown -R 10001:10001 "$sandbox_dir"
        fi
    fi
    chmod 0755 "$sandbox_dir"
    ts "prepared /sandbox ownership (${owner})"
}

configure_hostname() {
    local sandbox_hostname="${OPENSHELL_SANDBOX:-openshell-sandbox-vm}"
    sandbox_hostname="$(printf '%s' "$sandbox_hostname" | tr -c 'A-Za-z0-9.-' '-')"
    sandbox_hostname="$(printf '%s' "$sandbox_hostname" | sed 's/^[.-][.-]*//; s/[.-][.-]*$//')"
    sandbox_hostname="$(printf '%.63s' "$sandbox_hostname")"
    if [ -z "$sandbox_hostname" ]; then
        sandbox_hostname="openshell-sandbox-vm"
    fi

    hostname "$sandbox_hostname" 2>/dev/null || true
    printf '%s\n' "$sandbox_hostname" >"$(root_path /etc/hostname)" 2>/dev/null || true
    ts "hostname=${sandbox_hostname}"
}

run_openshell_init_dropins() {
    # Run executable drop-ins from /opt/openshell/init.d in deterministic
    # ASCII-sorted order. Drop-ins are *executed* in a child shell rather
    # than sourced, so they cannot mutate parent shell state or exit the
    # caller. They inherit `OPENSHELL_VM_INIT_PHASE`, `ROOT_PREFIX`, and
    # any `OPENSHELL_VM_DATA_*` env vars set by lifecycle extensions.
    #
    # Security: this runs as root before the supervisor enforces policy, so
    # it executes *only* the drop-ins the VM driver explicitly injected this
    # launch, as enumerated in the driver-authored manifest. Anything else
    # found under init.d (e.g. files baked into a user-controlled guest
    # image) is ignored. The manifest lives in the overlay upperdir, which
    # the driver owns, so a guest image cannot forge or shadow it. A missing
    # manifest is treated as "run nothing" (fail-closed).
    local init_dir manifest
    init_dir="$(root_path /opt/openshell/init.d)"
    manifest="$(root_path /opt/openshell/init.d.manifest)"

    if [ ! -f "$manifest" ]; then
        if [ -d "$init_dir" ]; then
            ts "no OpenShell VM init drop-in manifest present; skipping init.d"
        fi
        return 0
    fi

    export OPENSHELL_VM_INIT_PHASE="before-supervisor"
    export ROOT_PREFIX="${ROOT_PREFIX:-}"

    # Fail closed on any inconsistency: every drop-in below is trusted,
    # required setup the driver injected on purpose, so we abort the boot
    # rather than run a half-configured sandbox. Aborting exits this init
    # non-zero; the VM helper then exits and the driver runs
    # lifecycle-extension cleanup, so a failed init does not leak resources.
    # The loop runs in the main shell (process substitution, not a pipe), so
    # `exit` here terminates init as intended.
    local name dropin rc
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        # Manifest entries are bare file names that the driver already
        # validated. A separator or traversal here means the manifest was
        # tampered with after the driver wrote it.
        case "$name" in
            */* | . | ..)
                ts "FATAL: unsafe init drop-in manifest entry '${name}'"
                exit 1
                ;;
        esac

        # The driver writes each entry's file and marks it 0755 in the same
        # operation, so a missing or non-executable entry means the overlay
        # was tampered with or provisioning is broken.
        dropin="${init_dir}/${name}"
        if [ ! -f "$dropin" ]; then
            ts "FATAL: init drop-in '${name}' listed in manifest but not found"
            exit 1
        fi
        if [ ! -x "$dropin" ]; then
            ts "FATAL: init drop-in '${name}' is not executable"
            exit 1
        fi

        ts "running OpenShell VM init drop-in ${name}"
        rc=0
        set +e
        "$dropin"
        rc=$?
        set -e
        if [ "$rc" -ne 0 ]; then
            ts "FATAL: OpenShell VM init drop-in ${name} failed with exit code ${rc}"
            exit 1
        fi
    done < <(LC_ALL=C sort -u "$manifest")
}

run_post_overlay_setup() {
    # Source QEMU-injected environment variables if present. The file lives in
    # the overlay upperdir so the cached bootstrap rootfs remains immutable.
    local env_file
    env_file="$(root_path /srv/openshell-env.sh)"
    if [ -f "$env_file" ]; then
        # shellcheck source=/dev/null
        source "$env_file"
    fi

    if [ -z "${ROOT_PREFIX:-}" ]; then
        mount -t proc proc /proc 2>/dev/null &
        mount -t sysfs sysfs /sys 2>/dev/null &
        mount -t tmpfs tmpfs /tmp 2>/dev/null &
        mount -t tmpfs tmpfs /run 2>/dev/null &
        mount -t devtmpfs devtmpfs /dev 2>/dev/null &
        wait
    fi

    mkdir -p "$(root_path /dev/pts)" "$(root_path /dev/shm)" "$(root_path /sys/fs/cgroup)"
    mount -t devpts devpts "$(root_path /dev/pts)" 2>/dev/null &
    mount -t tmpfs tmpfs "$(root_path /dev/shm)" 2>/dev/null &
    mount -t cgroup2 cgroup2 "$(root_path /sys/fs/cgroup)" 2>/dev/null &
    wait

    setup_sandbox_workdir

    configure_hostname
    if ! ip link set lo up; then
        ts "FATAL: failed to bring up the loopback interface"
        exit 1
    fi

    # The capability-free sandbox owns a loopback-only DNS relay. Guest init
    # grants the low port before handing control to the zero-capability UID.
    if ! echo 0 > /proc/sys/net/ipv4/ip_unprivileged_port_start; then
        ts "FATAL: failed to permit the unprivileged DNS relay to bind port 53"
        exit 1
    fi
    cat >"$(root_path /etc/resolv.conf)" <<'EOF'
nameserver 127.0.0.53
options timeout:2 attempts:2
EOF

# The boundary transport mediates network and DNS requests. Only loopback is
# configured in the guest; no public resolver or guest NIC is needed.

export HOME=/sandbox
export USER=sandbox

# Fix /sandbox ownership. The host-side CLI extracts OCI layers as a non-root
# user (e.g. UID 501 on macOS), so /sandbox may be owned by the host UID.
#
# On macOS (Hypervisor.framework), guest root has real root privileges and
# chown succeeds. On Linux non-root hosts with virtiofs, guest root maps to
# the host user, so chown is denied — this is non-fatal because the
# supervisor's own filesystem preparation handles the paths that matter.
if [ -d /sandbox ]; then
    _sb_uid=$(id -u sandbox 2>/dev/null || true)
    _sb_gid=$(id -g sandbox 2>/dev/null || true)
    if [ -n "$_sb_uid" ] && [ -n "$_sb_gid" ]; then
        _cur_uid=$(stat -c '%u' /sandbox 2>/dev/null || true)
        if [ -n "$_cur_uid" ] && [ "$_cur_uid" != "$_sb_uid" ]; then
            ts "fixing /sandbox ownership (was uid=${_cur_uid}, setting to sandbox=${_sb_uid}:${_sb_gid})"
            chown -R "${_sb_uid}:${_sb_gid}" /sandbox 2>/dev/null || \
                ts "chown /sandbox denied (virtiofs rootless host), continuing"
        fi
    fi
fi

run_openshell_init_dropins

if [ -n "${OPENSHELL_SANDBOX_ID:-}" ]; then
    ts "OPENSHELL_SANDBOX_ID=${OPENSHELL_SANDBOX_ID}"
fi

ts "starting OpenShell VM sandbox"
_sandbox_owner="$(sandbox_owner)"
_sandbox_uid="${_sandbox_owner%%:*}"
_sandbox_gid="${_sandbox_owner##*:}"
_sandbox_bootstrap_guest="${OPENSHELL_VM_SANDBOX_BOOTSTRAP:-/.openshell/state/bootstrap.json}"
_sandbox_bootstrap="$(root_path "$_sandbox_bootstrap_guest")"
_sandbox_state_dir="${_sandbox_bootstrap%/*}"
if [ ! -f "$_sandbox_bootstrap" ]; then
    ts "FATAL: capability-free sandbox bootstrap is missing"
    exit 1
fi
chown "${_sandbox_uid}:${_sandbox_gid}" "$_sandbox_state_dir"
chmod 0700 "$_sandbox_state_dir"
for _sandbox_private_file in "$_sandbox_state_dir"/*; do
    [ -f "$_sandbox_private_file" ] || continue
    chown "${_sandbox_uid}:${_sandbox_gid}" "$_sandbox_private_file"
    chmod 0600 "$_sandbox_private_file"
done
if [ "${OPENSHELL_VM_INIT_MODE:-sandbox}" = "capability-probe" ]; then
    ts "starting capability-free VM qualification as ${_sandbox_uid}:${_sandbox_gid}"
    if [ "${ROOT_PREFIX:-}" = "/newroot" ]; then
        exec_supervisor_in_newroot capability-probe-launch "$_sandbox_uid" "$_sandbox_gid"
    fi
    exec /opt/openshell/bin/openshell-sandbox \
        capability-probe-launch "$_sandbox_uid" "$_sandbox_gid"
fi
if [ "${ROOT_PREFIX:-}" = "/newroot" ]; then
    exec_supervisor_in_newroot \
        launch-capability-free "$_sandbox_uid" "$_sandbox_gid" "$_sandbox_bootstrap_guest"
fi
exec /opt/openshell/bin/openshell-sandbox \
    launch-capability-free "$_sandbox_uid" "$_sandbox_gid" "$_sandbox_bootstrap_guest"
}

if [ "${1:-}" != "--post-overlay" ]; then
    setup_overlay_root
fi

shift || true
run_post_overlay_setup
