//! Raw FFI bindings for the libkrun C API.
//!
//! These are manual declarations for the subset of `libkrun.h` functions
//! needed by the gateway. libkrun is a dynamic library providing
//! virtualization-based process isolation via KVM (Linux) or
//! Hypervisor.framework (macOS ARM64).
//!
//! See: <https://github.com/containers/libkrun/blob/main/include/libkrun.h>

use std::ffi::c_char;

// Log level constants matching libkrun.h.
// Not all are used yet but they form the public API surface for log configuration.
#[allow(dead_code)]
pub const KRUN_LOG_LEVEL_OFF: u32 = 0;
#[allow(dead_code)]
pub const KRUN_LOG_LEVEL_ERROR: u32 = 1;
pub const KRUN_LOG_LEVEL_WARN: u32 = 2;
#[allow(dead_code)]
pub const KRUN_LOG_LEVEL_INFO: u32 = 3;
#[allow(dead_code)]
pub const KRUN_LOG_LEVEL_DEBUG: u32 = 4;
#[allow(dead_code)]
pub const KRUN_LOG_LEVEL_TRACE: u32 = 5;

// Network backend flags from libkrun.h.
/// Send the VFKIT magic after establishing the connection, as required by
/// gvproxy in vfkit mode.
pub const NET_FLAG_VFKIT: u32 = 1 << 0;

/// Compatible virtio-net features enabled by `krun_set_passt_fd` and
/// `krun_set_gvproxy_path`. We use the same set for `krun_add_net_unixgram`.
pub const COMPAT_NET_FEATURES: u32 = (1 << 0)  // CSUM
    | (1 << 1)  // GUEST_CSUM
    | (1 << 7)  // GUEST_TSO4
    | (1 << 10) // GUEST_UFO
    | (1 << 11) // HOST_TSO4
    | (1 << 14); // HOST_UFO

// Well-known exit codes from the libkrun init process.
//
// 125 - init cannot set up the environment inside the microVM.
// 126 - init can find the executable but cannot execute it.
// 127 - init cannot find the executable to be run.

unsafe extern "C" {
    /// Sets the log level for the library.
    ///
    /// Returns zero on success or a negative error number on failure.
    pub fn krun_set_log_level(level: u32) -> i32;

    /// Creates a configuration context.
    ///
    /// Returns the context ID (>= 0) on success or a negative error number on failure.
    pub fn krun_create_ctx() -> i32;

    /// Frees an existing configuration context.
    ///
    /// Returns zero on success or a negative error number on failure.
    pub fn krun_free_ctx(ctx_id: u32) -> i32;

    /// Sets the basic configuration parameters for the microVM.
    ///
    /// - `num_vcpus`: the number of vCPUs.
    /// - `ram_mib`: the amount of RAM in MiB.
    ///
    /// Returns zero on success or a negative error number on failure.
    pub fn krun_set_vm_config(ctx_id: u32, num_vcpus: u8, ram_mib: u32) -> i32;

    /// Sets the path to be used as root for the microVM.
    ///
    /// The path is mapped into the VM via virtio-fs. The libkrun init process
    /// uses this as the root filesystem.
    ///
    /// Returns zero on success or a negative error number on failure.
    pub fn krun_set_root(ctx_id: u32, root_path: *const c_char) -> i32;

    /// Sets the working directory for the executable inside the microVM.
    ///
    /// The path is relative to the root configured with `krun_set_root`.
    ///
    /// Returns zero on success or a negative error number on failure.
    pub fn krun_set_workdir(ctx_id: u32, workdir_path: *const c_char) -> i32;

    /// Sets the executable path, arguments, and environment variables.
    ///
    /// - `exec_path`: path relative to the root configured with `krun_set_root`.
    /// - `argv`: null-terminated array of argument string pointers.
    /// - `envp`: null-terminated array of environment variable string pointers
    ///   (format: `KEY=VALUE`). If null, inherits the current environment.
    ///
    /// Returns zero on success or a negative error number on failure.
    pub fn krun_set_exec(
        ctx_id: u32,
        exec_path: *const c_char,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> i32;

    /// Configures a map of host to guest TCP ports for the microVM.
    ///
    /// - `port_map`: null-terminated array of string pointers with format
    ///   `"host_port:guest_port"`.
    ///
    /// Passing NULL instructs libkrun to expose all listening ports in the
    /// guest to the host. Passing an empty (null-terminated) array means no
    /// ports are exposed.
    ///
    /// Exposed ports become accessible by their `host_port` in the guest too,
    /// so for a map `"8080:80"`, guest-side applications must also use port 8080.
    ///
    /// Returns zero on success or a negative error number on failure.
    pub fn krun_set_port_map(ctx_id: u32, port_map: *const *const c_char) -> i32;

    /// Adds an independent virtio-fs device pointing to a host directory.
    ///
    /// - `c_tag`: tag to identify the filesystem in the guest (used for
    ///   mounting: `mount -t virtiofs <tag> <mountpoint>`).
    /// - `c_path`: full path to the host directory to be exposed.
    ///
    /// Returns zero on success or a negative error number on failure.
    pub fn krun_add_virtiofs(ctx_id: u32, c_tag: *const c_char, c_path: *const c_char) -> i32;

    /// Configures the console device to ignore stdin and write output to a file.
    ///
    /// - `c_filepath`: path to the file for console output.
    ///
    /// Returns zero on success or a negative error number on failure.
    pub fn krun_set_console_output(ctx_id: u32, c_filepath: *const c_char) -> i32;

    /// Disable the implicit vsock device (which carries TSI by default).
    ///
    /// Must be called before `krun_add_vsock` to add a vsock with custom
    /// TSI feature flags.
    ///
    /// Returns zero on success or a negative error number on failure.
    pub fn krun_disable_implicit_vsock(ctx_id: u32) -> i32;

    /// Add a vsock device with specified TSI features.
    ///
    /// - `tsi_features`: bitmask of `KRUN_TSI_HIJACK_INET` (1) and
    ///   `KRUN_TSI_HIJACK_UNIX` (2). Use 0 for no TSI hijacking.
    ///
    /// Only one vsock device is supported. Call after
    /// `krun_disable_implicit_vsock`.
    ///
    /// Returns zero on success or a negative error number on failure.
    pub fn krun_add_vsock(ctx_id: u32, tsi_features: u32) -> i32;

    /// Adds an independent virtio-net device with a unixgram-based backend,
    /// such as gvproxy or vmnet-helper.
    ///
    /// Adding ANY `krun_add_net_*` device **automatically disables TSI**. The
    /// guest gets a real `ethN` interface instead of TSI socket interception.
    ///
    /// - `c_path`: path to the Unix datagram socket for the network proxy
    ///   (e.g., gvproxy's `--listen-vfkit` socket). Must be NULL if `fd != -1`.
    /// - `fd`: open file descriptor for the socket. Must be -1 if `c_path`
    ///   is not NULL.
    /// - `c_mac`: 6-byte MAC address array.
    /// - `features`: virtio-net feature bitmask (use `COMPAT_NET_FEATURES`).
    /// - `flags`: generic flags. Use `NET_FLAG_VFKIT` for gvproxy in vfkit
    ///   mode when using `c_path`.
    ///
    /// Returns zero on success or a negative error number on failure.
    pub fn krun_add_net_unixgram(
        ctx_id: u32,
        c_path: *const c_char,
        fd: i32,
        c_mac: *const u8,
        features: u32,
        flags: u32,
    ) -> i32;

    /// Starts and enters the microVM with the configured parameters.
    ///
    /// The VMM takes over stdin/stdout to manage them on behalf of the process
    /// running inside the isolated environment.
    ///
    /// **This function never returns on success.** The VMM calls `exit()` with
    /// the workload's exit code once the microVM shuts down.
    ///
    /// Returns a negative error number only if an error happens before the
    /// microVM is started (e.g., `-EINVAL` for invalid configuration).
    pub fn krun_start_enter(ctx_id: u32) -> i32;
}
