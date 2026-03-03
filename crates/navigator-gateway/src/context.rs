//! Safe wrapper around the libkrun configuration context and VM lifecycle.
//!
//! The main entry point is [`KrunContextBuilder`], obtained via
//! [`KrunContext::builder()`]. After configuring the VM parameters, call
//! [`.build()`](KrunContextBuilder::build) to create a [`KrunContext`], then
//! [`.start_enter()`](KrunContext::start_enter) to boot the microVM in the
//! current process, or [`.fork_start()`](KrunContext::fork_start) to boot it
//! in a child process while the parent retains control.

use std::ffi::{CString, c_char};
use std::mem::ManuallyDrop;
use std::path::{Path, PathBuf};
use std::ptr;

use tracing::{debug, info};

use crate::error::GatewayError;
use crate::ffi;

/// A configured libkrun microVM context, ready to be started.
///
/// Owns the libkrun context ID and frees it on drop (unless consumed by
/// `start_enter`, which never returns).
pub struct KrunContext {
    ctx_id: u32,
}

impl KrunContext {
    /// Create a new builder for configuring a microVM.
    pub fn builder() -> KrunContextBuilder {
        KrunContextBuilder::default()
    }

    /// Boot the microVM and enter it (direct model).
    ///
    /// # Never returns
    ///
    /// On success, this function **never returns**. The libkrun VMM takes over
    /// the process and calls `exit()` with the guest workload's exit code when
    /// the VM shuts down.
    ///
    /// The only way this function returns is if libkrun encounters an error
    /// before actually starting the VM.
    pub fn start_enter(self) -> Result<(), GatewayError> {
        // Prevent Drop from running -- krun_start_enter consumes the context
        // and will exit() the process, so we must not call krun_free_ctx.
        let this = ManuallyDrop::new(self);

        // Raise RLIMIT_NOFILE to the maximum allowed. virtio-fs (used by
        // krun_set_root) needs a large number of file descriptors to map the
        // host directory into the guest. The chroot_vm reference example does
        // the same thing.
        raise_nofile_limit();

        info!(
            ctx_id = this.ctx_id,
            "starting microVM (this process will be taken over)"
        );

        let ret = unsafe { ffi::krun_start_enter(this.ctx_id) };

        // If we reach here, it means krun_start_enter failed.
        Err(GatewayError::StartFailed(ret))
    }

    /// Boot the microVM in a forked child process.
    ///
    /// The parent process retains control and receives the child's PID.
    /// The child process calls `krun_start_enter()`, which never returns on
    /// success.
    ///
    /// # Returns
    ///
    /// - `Ok(child_pid)` in the parent process
    /// - Never returns in the child (on success)
    /// - `Err(...)` if the fork fails or the VM fails to start in the child
    ///
    /// # Safety
    ///
    /// After `fork()`, the child inherits all file descriptors and memory.
    /// `krun_start_enter()` takes over the child process immediately, so
    /// no Rust destructors run in the child. This is safe because
    /// `krun_start_enter` calls `exit()` directly.
    pub fn fork_start(self) -> Result<u32, GatewayError> {
        raise_nofile_limit();

        info!(ctx_id = self.ctx_id, "forking to start microVM in child");

        // Prevent Drop from running in EITHER process. After fork(), the
        // parent and child share kernel-level hypervisor resources (e.g.,
        // Hypervisor.framework VM handles on macOS). If the parent calls
        // krun_free_ctx(), it destroys the VM the child is about to start.
        // The child's krun_start_enter() consumes the context and calls
        // exit() when the VM shuts down, so cleanup is not needed there
        // either.
        let this = ManuallyDrop::new(self);

        let pid = unsafe { libc::fork() };

        if pid < 0 {
            return Err(GatewayError::Fork(std::io::Error::last_os_error()));
        }

        if pid == 0 {
            // Child process: start the VM. This never returns on success.
            let ret = unsafe { ffi::krun_start_enter(this.ctx_id) };
            // If we reach here, start failed. Exit with an error code so the
            // parent can detect it.
            std::process::exit(ret.unsigned_abs().cast_signed());
        }

        // Parent process: return the child PID.
        // We intentionally leak the KrunContext (ManuallyDrop) to avoid
        // destroying the child's VM. The kernel cleans up when the child
        // exits.
        debug!(child_pid = pid, "microVM child process started");
        #[expect(clippy::cast_sign_loss, reason = "checked non-negative above")]
        Ok(pid as u32)
    }
}

impl Drop for KrunContext {
    fn drop(&mut self) {
        debug!(ctx_id = self.ctx_id, "freeing libkrun context");
        unsafe {
            ffi::krun_free_ctx(self.ctx_id);
        }
    }
}

/// A port mapping entry for the microVM (`host_port` -> `guest_port`).
#[derive(Debug, Clone)]
pub struct PortMapping {
    /// Port on the host.
    pub host_port: u16,
    /// Port inside the guest VM.
    pub guest_port: u16,
}

impl PortMapping {
    /// Create a new port mapping.
    pub fn new(host_port: u16, guest_port: u16) -> Self {
        Self {
            host_port,
            guest_port,
        }
    }
}

impl std::fmt::Display for PortMapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host_port, self.guest_port)
    }
}

/// A virtio-fs volume mount (`host_path` -> `guest_tag`).
#[derive(Debug, Clone)]
pub struct VirtiofsMount {
    /// Tag to identify the filesystem in the guest (used in mount command).
    pub tag: String,
    /// Full path to the host directory to expose.
    pub host_path: PathBuf,
}

impl VirtiofsMount {
    /// Create a new virtio-fs mount.
    pub fn new(tag: impl Into<String>, host_path: impl AsRef<Path>) -> Self {
        Self {
            tag: tag.into(),
            host_path: host_path.as_ref().to_path_buf(),
        }
    }
}

/// Builder for configuring and creating a [`KrunContext`].
///
/// # Example
///
/// ```no_run
/// use navigator_gateway::KrunContext;
///
/// let ctx = KrunContext::builder()
///     .vcpus(1)
///     .memory_mib(128)
///     .rootfs("./my-rootfs")
///     .workdir("/")
///     .exec("/bin/echo", &["Hello from microVM!"])
///     .build()
///     .expect("failed to configure microVM");
///
/// // This never returns on success:
/// ctx.start_enter().expect("failed to start microVM");
/// ```
pub struct KrunContextBuilder {
    vcpus: u8,
    memory_mib: u32,
    rootfs: Option<PathBuf>,
    workdir: Option<String>,
    exec_path: Option<String>,
    args: Vec<String>,
    env: Option<Vec<String>>,
    log_level: u32,
    port_map: Vec<PortMapping>,
    virtiofs_mounts: Vec<VirtiofsMount>,
    console_output: Option<PathBuf>,
    disable_tsi: bool,
    /// Path to a gvproxy Unix datagram socket for virtio-net networking.
    /// When set, TSI is automatically disabled by libkrun and the guest
    /// gets a real `eth0` interface with DHCP from gvproxy.
    net_gvproxy: Option<PathBuf>,
}

impl Default for KrunContextBuilder {
    fn default() -> Self {
        Self {
            vcpus: 1,
            memory_mib: 128,
            rootfs: None,
            workdir: None,
            exec_path: None,
            args: Vec::new(),
            env: None,
            log_level: ffi::KRUN_LOG_LEVEL_WARN,
            port_map: Vec::new(),
            virtiofs_mounts: Vec::new(),
            console_output: None,
            disable_tsi: false,
            net_gvproxy: None,
        }
    }
}

#[allow(clippy::return_self_not_must_use)]
impl KrunContextBuilder {
    /// Set the number of virtual CPUs for the microVM.
    pub fn vcpus(mut self, n: u8) -> Self {
        self.vcpus = n;
        self
    }

    /// Set the amount of RAM in MiB for the microVM.
    pub fn memory_mib(mut self, mib: u32) -> Self {
        self.memory_mib = mib;
        self
    }

    /// Set the host directory to be used as the VM's root filesystem.
    ///
    /// This directory is mapped into the VM via virtio-fs. It must contain
    /// an aarch64 Linux userspace (e.g., Alpine minirootfs).
    pub fn rootfs(mut self, path: impl AsRef<Path>) -> Self {
        self.rootfs = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set the working directory inside the VM (relative to rootfs).
    pub fn workdir(mut self, path: impl Into<String>) -> Self {
        self.workdir = Some(path.into());
        self
    }

    /// Set the executable to run inside the VM and its arguments.
    ///
    /// The `exec_path` is relative to the rootfs.
    pub fn exec(mut self, exec_path: impl Into<String>, args: &[impl AsRef<str>]) -> Self {
        self.exec_path = Some(exec_path.into());
        self.args = args.iter().map(|a| a.as_ref().to_string()).collect();
        self
    }

    /// Set environment variables for the guest process.
    ///
    /// Each entry should be in `KEY=VALUE` format. If not called (or called
    /// with `None`), a minimal default environment is used.
    pub fn env(mut self, vars: Option<Vec<String>>) -> Self {
        self.env = vars;
        self
    }

    /// Set the libkrun log level (0=Off .. 5=Trace). Default is 2 (Warn).
    pub fn log_level(mut self, level: u32) -> Self {
        self.log_level = level;
        self
    }

    /// Add a TCP port mapping from host to guest.
    ///
    /// The port will be accessible on `host_port` from the host and will
    /// forward to `guest_port` inside the VM. Note that libkrun also makes
    /// the port accessible inside the guest via `host_port`.
    pub fn port_map(mut self, host_port: u16, guest_port: u16) -> Self {
        self.port_map.push(PortMapping::new(host_port, guest_port));
        self
    }

    /// Add multiple TCP port mappings at once.
    pub fn port_maps(mut self, mappings: impl IntoIterator<Item = PortMapping>) -> Self {
        self.port_map.extend(mappings);
        self
    }

    /// Add a virtio-fs volume mount.
    ///
    /// The host directory at `host_path` will be available inside the guest
    /// as a virtio-fs filesystem with the given `tag`. The guest must mount
    /// it explicitly: `mount -t virtiofs <tag> <mountpoint>`.
    pub fn virtiofs(mut self, tag: impl Into<String>, host_path: impl AsRef<Path>) -> Self {
        self.virtiofs_mounts
            .push(VirtiofsMount::new(tag, host_path));
        self
    }

    /// Redirect VM console output to a file instead of stdout.
    ///
    /// When set, the VM's console device ignores stdin and writes all output
    /// to the specified file. Useful when the VM runs in a forked child and
    /// the parent needs to capture output.
    pub fn console_output(mut self, path: impl AsRef<Path>) -> Self {
        self.console_output = Some(path.as_ref().to_path_buf());
        self
    }

    /// Use gvproxy for virtio-net networking instead of TSI.
    ///
    /// When set, libkrun adds a virtio-net device backed by the gvproxy
    /// Unix datagram socket at the given path. This **automatically disables
    /// TSI**, so the guest gets a real `eth0` interface with DHCP from
    /// gvproxy (default subnet: 192.168.127.0/24, gateway: 192.168.127.1,
    /// guest IP: 192.168.127.2).
    ///
    /// Port forwarding is handled by gvproxy's HTTP API, not by
    /// `krun_set_port_map` (which is TSI-only).
    ///
    /// Note: When using gvproxy, `port_map` entries are ignored by libkrun.
    /// Use gvproxy's HTTP API endpoint to configure port forwarding instead.
    pub fn net_gvproxy(mut self, socket_path: impl AsRef<Path>) -> Self {
        self.net_gvproxy = Some(socket_path.as_ref().to_path_buf());
        self
    }

    /// Disable TSI (Transparent Socket Impersonation) for the microVM.
    ///
    /// When enabled, libkrun's implicit vsock (which hijacks all guest
    /// `connect()` syscalls on inet sockets) is replaced with a vsock
    /// device that has no TSI features. This allows localhost traffic
    /// inside the guest to flow through the real kernel loopback instead
    /// of being tunnelled through vsock to the host.
    ///
    /// This is required for workloads like k3s that make many concurrent
    /// internal localhost connections (API server, kine, controllers).
    /// TSI intercepts those connections and overwhelms the vsock muxer,
    /// causing deadlocks.
    ///
    /// Port mapping via `krun_set_port_map` still works because it uses
    /// the vsock device (with `tsi_features = 0`, only explicit port
    /// mappings are forwarded).
    pub fn disable_tsi(mut self, disable: bool) -> Self {
        self.disable_tsi = disable;
        self
    }

    /// Build the [`KrunContext`] by calling the libkrun C API to create and
    /// configure the microVM.
    ///
    /// # Errors
    ///
    /// Returns [`GatewayError`] if the rootfs doesn't exist, if any libkrun
    /// API call fails, or if string arguments contain interior null bytes.
    pub fn build(self) -> Result<KrunContext, GatewayError> {
        // Validate rootfs exists.
        let rootfs = self
            .rootfs
            .as_ref()
            .ok_or_else(|| GatewayError::RootfsNotFound(PathBuf::from("<not set>")))?;

        if !rootfs.is_dir() {
            return Err(GatewayError::RootfsNotFound(rootfs.clone()));
        }

        let exec_path = self.exec_path.as_deref().unwrap_or("/bin/sh");

        // Set log level.
        check_ret("krun_set_log_level", unsafe {
            ffi::krun_set_log_level(self.log_level)
        })?;

        // Create the libkrun context.
        let ctx_id = unsafe { ffi::krun_create_ctx() };
        if ctx_id < 0 {
            return Err(GatewayError::ContextCreation(ctx_id));
        }
        #[expect(clippy::cast_sign_loss, reason = "checked non-negative above")]
        let ctx_id = ctx_id as u32;

        debug!(
            ctx_id,
            vcpus = self.vcpus,
            ram_mib = self.memory_mib,
            "configuring microVM"
        );

        // From here on, if we hit an error we need to clean up the context.
        // We'll create KrunContext now so Drop handles it.
        let ctx = KrunContext { ctx_id };

        // Configure VM resources.
        check_ret("krun_set_vm_config", unsafe {
            ffi::krun_set_vm_config(ctx_id, self.vcpus, self.memory_mib)
        })?;

        // Set root filesystem.
        let c_rootfs = path_to_cstring(rootfs)?;
        check_ret("krun_set_root", unsafe {
            ffi::krun_set_root(ctx_id, c_rootfs.as_ptr())
        })?;

        // Set working directory.
        if let Some(ref workdir) = self.workdir {
            let c_workdir = CString::new(workdir.as_str())?;
            check_ret("krun_set_workdir", unsafe {
                ffi::krun_set_workdir(ctx_id, c_workdir.as_ptr())
            })?;
        }

        // Configure gvproxy-based virtio-net networking.
        //
        // When a net device is added, libkrun automatically disables TSI.
        // The guest gets a real eth0 with DHCP from gvproxy. This MUST be
        // called before krun_set_port_map (per libkrun.h).
        if let Some(ref gvproxy_path) = self.net_gvproxy {
            let c_path = path_to_cstring(gvproxy_path)?;
            // Default MAC address for the guest.
            let mac: [u8; 6] = [0x02, 0x42, 0xAC, 0x11, 0x00, 0x02];

            debug!(
                path = %gvproxy_path.display(),
                "adding gvproxy virtio-net device (disables TSI)"
            );
            check_ret("krun_add_net_unixgram", unsafe {
                ffi::krun_add_net_unixgram(
                    ctx_id,
                    c_path.as_ptr(),
                    -1, // no fd, use path
                    mac.as_ptr(),
                    ffi::COMPAT_NET_FEATURES,
                    ffi::NET_FLAG_VFKIT,
                )
            })?;
        }

        // Configure port mapping (TSI-only, skipped when gvproxy is used).
        if !self.port_map.is_empty() {
            let map_strings: Vec<String> = self.port_map.iter().map(ToString::to_string).collect();
            let c_map_strings = to_cstring_vec(&map_strings)?;
            let c_port_map = to_ptr_array(&c_map_strings);

            debug!(?map_strings, "setting port map");
            check_ret("krun_set_port_map", unsafe {
                ffi::krun_set_port_map(ctx_id, c_port_map.as_ptr())
            })?;
        }

        // Configure virtio-fs volume mounts.
        for mount in &self.virtiofs_mounts {
            let c_tag = CString::new(mount.tag.as_str())?;
            let c_path = path_to_cstring(&mount.host_path)?;

            debug!(tag = mount.tag, path = %mount.host_path.display(), "adding virtiofs mount");
            check_ret("krun_add_virtiofs", unsafe {
                ffi::krun_add_virtiofs(ctx_id, c_tag.as_ptr(), c_path.as_ptr())
            })?;
        }

        // Configure console output redirection.
        if let Some(ref console_path) = self.console_output {
            let c_console = path_to_cstring(console_path)?;
            check_ret("krun_set_console_output", unsafe {
                ffi::krun_set_console_output(ctx_id, c_console.as_ptr())
            })?;
        }

        // Disable TSI (Transparent Socket Impersonation) if requested.
        //
        // TSI intercepts ALL guest connect() syscalls on inet sockets and
        // tunnels them through vsock to the host. This breaks workloads
        // that rely on internal localhost connections (e.g., k3s).
        //
        // We replace the implicit vsock with a bare vsock (tsi_features=0)
        // so that only explicit port mappings are forwarded while localhost
        // traffic stays inside the guest kernel.
        if self.disable_tsi {
            debug!(ctx_id, "disabling TSI (transparent socket impersonation)");
            check_ret("krun_disable_implicit_vsock", unsafe {
                ffi::krun_disable_implicit_vsock(ctx_id)
            })?;
            check_ret("krun_add_vsock", unsafe { ffi::krun_add_vsock(ctx_id, 0) })?;
        }

        // Set executable, arguments, and environment.
        let c_exec = CString::new(exec_path)?;
        let c_args = to_cstring_vec(&self.args)?;
        let c_arg_ptrs = to_ptr_array(&c_args);

        // If no explicit env was provided, use a minimal default environment.
        // We must NOT pass NULL to krun_set_exec's envp parameter because
        // libkrun would then serialize the entire host environment into the
        // kernel command line, which easily overflows its 4096-byte limit
        // on developer machines with large PATH/etc.
        let default_env = vec![
            "HOME=/root".to_string(),
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            "TERM=xterm".to_string(),
        ];
        let env_ref = self.env.as_ref().unwrap_or(&default_env);
        let c_env_strings = to_cstring_vec(env_ref)?;
        let c_envp = to_ptr_array(&c_env_strings);

        check_ret("krun_set_exec", unsafe {
            ffi::krun_set_exec(
                ctx_id,
                c_exec.as_ptr(),
                c_arg_ptrs.as_ptr(),
                c_envp.as_ptr(),
            )
        })?;

        // Keep CStrings alive until after the FFI call.
        drop(c_env_strings);

        info!(
            ctx_id,
            rootfs = %rootfs.display(),
            exec = exec_path,
            ports = ?self.port_map.iter().map(ToString::to_string).collect::<Vec<_>>(),
            virtiofs = self.virtiofs_mounts.len(),
            "microVM configured successfully"
        );

        Ok(ctx)
    }
}

/// Check a libkrun return code; zero means success, negative means error.
fn check_ret(call: &'static str, ret: i32) -> Result<(), GatewayError> {
    if ret < 0 {
        Err(GatewayError::Configuration { call, code: ret })
    } else {
        Ok(())
    }
}

/// Convert a `Path` to a `CString`.
fn path_to_cstring(path: &Path) -> Result<CString, GatewayError> {
    let s = path.to_str().ok_or(GatewayError::Configuration {
        call: "path_to_cstring",
        code: -1,
    })?;
    Ok(CString::new(s)?)
}

/// Convert a slice of strings to a `Vec<CString>`.
fn to_cstring_vec(strings: &[String]) -> Result<Vec<CString>, GatewayError> {
    strings
        .iter()
        .map(|s| Ok(CString::new(s.as_str())?))
        .collect()
}

/// Create a null-terminated array of C string pointers suitable for passing
/// to libkrun functions that expect `const char *const argv[]`.
///
/// The returned `Vec` contains pointers into the `CString` values (which must
/// outlive the returned `Vec`) followed by a null terminator.
fn to_ptr_array(strings: &[CString]) -> Vec<*const c_char> {
    let mut ptrs: Vec<*const c_char> = strings.iter().map(|s| s.as_ptr()).collect();
    ptrs.push(ptr::null());
    ptrs
}

/// Raise `RLIMIT_NOFILE` to the maximum allowed value.
///
/// virtio-fs (used by `krun_set_root` to map the rootfs directory) requires a
/// large number of file descriptors. Without this, `krun_start_enter` can fail
/// with internal errors. This mirrors what the upstream `chroot_vm` example does.
fn raise_nofile_limit() {
    use libc::{RLIMIT_NOFILE, getrlimit, rlimit, setrlimit};

    let mut rlim = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { getrlimit(RLIMIT_NOFILE, &raw mut rlim) } == 0 {
        rlim.rlim_cur = rlim.rlim_max;
        if unsafe { setrlimit(RLIMIT_NOFILE, &raw const rlim) } != 0 {
            debug!("failed to raise RLIMIT_NOFILE (non-fatal)");
        } else {
            debug!(limit = rlim.rlim_cur, "raised RLIMIT_NOFILE");
        }
    }
}
