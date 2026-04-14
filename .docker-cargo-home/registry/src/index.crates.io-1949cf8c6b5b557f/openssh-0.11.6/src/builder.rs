use super::{Error, Session};

use std::borrow::Cow;
use std::ffi::OsString;
use std::iter::IntoIterator;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::str;
use std::{fs, io};

use once_cell::sync::OnceCell;
use tempfile::{Builder, TempDir};
use tokio::process;

#[cfg(not(windows))]
fn state_dir() -> Option<PathBuf> {
    fn get_absolute_path(path: OsString) -> Option<PathBuf> {
        let path = PathBuf::from(path);
        path.is_absolute().then_some(path)
    }

    #[allow(deprecated)]
    if let Some(xdg) = std::env::var_os("XDG_STATE_HOME") {
        get_absolute_path(xdg)
    } else if let Some(home) = std::env::home_dir() {
        Some(get_absolute_path(home.into())?.join(".local/state"))
    } else {
        None
    }
}

#[cfg(windows)]
fn state_dir() -> Option<PathBuf> {
    None
}

/// The returned `&'static Path` can be coreced to any lifetime.
fn get_default_control_dir<'a>() -> Result<&'a Path, Error> {
    static DEFAULT_CONTROL_DIR: OnceCell<Option<Box<Path>>> = OnceCell::new();

    DEFAULT_CONTROL_DIR
        .get_or_try_init(|| {
            if let Some(state_dir) = state_dir() {
                fs::create_dir_all(&state_dir).map_err(Error::Connect)?;

                Ok(Some(state_dir.into_boxed_path()))
            } else {
                Ok(None)
            }
        })
        .map(|default_control_dir| {
            default_control_dir
                .as_deref()
                .unwrap_or_else(|| Path::new("./"))
        })
}

fn clean_history_control_dir(socketdir: &Path, prefix: &str) -> io::Result<()> {
    // Read the entries in the parent directory
    fs::read_dir(socketdir)?
        // Filter out and keep only the valid entries
        .filter_map(Result::ok)
        // Filter the entries to only include files that start with prefix
        .filter(|entry| {
            if let Ok(file_type) = entry.file_type() {
                file_type.is_dir() && entry.file_name().to_string_lossy().starts_with(prefix)
            } else {
                false
            }
        })
        // For each matching entry, remove the directory
        .for_each(|entry| {
            let _ = fs::remove_dir_all(entry.path());
        });
    Ok(())
}

/// Build a [`Session`] with options.
#[derive(Debug, Clone)]
pub struct SessionBuilder {
    user: Option<String>,
    port: Option<String>,
    keyfile: Option<PathBuf>,
    connect_timeout: Option<String>,
    server_alive_interval: Option<u64>,
    known_hosts_check: KnownHosts,
    control_dir: Option<PathBuf>,
    control_persist: ControlPersist,
    clean_history_control_dir: bool,
    config_file: Option<PathBuf>,
    compression: Option<bool>,
    jump_hosts: Vec<Box<str>>,
    user_known_hosts_file: Option<Box<Path>>,
    ssh_auth_sock: Option<Box<Path>>,
}

impl Default for SessionBuilder {
    fn default() -> Self {
        Self {
            user: None,
            port: None,
            keyfile: None,
            connect_timeout: None,
            server_alive_interval: None,
            known_hosts_check: KnownHosts::Add,
            control_dir: None,
            control_persist: ControlPersist::Forever,
            clean_history_control_dir: false,
            config_file: None,
            compression: None,
            jump_hosts: Vec::new(),
            user_known_hosts_file: None,
            ssh_auth_sock: None,
        }
    }
}

impl SessionBuilder {
    /// Return the user set in builder.
    pub fn get_user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// Return the port set in builder.
    pub fn get_port(&self) -> Option<&str> {
        self.port.as_deref()
    }

    /// Set the ssh user (`ssh -l`).
    ///
    /// Defaults to `None`.
    pub fn user(&mut self, user: String) -> &mut Self {
        self.user = Some(user);
        self
    }

    /// Set the port to connect on (`ssh -p`).
    ///
    /// Defaults to `None`.
    pub fn port(&mut self, port: u16) -> &mut Self {
        self.port = Some(format!("{}", port));
        self
    }

    /// Set the keyfile to use (`ssh -i`).
    ///
    /// Defaults to `None`.
    pub fn keyfile(&mut self, p: impl AsRef<Path>) -> &mut Self {
        self.keyfile = Some(p.as_ref().to_path_buf());
        self
    }

    /// See [`KnownHosts`].
    ///
    /// Default `KnownHosts::Add`.
    pub fn known_hosts_check(&mut self, k: KnownHosts) -> &mut Self {
        self.known_hosts_check = k;
        self
    }

    /// Set the connection timeout (`ssh -o ConnectTimeout`).
    ///
    /// This value is specified in seconds. Any sub-second duration remainder will be ignored.
    /// Defaults to `None`.
    pub fn connect_timeout(&mut self, d: std::time::Duration) -> &mut Self {
        self.connect_timeout = Some(d.as_secs().to_string());
        self
    }

    /// Set the timeout interval after which if no data has been received from the server, ssh
    /// will request a response from the server (`ssh -o ServerAliveInterval`).
    ///
    /// This value is specified in seconds. Any sub-second duration remainder will be ignored.
    /// Defaults to `None`.
    pub fn server_alive_interval(&mut self, d: std::time::Duration) -> &mut Self {
        self.server_alive_interval = Some(d.as_secs());
        self
    }

    /// Set the directory in which the temporary directory containing the control socket will
    /// be created.
    ///
    /// If not set, openssh will try to use `$XDG_STATE_HOME`, `$HOME/.local/state` on unix, and fallback to
    /// `./` (the current directory) if it failed.
    ///
    #[cfg(not(windows))]
    #[cfg_attr(docsrs, doc(cfg(not(windows))))]
    pub fn control_directory(&mut self, p: impl AsRef<Path>) -> &mut Self {
        self.control_dir = Some(p.as_ref().to_path_buf());
        self
    }

    /// Clean up the temporary directories with the `.ssh-connection` prefix
    /// in directory specified by [`SessionBuilder::control_directory`], created by
    /// previous `openssh::Session` that is not cleaned up for some reasons
    /// (e.g. process getting killed, abort on panic, etc)
    ///
    /// Use this with caution, do not enable this if you don't understand
    /// what it does,
    #[cfg(not(windows))]
    #[cfg_attr(docsrs, doc(cfg(not(windows))))]
    pub fn clean_history_control_directory(&mut self, clean: bool) -> &mut Self {
        self.clean_history_control_dir = clean;
        self
    }

    /// Set the ControlPersist option to configure how long the controlling
    /// ssh session should stay alive.
    ///
    /// Defaults to `ControlPersist::Forever`.
    ///
    pub fn control_persist(&mut self, value: ControlPersist) -> &mut Self {
        self.control_persist = value;
        self
    }

    /// Set an alternative per-user configuration file.
    ///
    /// By default, ssh uses `~/.ssh/config`. This is equivalent to `ssh -F <p>`.
    ///
    /// Defaults to `None`.
    pub fn config_file(&mut self, p: impl AsRef<Path>) -> &mut Self {
        self.config_file = Some(p.as_ref().to_path_buf());
        self
    }

    /// Enable or disable compression (including stdin, stdout, stderr, data
    /// for forwarded TCP and unix-domain connections, sftp and scp
    /// connections).
    ///
    /// Note that the ssh server can forcibly disable the compression.
    ///
    /// By default, ssh uses configure value set in `~/.ssh/config`.
    ///
    /// If `~/.ssh/config` does not enable compression, then it is disabled
    /// by default.
    pub fn compression(&mut self, compression: bool) -> &mut Self {
        self.compression = Some(compression);
        self
    }

    /// Specify one or multiple jump hosts.
    ///
    /// Connect to the target host by first making a ssh connection to the
    /// jump host described by destination and then establishing a TCP
    /// forwarding to the ultimate destination from there.
    ///
    /// Multiple jump hops may be specified.
    /// This is a shortcut to specify a ProxyJump configuration directive.
    ///
    /// Note that configuration directives specified by [`SessionBuilder`]
    /// do not apply to the jump hosts.
    ///
    /// Use ~/.ssh/config to specify configuration for jump hosts.
    pub fn jump_hosts<T: AsRef<str>>(&mut self, hosts: impl IntoIterator<Item = T>) -> &mut Self {
        self.jump_hosts = hosts
            .into_iter()
            .map(|s| s.as_ref().to_string().into_boxed_str())
            .collect();
        self
    }

    /// Specify the path to the `known_hosts` file.
    ///
    /// The path provided may use tilde notation (`~`) to refer to the user's
    /// home directory.
    ///
    /// The default is `~/.ssh/known_hosts` and `~/.ssh/known_hosts2`.
    pub fn user_known_hosts_file(&mut self, user_known_hosts_file: impl AsRef<Path>) -> &mut Self {
        self.user_known_hosts_file =
            Some(user_known_hosts_file.as_ref().to_owned().into_boxed_path());
        self
    }

    /// Specify the path to the ssh-agent.
    ///
    /// The path provided may use tilde notation (`~`) to refer to the user's
    /// home directory.
    ///
    /// The default is `None`.
    pub fn ssh_auth_sock(&mut self, ssh_auth_sock: impl AsRef<Path>) -> &mut Self {
        self.ssh_auth_sock = Some(ssh_auth_sock.as_ref().to_owned().into_boxed_path());
        self
    }

    /// Connect to the host at the given `host` over SSH using process impl, which will
    /// spawn a new ssh process for each `Child` created.
    ///
    /// The format of `destination` is the same as the `destination` argument to `ssh`. It may be
    /// specified as either `[user@]hostname` or a URI of the form `ssh://[user@]hostname[:port]`.
    /// A username or port that is specified in the connection string overrides the one set in the
    /// builder (but does not change the builder).
    ///
    /// If connecting requires interactive authentication based on `STDIN` (such as reading a
    /// password), the connection will fail. Consider setting up keypair-based authentication
    /// instead.
    #[cfg(feature = "process-mux")]
    #[cfg_attr(docsrs, doc(cfg(feature = "process-mux")))]
    pub async fn connect<S: AsRef<str>>(&self, destination: S) -> Result<Session, Error> {
        self.connect_impl(destination.as_ref(), Session::new_process_mux)
            .await
    }

    /// Connect to the host at the given `host` over SSH using native mux, which will
    /// create a new local socket connection for each `Child` created.
    ///
    /// See the crate-level documentation for more details on the difference between native and process-based mux.
    ///
    /// The format of `destination` is the same as the `destination` argument to `ssh`. It may be
    /// specified as either `[user@]hostname` or a URI of the form `ssh://[user@]hostname[:port]`.
    /// A username or port that is specified in the connection string overrides the one set in the
    /// builder (but does not change the builder).
    ///
    /// If connecting requires interactive authentication based on `STDIN` (such as reading a
    /// password), the connection will fail. Consider setting up keypair-based authentication
    /// instead.
    #[cfg(feature = "native-mux")]
    #[cfg_attr(docsrs, doc(cfg(feature = "native-mux")))]
    pub async fn connect_mux<S: AsRef<str>>(&self, destination: S) -> Result<Session, Error> {
        self.connect_impl(destination.as_ref(), Session::new_native_mux)
            .await
    }

    async fn connect_impl(
        &self,
        destination: &str,
        f: fn(TempDir) -> Session,
    ) -> Result<Session, Error> {
        let (builder, destination) = self.resolve(destination);
        let tempdir = builder.launch_master(destination).await?;
        Ok(f(tempdir))
    }

    /// [`SessionBuilder`] support for `destination` parsing.
    /// The format of `destination` is the same as the `destination` argument to `ssh`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use openssh::SessionBuilder;
    /// let b = SessionBuilder::default();
    /// let (b, d) = b.resolve("ssh://test-user@127.0.0.1:2222");
    /// assert_eq!(b.get_port().as_deref(), Some("2222"));
    /// assert_eq!(b.get_user().as_deref(), Some("test-user"));
    /// assert_eq!(d, "127.0.0.1");
    /// ```
    pub fn resolve<'a, 'b>(&'a self, mut destination: &'b str) -> (Cow<'a, Self>, &'b str) {
        // the "new" ssh://user@host:port form is not supported by all versions of ssh,
        // so we always translate it into the option form.
        let mut user = None;
        let mut port = None;
        if destination.starts_with("ssh://") {
            destination = &destination[6..];
            if let Some(at) = destination.rfind('@') {
                // specified a username -- extract it:
                user = Some(&destination[..at]);
                destination = &destination[(at + 1)..];
            }
            if let Some(colon) = destination.rfind(':') {
                let p = &destination[(colon + 1)..];
                if let Ok(p) = p.parse() {
                    // user specified a port -- extract it:
                    port = Some(p);
                    destination = &destination[..colon];
                }
            }
        }

        if user.is_none() && port.is_none() {
            return (Cow::Borrowed(self), destination);
        }

        let mut with_overrides = self.clone();
        if let Some(user) = user {
            with_overrides.user(user.to_owned());
        }

        if let Some(port) = port {
            with_overrides.port(port);
        }

        (Cow::Owned(with_overrides), destination)
    }

    /// Create ssh master session and return [`TempDir`] which
    /// contains the ssh control socket.
    pub async fn launch_master(&self, destination: &str) -> Result<TempDir, Error> {
        let socketdir = if let Some(socketdir) = self.control_dir.as_ref() {
            socketdir
        } else {
            get_default_control_dir()?
        };

        let prefix = ".ssh-connection";

        if self.clean_history_control_dir {
            let _ = clean_history_control_dir(socketdir, prefix);
        }

        let dir = Builder::new()
            .prefix(prefix)
            .tempdir_in(socketdir)
            .map_err(Error::Master)?;

        let log = dir.path().join("log");

        let mut init = process::Command::new("ssh");

        init.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .arg("-E")
            .arg(&log)
            .arg("-S")
            .arg(dir.path().join("master"))
            .arg("-M")
            .arg("-f")
            .arg("-N")
            .arg("-o")
            .arg(self.control_persist.as_option().deref())
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg(self.known_hosts_check.as_option());

        if let Some(ref timeout) = self.connect_timeout {
            init.arg("-o").arg(format!("ConnectTimeout={}", timeout));
        }

        if let Some(ref interval) = self.server_alive_interval {
            init.arg("-o")
                .arg(format!("ServerAliveInterval={}", interval));
        }

        if let Some(ref port) = self.port {
            init.arg("-p").arg(port);
        }

        if let Some(ref user) = self.user {
            init.arg("-l").arg(user);
        }

        if let Some(ref k) = self.keyfile {
            // if the user gives a keyfile, _only_ use that keyfile
            init.arg("-o").arg("IdentitiesOnly=yes");
            init.arg("-i").arg(k);
        }

        if let Some(ref config_file) = self.config_file {
            init.arg("-F").arg(config_file);
        }

        if let Some(compression) = self.compression {
            let arg = if compression { "yes" } else { "no" };

            init.arg("-o").arg(format!("Compression={}", arg));
        }

        if let Some(ssh_auth_sock) = self.ssh_auth_sock.as_deref() {
            init.env("SSH_AUTH_SOCK", ssh_auth_sock);
        }

        let mut it = self.jump_hosts.iter();

        if let Some(jump_host) = it.next() {
            let s = jump_host.to_string();

            let dest = it.fold(s, |mut s, jump_host| {
                s.push(',');
                s.push_str(jump_host);
                s
            });

            init.arg("-J").arg(&dest);
        }

        if let Some(user_known_hosts_file) = &self.user_known_hosts_file {
            let mut option: OsString = "UserKnownHostsFile=".into();
            option.push(&**user_known_hosts_file);
            init.arg("-o").arg(option);
        }

        init.arg(destination);

        // we spawn and immediately wait, because the process is supposed to fork.
        let status = init.status().await.map_err(Error::Connect)?;

        if !status.success() {
            let output = fs::read_to_string(log).map_err(Error::Connect)?;

            Err(Error::interpret_ssh_error(&output))
        } else {
            Ok(dir)
        }
    }
}

/// Specifies how long the controlling ssh process should stay alive.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub enum ControlPersist {
    /// Will stay alive indefinitely.
    #[default]
    Forever,
    /// Will be closed after the initial connection is closed
    ClosedAfterInitialConnection,
    /// If the ssh control server has been idle for specified duration
    /// (in seconds), it will exit.
    IdleFor(std::num::NonZeroUsize),
}

impl ControlPersist {
    fn as_option(&self) -> Cow<'_, str> {
        match self {
            ControlPersist::Forever => Cow::Borrowed("ControlPersist=yes"),
            ControlPersist::ClosedAfterInitialConnection => Cow::Borrowed("ControlPersist=no"),
            ControlPersist::IdleFor(d) => Cow::Owned(format!("ControlPersist={}s", d.get())),
        }
    }
}

/// Specifies how the host's key fingerprint should be handled.
#[derive(Debug, Clone)]
pub enum KnownHosts {
    /// The host's fingerprint must match what is in the known hosts file.
    ///
    /// If the host is not in the known hosts file, the connection is rejected.
    ///
    /// This corresponds to `ssh -o StrictHostKeyChecking=yes`.
    Strict,
    /// Strict, but if the host is not already in the known hosts file, it will be added.
    ///
    /// This corresponds to `ssh -o StrictHostKeyChecking=accept-new`.
    Add,
    /// Accept whatever key the server provides and add it to the known hosts file.
    ///
    /// This corresponds to `ssh -o StrictHostKeyChecking=no`.
    Accept,
}

impl KnownHosts {
    fn as_option(&self) -> &'static str {
        match *self {
            KnownHosts::Strict => "StrictHostKeyChecking=yes",
            KnownHosts::Add => "StrictHostKeyChecking=accept-new",
            KnownHosts::Accept => "StrictHostKeyChecking=no",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SessionBuilder;

    #[test]
    fn resolve() {
        let b = SessionBuilder::default();
        let (b, d) = b.resolve("ssh://test-user@127.0.0.1:2222");
        assert_eq!(b.port.as_deref(), Some("2222"));
        assert_eq!(b.user.as_deref(), Some("test-user"));
        assert_eq!(d, "127.0.0.1");

        let b = SessionBuilder::default();
        let (b, d) = b.resolve("ssh://test-user@opensshtest:2222");
        assert_eq!(b.port.as_deref(), Some("2222"));
        assert_eq!(b.user.as_deref(), Some("test-user"));
        assert_eq!(d, "opensshtest");

        let b = SessionBuilder::default();
        let (b, d) = b.resolve("ssh://opensshtest:2222");
        assert_eq!(b.port.as_deref(), Some("2222"));
        assert_eq!(b.user.as_deref(), None);
        assert_eq!(d, "opensshtest");

        let b = SessionBuilder::default();
        let (b, d) = b.resolve("ssh://test-user@opensshtest");
        assert_eq!(b.port.as_deref(), None);
        assert_eq!(b.user.as_deref(), Some("test-user"));
        assert_eq!(d, "opensshtest");

        let b = SessionBuilder::default();
        let (b, d) = b.resolve("ssh://opensshtest");
        assert_eq!(b.port.as_deref(), None);
        assert_eq!(b.user.as_deref(), None);
        assert_eq!(d, "opensshtest");

        let b = SessionBuilder::default();
        let (b, d) = b.resolve("opensshtest");
        assert_eq!(b.port.as_deref(), None);
        assert_eq!(b.user.as_deref(), None);
        assert_eq!(d, "opensshtest");
    }
}
