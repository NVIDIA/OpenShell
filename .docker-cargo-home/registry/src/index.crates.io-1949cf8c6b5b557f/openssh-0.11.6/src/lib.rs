//! Scriptable SSH through OpenSSH (**only works on unix**).
//!
//! This crate wraps the OpenSSH remote login client (`ssh` on most machines), and provides
//! a convenient mechanism for running commands on remote hosts. Since all commands are executed
//! through the `ssh` command, all your existing configuration (e.g., in `.ssh/config`) should
//! continue to work as expected.
//!
//! # Executing remote processes
//!
//! The library's API is modeled closely after that of [`std::process::Command`], since `ssh` also
//! attempts to make the remote process seem as much as possible like a local command. However,
//! there are some differences.
//!
//! First of all, all remote commands are executed in the context of a single ssh
//! [session](Session). Authentication happens once when the session is
//! [established](Session::connect), and subsequent command invocations re-use the same connection.
//!
//! Note that the maximum number of multiplexed remote commands is 10 by default. This value can be
//! increased by changing the `MaxSessions` setting in [`sshd_config`].
//!
//! Much like with [`std::process::Command`], you have multiple
//! options when it comes to launching a remote command. You can
//! [spawn](Command::spawn) the remote command, which just gives you a
//! handle to the running process, you can run the command and wait
//! for its [output](Command::output), or you can run it and just
//! extract its [exit status](Command::status). Unlike its `std`
//! counterpart though, these methods on [`OwningCommand`] can fail
//! even if the remote command executed successfully, since there is a
//! fallible network separating you from it.
//!
//! Also unlike its `std` counterpart, [`spawn`](OwningCommand::spawn) gives you a [`Child`] rather
//! than a [`std::process::Child`]. Behind the scenes, a remote child is really just a process
//! handle to the _local_ `ssh` instance corresponding to the spawned remote command. The behavior
//! of the methods of [`RemoteChild`] therefore match the behavior of `ssh`, rather than that of
//! the remote command directly. Usually, these are the same, though not always, as highlighted in
//! the documetantation the individual methods. See also the section below on Remote Shells.
//!
//! # Connection modes
//!
//! This library provides two way to connect to the [`ControlMaster`]:
//!
//! One is to spawn a new process, the other is to connect to
//! the control socket directly.
//!
//! The process implementation executes remote commands by invoking
//! the ssh command locally with arguments that make the invocation
//! reuse the connections set up by the control master.
//!
//! This maximizes compatibility with OpenSSH, but loses out on some fidelity
//! in information about execution since only the exit code and the output of
//! the ssh command is available to inspect.
//!
//! The native mux implementation on the other hand connects directly to
//! the ssh control master and executes commands and retrieves the exit codes and
//! the output of the remote process over its native protocol.
//!
//! This gives better access to error information at the cost of introducing
//! more non-OpenSSH code into the call path.
//!
//! The former parses the stdout/stderr of the ssh control master to retrieve the error
//! for any failed operations, while the later retrieves the error from the control socket
//! directly.
//!
//! Thus, the error handling in the later is more robust.
//!
//! Also, the former requires one process to be spawn for every connection while the later only
//! needs to create one socket, so the later has better performance and consumes less resource.
//!
//! Behind the scenes, the crate uses ssh's [`ControlMaster`] feature to multiplex the channels for
//! the different remote commands. Because of this, each remote command is tied to the lifetime of
//! the [`Session`] that spawned them. When the session is [closed](Session::close), the connection
//! is severed, and there can be no outstanding remote clients.
//!
//! # Authentication
//!
//! This library supports only password-less authentication schemes. If running `ssh` to a target
//! host requires you to provide input on standard input (`STDIN`), then this crate will not work
//! for you. You should set up keypair-based authentication instead.
//!
//! # Errors
//!
//! Since we are wrapping the `ssh`, which in turn runs a remote command that we do not control, we
//! do not have a reliable way to tell the difference between what is a failure of the SSH
//! connection itself, and what is a program error from the remote host. We do our best with some
//! heuristics (like `ssh` exiting with status code 255 if a connection error occurs), but the
//! errors from this crate will almost necessarily be worse than those of a native SSH
//! implementation. Sorry in advance :)
//!
//! This also means that you may see strange errors when the remote process is terminated by a
//! signal (such as through `kill` or `pkill`). When this happens, all the local ssh program sees
//! is that the remote process disappeared, and so it returns with an error. It does not
//! communicate that the process exited due to a signal. In cases like this, your call will return
//! [`Error::Disconnected`], because the connection to _that_ remote process was disconnected. The
//! ssh connection as a whole is likely still intact.
//!
//! To check if the connection has truly failed, use [`Session::check`]. It will return `Ok` if the
//! master connection is still operational, and _may_ provide you with more information than you
//! got from the failing command (that is, just [`Error::Disconnected`]) if it is not.
//!
//! # Remote Shells
//!
//! When you invoke a remote command through ssh, the remote command is executed by a shell on the
//! remote end. That shell _interprets_ anything passed to it — it might evalute words starting
//! with `$` as variables, split arguments by whitespace, and other things a shell is wont to do.
//! Since that is _usually_ not what you expect to happen, `.arg("a b")` should pass a _single_
//! argument with the value `a b`, `openssh` _escapes_ every argument (and the command itself) by
//! default using [`shell-escape`]. This works well in most cases, but might run into issues when
//! the remote shell (generally the remote user's login shell) has a different syntax than the
//! shell `shell-escape` targets (bash). For example, Windows shells have different escaping syntax
//! than bash does.
//!
//! If this applies to you, you can use [`raw_arg`](Command::raw_arg),
//! [`raw_args`](Command::raw_args), and [`raw_command`](Session::raw_command) to bypass the
//! escaping that `openssh` normally does for you.
//!
//! # Sftp subsystem
//!
//! For sftp and other ssh subsystem, check [`Session::subsystem`] for more information.
//!
//! # Examples
//!
//! ```rust,no_run
//! # #[cfg(feature = "native-mux")]
//! # #[tokio::main]
//! # async fn main() -> Result<(), openssh::Error> {
//! use openssh::{Session, KnownHosts};
//!
//! let session = Session::connect_mux("me@ssh.example.com", KnownHosts::Strict).await?;
//!
//! let ls = session.command("ls").output().await?;
//! eprintln!("{}", String::from_utf8(ls.stdout).expect("server output was not valid UTF-8"));
//!
//! let whoami = session.command("whoami").output().await?;
//! assert_eq!(whoami.stdout, b"me\n");
//!
//! session.close().await?;
//! # Ok(()) }
//! ```
//!
//!   [`ControlMaster`]: https://en.wikibooks.org/wiki/OpenSSH/Cookbook/Multiplexing
//!   [`sshd_config`]: https://linux.die.net/man/5/sshd_config
//!   [`shell-escape`]: https://crates.io/crates/shell-escape

#![warn(
    missing_docs,
    missing_debug_implementations,
    rustdoc::broken_intra_doc_links,
    rust_2018_idioms,
    unreachable_pub
)]
#![cfg_attr(
    not(any(feature = "process-mux", feature = "native-mux")),
    allow(unused_variables, unreachable_code, unused_imports, dead_code)
)]
// only enables the nightly `doc_cfg` feature when
// the `docsrs` configuration attribute is defined
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(not(unix))]
compile_error!("This crate can only be used on unix");

mod stdio;
pub use stdio::{ChildStderr, ChildStdin, ChildStdout, Stdio};

mod session;
pub use session::Session;

mod builder;
pub use builder::{ControlPersist, KnownHosts, SessionBuilder};

mod command;
pub use command::{OverSsh, OwningCommand};
/// Convenience [`OwningCommand`] alias when working with a session reference.
pub type Command<'s> = OwningCommand<&'s Session>;

mod escape;

mod child;
pub use child::Child;
/// Convenience [`Child`] alias when working with a session reference.
pub type RemoteChild<'a> = Child<&'a Session>;

mod error;
pub use error::Error;

#[cfg(feature = "process-mux")]
pub(crate) mod process_impl;

#[cfg(feature = "native-mux")]
pub(crate) mod native_mux_impl;

#[cfg(doc)]
/// Changelog for this crate.
pub mod changelog;

mod port_forwarding;
pub use port_forwarding::*;

/// Types to create and interact with the Remote Process
pub mod process {
    pub use super::{ChildStderr, ChildStdin, ChildStdout, Command, RemoteChild, Stdio};
}
