#[allow(unused_imports)]
use crate::*;

/// TODO: RENAME THIS INTO THE NEXT VERSION BEFORE RELEASE
#[doc(hidden)]
pub mod unreleased {}

/// # Changed
/// - Remove dep tokio-pipe (#156)
/// - Remove deprecated functions (#156)
/// - Replace `From<tokio::proces::Child*>`
///   with `TryFrom<tokio::proces::Child*>`, since the converison is falliable (#156)
/// - Remove `IntoRawFd` for `Child*` since the conversion is falliable (#156)
pub mod v0_11_0 {}

/// ## Changed
///  - Add missing feature doc for `Session::new*`
pub mod v0_10_5 {}

/// ## Changed
/// - Added new fn [`Session::control_persist`] to set the `ControlPersist` option of
///   the master ssh connection.
pub mod v0_10_4 {}

/// ## Changed
/// - Removed dependency on MPL licensed dirs-sys in favor of local implementation
pub mod v0_10_3 {}

/// ## Changed
///  - Use `str::rfind` to locate the `@` in connection string in case the username contains `@`
pub mod v0_10_2 {}

/// ## Added
///  - Add new fns [`Session::arc_command`], [`Session::arc_raw_command`],
///    [`Session::to_command`], and [`Session::to_raw_command`] to support
///    session-owning commands
///  - Add generic [`crate::OwningCommand`], to support session-owning
///    commands.
///  - Add [`crate::child::Child`] as a generic version of [`RemoteChild`]
///    to support session-owning commands
/// ## Changed
///  - Change [`RemoteChild`] to be an alias to [`crate::child::Child`]
///    owning a session references.
///  - Change [`Command`] to be an alias to [`OwningCommand`] owning a
///    session reference.
///  - Change [`OverSsh::over_ssh`] to be generic and support owned
///    sessions.
/// ## Removed
#[doc(hidden)]
pub mod v0_10_1 {}

/// ## Added
///  - [`Session::new_process_mux`]
///  - [`Session::new_native_mux`]
///  - [`SessionBuilder::get_user`]
///  - [`SessionBuilder::get_port`]
///  - [`SessionBuilder::resolve`]
///  - [`SessionBuilder::launch_master`]
///  - [`SessionBuilder::clean_history_control_directory`]
///  - [`OverSsh`] for converting [`std::process::Command`],
///    [`tokio::process::Command`] or other custom types to
///    [`Command`].
/// ## Changed
///  - [`Socket::TcpSocket`] now contains `host: Cow<'_, str>` and `port: u16`
///    instead of an already resolved `SocketAddr`.
///    Since the socket could be opened on remote host, which might has
///    different dns configuration, it's better to delay resolution and perform
///    it on remote instead.
///  - [`Socket::new`] now takes `host: Cow<'_, str>` and `port: u16` for the
///    same reason as above.
pub mod v0_10_0 {}

/// ## Added
///  - Add new fn `SessionBuilder::ssh_auth_sock`
pub mod v0_9_9 {}

/// ## Added
///  - `impl From<std::os::unix::io::OwnedFd> for Stdio`
///  -  Add new fn `Stdio::from_raw_fd_owned`
/// ## Changed
///  - Mark `FromRawFd` impl for `Stdio` as deprecated
///  - Mark `From<tokio_pipe::PipeRead>` for `Stdio` as deprecated
///  - Mark `From<tokio_pipe::PipeWrite>` for `Stdio` as deprecated
/// ## Fixed
///  - [`wait_with_output` + `native-mux` cuts off stdout output](https://github.com/openssh-rust/openssh/issues/103)
pub mod v0_9_8 {}

/// ## Changed
///  - Bumped minimum version of `openssh-mux-client` to 0.15.1
pub mod v0_9_7 {}

/// ## Added
///  - [`SessionBuilder::jump_hosts`]
pub mod v0_9_6 {}

/// ## Added
///  - `From<SocketAddr> for Socket<'static>`
///  - `From<Cow<'a, Path>> for Socket<'a>`
///  - `From<&'a Path> for Socket<'a>`
///  - `From<PathBuf> for Socket<'static>`
///  - `From<Box<Path>> for Socket<'static>`
///  - `From<(IpAddr, u16)> for Socket<'static>`
///  - `From<(Ipv4Addr, u16)> for Socket<'static>`
///  - `From<(Ipv6Addr, u16)> for Socket<'static>`
///
/// ## Changed
///  - [`Session::request_port_forward`] now takes `impl Into<...>`
///    to make it much easier to use.
///  - [`Socket::new`] now returns `Socket<'static>`
pub mod v0_9_5 {}

/// ## Added
///  - [`Session::resume`]
///  - [`Session::resume_mux`]
///  - [`Session::detach`]
pub mod v0_9_3 {}

/// ## Changed
///  - Removed `impl From<OwnedFd> for Stdio` as it was an unintentional part of the public API.
///    This is technically a breaking change, but should in practice affect no-one.
pub mod v0_9_2 {}

/// ## Added
///  - [`Session::subsystem`]
pub mod v0_9_1 {}

/// No changes since 0.9.0-rc4.
pub mod v0_9_0 {}

/// ## Fixed
///  - Remove accidentally exposed `TryFrom<tokio::process::ChildStdin`
///    implementation for [`ChildStdin`].
///  - Remove accidentally exposed `TryFrom<tokio_pipe::PipeWrite>`
///    implementation for [`ChildStdin`].
///  - Remove accidentally exposed `TryFrom<tokio::process::ChildStdout>`
///    implementation for [`ChildStdout`].
///  - Remove accidentally exposed `TryFrom<tokio_pipe::PipeRead>`
///    implementation for [`ChildStdout`].
///  - Remove accidentally exposed `TryFrom<tokio::process::ChildStderr>`
///    implementation for [`ChildStderr`].
///  - Remove accidentally exposed `TryFrom<tokio_pipe::PipeRead>`
///    implementation for [`ChildStderr`].
///
/// ## Changed
///  - Make [`Session::check`] available only on unix.
///  - Make [`Socket::UnixSocket`] available only on unix.
///  - Make [`SessionBuilder::control_directory`] available only on unix.
pub mod v0_9_0_rc4 {}

/// ## Fixed
///  - Fixed changelog entry for rc2 not being visible
pub mod v0_9_0_rc3 {}

/// ## Fixed
///  - Fixed crate level doc
///
/// ## Added
///  - Added changelog
///  - Associated function [`SessionBuilder::compression`]
///  - Associated function [`SessionBuilder::user_known_hosts_file`]
///  - Associated function [`Session::control_socket`] for non-Windows platform.
///
/// ## Changed
///  - Make [`ChildStdin`] an opaque type.
///  - Make [`ChildStdout`] an opaque type.
///  - Make [`ChildStderr`] an opaque type.
///
/// ## Removed
///  - Type `Sftp`.
///  - Type `Mode`.
///  - Type `RemoteFile`.
///  - Associated function `Session::sftp`.
pub mod v0_9_0_rc2 {}

/// ## Added
///  - Feature flag `native-mux`, an alternative backend that communicates
///    with the ssh multiplex server directly through control socket as opposed
///    `process-mux` implementation that spawns a process to communicate with
///    the ssh multiplex server.
///
///    Compared to `process-mux`, `native-mux` provides more robust error
///    reporting, better performance and reduced memory usage.
///
///    `process-mux` checks the exit status of `ssh` for indication of error,
///    then parse the output of it and the output of the ssh multiplex master
///    to return an error.
///
///    This method is obviously not so robust as `native-mux`, which directly
///    communicates with ssh multiplex master through its [multiplex protocol].
///
///  - Feature flag `process-mux` (enabled by default) to disable the old
///    backend if desired.
///  - API [`Session::connect_mux`] for the new `native-mux` backend,
///    which is used to create a [`Session`] backed by `native-mux`
///    implementation.
///  - API [`SessionBuilder::connect_mux`] for the new `native-mux` backend,
///    which is used to create a [`Session`] backed by `native-mux`
///    implementation.
///  - [`Session::request_port_forward`] for local/remote forwarding
///    of tcp or unix stream sockets, along with [`ForwardType`] and
///    [`Socket`], which is used to setup port forwarding.
///  - A new module [`process`] is added to provide interfaces more similar to
///    [`std::process`].
///  - New variants are added to [`Error`].
///
/// ## Changed
///  - A new type [`Stdio`] is used for setting stdin/stdout/stderr.
///  - [`ChildStdin`], [`ChildStdout`] and [`ChildStderr`] are now aliases
///    for [`tokio_pipe::PipeRead`] and [`tokio_pipe::PipeWrite`].
///  - [`Command::spawn`] and [`Command::status`] now conforms to
///    [`std::process::Command`] and [`tokio::process::Command`], in which
///    stdin, stdout and stderr are inherit by default.
///  - [`Command::spawn`] is now an `async` method.
///  - [`RemoteChild::wait`] now takes `self` by value.
///  - [`Error`] is now marked `#[non_exhaustive]`.
///
/// [multiplex protocol]: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.mux
pub mod v0_9_0_rc_1 {}
