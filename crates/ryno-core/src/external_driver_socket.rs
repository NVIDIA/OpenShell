// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Public Unix-socket transport helpers for out-of-process drivers.

use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::net::{UnixListener, UnixStream};
use tokio_stream::Stream;

/// Prepare and bind a private Unix socket owned by the current effective UID.
pub fn bind_private(path: &Path) -> Result<UnixListener, String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("driver socket path '{}' has no parent", path.display()))?;
    let expected_uid = rustix::process::geteuid().as_raw();
    std::fs::create_dir_all(parent)
        .map_err(|err| format!("create socket directory {}: {err}", parent.display()))?;
    let parent_metadata = std::fs::symlink_metadata(parent)
        .map_err(|err| format!("stat socket directory {}: {err}", parent.display()))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.file_type().is_dir() {
        return Err(format!(
            "driver socket parent '{}' must be a directory, not a symlink",
            parent.display()
        ));
    }
    if parent_metadata.uid() != expected_uid {
        return Err(format!(
            "driver socket parent '{}' is owned by uid {}, expected {}",
            parent.display(),
            parent_metadata.uid(),
            expected_uid
        ));
    }
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
        .map_err(|err| format!("chmod socket directory {}: {err}", parent.display()))?;

    match std::fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == expected_uid =>
        {
            std::fs::remove_file(path)
                .map_err(|err| format!("remove stale socket {}: {err}", path.display()))?;
        }
        Ok(_) => {
            return Err(format!(
                "driver socket path '{}' exists but is not an owned Unix socket",
                path.display()
            ));
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(format!("stat driver socket {}: {err}", path.display())),
    }

    let listener = UnixListener::bind(path)
        .map_err(|err| format!("bind driver socket {}: {err}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("chmod driver socket {}: {err}", path.display()))?;
    Ok(listener)
}

/// Remove a socket created by [`bind_private`].
pub struct SocketCleanup(PathBuf);

impl SocketCleanup {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self(path)
    }
}

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Incoming UDS connections restricted to the driver's effective UID.
pub struct SameUidUnixIncoming {
    listener: UnixListener,
    expected_uid: u32,
}

impl SameUidUnixIncoming {
    #[must_use]
    pub fn new(listener: UnixListener) -> Self {
        Self {
            listener,
            expected_uid: rustix::process::geteuid().as_raw(),
        }
    }
}

impl Stream for SameUidUnixIncoming {
    type Item = io::Result<UnixStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match this.listener.poll_accept(cx) {
                Poll::Ready(Ok((stream, _))) => match stream.peer_cred() {
                    Ok(credentials) if credentials.uid() == this.expected_uid => {
                        return Poll::Ready(Some(Ok(stream)));
                    }
                    Ok(credentials) => tracing::warn!(
                        peer_uid = credentials.uid(),
                        expected_uid = this.expected_uid,
                        "rejected external driver socket client"
                    ),
                    Err(err) => {
                        tracing::warn!(error = %err, "failed to authenticate driver socket client");
                    }
                },
                Poll::Ready(Err(err)) => return Poll::Ready(Some(Err(err))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use tokio_stream::StreamExt;

    use super::*;

    #[tokio::test]
    async fn bind_private_creates_private_socket_and_cleanup_removes_it() {
        let temp_dir = tempfile::tempdir().expect("create temporary directory");
        let socket_dir = temp_dir.path().join("driver");
        let socket_path = socket_dir.join("compute.sock");

        let listener = bind_private(&socket_path).expect("bind private socket");

        let directory_mode = std::fs::metadata(&socket_dir)
            .expect("stat socket directory")
            .permissions()
            .mode()
            & 0o777;
        let socket_mode = std::fs::metadata(&socket_path)
            .expect("stat socket")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory_mode, 0o700);
        assert_eq!(socket_mode, 0o600);

        drop(listener);
        let cleanup = SocketCleanup::new(socket_path.clone());
        drop(cleanup);
        assert!(!socket_path.exists());
    }

    #[test]
    fn bind_private_rejects_symlinked_parent() {
        let temp_dir = tempfile::tempdir().expect("create temporary directory");
        let actual_dir = temp_dir.path().join("actual");
        let linked_dir = temp_dir.path().join("linked");
        std::fs::create_dir(&actual_dir).expect("create socket directory");
        symlink(&actual_dir, &linked_dir).expect("create directory symlink");

        let err = bind_private(&linked_dir.join("compute.sock"))
            .expect_err("symlinked socket parent must be rejected");

        assert!(err.contains("must be a directory, not a symlink"));
    }

    #[test]
    fn bind_private_rejects_existing_non_socket() {
        let temp_dir = tempfile::tempdir().expect("create temporary directory");
        let socket_path = temp_dir.path().join("compute.sock");
        std::fs::write(&socket_path, b"not a socket").expect("create conflicting file");

        let err = bind_private(&socket_path).expect_err("non-socket path must be rejected");

        assert!(err.contains("is not an owned Unix socket"));
        assert_eq!(
            std::fs::read(&socket_path).expect("read conflicting file"),
            b"not a socket"
        );
    }

    #[tokio::test]
    async fn bind_private_replaces_existing_owned_socket() {
        let temp_dir = tempfile::tempdir().expect("create temporary directory");
        let socket_path = temp_dir.path().join("compute.sock");
        let stale_listener =
            std::os::unix::net::UnixListener::bind(&socket_path).expect("bind stale Unix socket");
        drop(stale_listener);

        let listener = bind_private(&socket_path).expect("replace owned Unix socket");

        assert!(
            std::fs::symlink_metadata(&socket_path)
                .expect("stat replacement socket")
                .file_type()
                .is_socket()
        );
        drop(listener);
    }

    #[tokio::test]
    async fn same_uid_incoming_accepts_current_user() {
        let temp_dir = tempfile::tempdir().expect("create temporary directory");
        let socket_path = temp_dir.path().join("compute.sock");
        let listener = bind_private(&socket_path).expect("bind private socket");
        let mut incoming = SameUidUnixIncoming::new(listener);

        let client = UnixStream::connect(&socket_path)
            .await
            .expect("connect to private socket");
        let accepted = incoming
            .next()
            .await
            .expect("incoming stream ended")
            .expect("accept same-UID client");

        assert_eq!(
            accepted.peer_cred().expect("read client credentials").uid(),
            rustix::process::geteuid().as_raw()
        );
        drop(client);
    }
}
