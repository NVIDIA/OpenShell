// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SFTP v3 adapter backed by a directory file descriptor.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::File as StdFile;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Component, Path, PathBuf};

use miette::{IntoDiagnostic as _, Result};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode,
};
use rustix::fs::{
    AtFlags, Dir, FileType, Gid, Mode, OFlags, RenameFlags, ResolveFlags, Timestamps, Uid, fchmod,
    fchown, fstat, futimens, mkdirat, openat, openat2, readlinkat, renameat_with, statat,
    symlinkat, unlinkat,
};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};

const MAX_HANDLES: usize = 256;
const MAX_PACKET_SIZE: u32 = 256 * 1024;
const MAX_READ_SIZE: usize = MAX_PACKET_SIZE as usize;
const MAX_DIRECTORY_ENTRIES: usize = 128;
const SAFE_MODE_MASK: u32 = 0o777;

struct SftpHandler {
    root: OwnedFd,
    root_path: PathBuf,
    files: HashMap<String, tokio::fs::File>,
    directories: HashMap<String, Dir>,
    done: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for SftpHandler {
    fn drop(&mut self) {
        if let Some(done) = self.done.take() {
            let _ = done.send(());
        }
    }
}

impl SftpHandler {
    fn new(root: &Path, done: tokio::sync::oneshot::Sender<()>) -> io::Result<Self> {
        let root_path = std::fs::canonicalize(root)?;
        let root = openat(
            rustix::fs::CWD,
            &root_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        Ok(Self {
            root,
            root_path,
            files: HashMap::new(),
            directories: HashMap::new(),
            done: Some(done),
        })
    }

    fn path(&self, path: &str) -> Result<PathBuf, StatusCode> {
        let supplied = Path::new(path);
        let supplied = if supplied.is_absolute() && supplied.starts_with(&self.root_path) {
            supplied
                .strip_prefix(&self.root_path)
                .map_err(|_| StatusCode::PermissionDenied)?
        } else {
            supplied
        };
        let mut relative = PathBuf::new();
        for component in supplied.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(value) => relative.push(value),
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(StatusCode::PermissionDenied);
                }
            }
        }
        if relative.as_os_str().is_empty() {
            relative.push(".");
        }
        Ok(relative)
    }

    fn parent(&self, path: &str) -> Result<(OwnedFd, OsString), StatusCode> {
        let path = self.path(path)?;
        if path == Path::new(".") {
            return Err(StatusCode::PermissionDenied);
        }
        let leaf = path
            .file_name()
            .ok_or(StatusCode::PermissionDenied)?
            .to_os_string();
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let fd = self.open_path(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok((fd, leaf))
    }

    fn open_path(&self, path: &Path, flags: OFlags, mode: Mode) -> Result<OwnedFd, StatusCode> {
        openat2(
            &self.root,
            path,
            flags,
            mode,
            ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(status_code)
    }

    fn reserve_handle(&self) -> Result<(), StatusCode> {
        if self.files.len() + self.directories.len() >= MAX_HANDLES {
            Err(StatusCode::Failure)
        } else {
            Ok(())
        }
    }

    fn handle() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }
}

fn status_code(error: rustix::io::Errno) -> StatusCode {
    match error {
        rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR => StatusCode::NoSuchFile,
        rustix::io::Errno::ACCESS
        | rustix::io::Errno::PERM
        | rustix::io::Errno::LOOP
        | rustix::io::Errno::XDEV => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

fn io_status(error: io::Error) -> StatusCode {
    error
        .raw_os_error()
        .map(rustix::io::Errno::from_raw_os_error)
        .map_or(StatusCode::Failure, status_code)
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: String::new(),
        language_tag: "en-US".to_string(),
    }
}

fn attributes(stat: &rustix::fs::Stat) -> FileAttributes {
    FileAttributes {
        size: stat.st_size.try_into().ok(),
        uid: Some(stat.st_uid),
        user: None,
        gid: Some(stat.st_gid),
        group: None,
        permissions: Some(stat.st_mode),
        atime: stat.st_atime.try_into().ok(),
        mtime: stat.st_mtime.try_into().ok(),
    }
}

fn open_flags(flags: OpenFlags) -> OFlags {
    let mut result = OFlags::CLOEXEC | OFlags::NONBLOCK;
    result |= if flags.contains(OpenFlags::READ) && flags.contains(OpenFlags::WRITE) {
        OFlags::RDWR
    } else if flags.contains(OpenFlags::WRITE) {
        OFlags::WRONLY
    } else {
        OFlags::RDONLY
    };
    if flags.contains(OpenFlags::APPEND) {
        result |= OFlags::APPEND;
    }
    if flags.contains(OpenFlags::CREATE) {
        result |= OFlags::CREATE;
    }
    if flags.contains(OpenFlags::TRUNCATE) {
        result |= OFlags::TRUNC;
    }
    if flags.contains(OpenFlags::EXCLUDE) {
        result |= OFlags::EXCL;
    }
    result
}

fn ensure_regular_file(fd: impl AsFd) -> Result<(), StatusCode> {
    let stat = fstat(fd).map_err(status_code)?;
    if FileType::from_raw_mode(stat.st_mode).is_file() {
        Ok(())
    } else {
        Err(StatusCode::OpUnsupported)
    }
}

fn ensure_setstat_target(fd: impl AsFd, changes_size: bool) -> Result<(), StatusCode> {
    let stat = fstat(fd).map_err(status_code)?;
    let file_type = FileType::from_raw_mode(stat.st_mode);
    if file_type.is_file() || (!changes_size && file_type.is_dir()) {
        Ok(())
    } else {
        Err(StatusCode::OpUnsupported)
    }
}

fn set_attributes(fd: impl AsFd, attrs: &FileAttributes) -> Result<(), StatusCode> {
    if attrs.uid.is_some() || attrs.gid.is_some() {
        fchown(
            &fd,
            attrs.uid.map(Uid::from_raw),
            attrs.gid.map(Gid::from_raw),
        )
        .map_err(status_code)?;
    }
    if let Some(mode) = attrs.permissions {
        fchmod(&fd, Mode::from_bits_truncate(mode & SAFE_MODE_MASK)).map_err(status_code)?;
    }
    if attrs.atime.is_some() || attrs.mtime.is_some() {
        let current = fstat(&fd).map_err(status_code)?;
        let times = Timestamps {
            last_access: rustix::fs::Timespec {
                tv_sec: attrs.atime.map_or(current.st_atime, i64::from),
                tv_nsec: 0,
            },
            last_modification: rustix::fs::Timespec {
                tv_sec: attrs.mtime.map_or(current.st_mtime, i64::from),
                tv_nsec: 0,
            },
        };
        futimens(fd, &times).map_err(status_code)?;
    }
    Ok(())
}

impl russh_sftp::server::Handler for SftpHandler {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        self.reserve_handle()?;
        if pflags.contains(OpenFlags::EXCLUDE) && !pflags.contains(OpenFlags::CREATE) {
            return Err(StatusCode::BadMessage);
        }
        let path = self.path(&filename)?;
        let flags = open_flags(pflags);
        let mode = if flags.contains(OFlags::CREATE) {
            Mode::from_bits_truncate(attrs.permissions.unwrap_or(0o666) & SAFE_MODE_MASK)
        } else {
            Mode::empty()
        };
        let fd = self.open_path(&path, flags, mode)?;
        ensure_regular_file(&fd)?;
        let handle = Self::handle();
        self.files
            .insert(handle.clone(), tokio::fs::File::from_std(StdFile::from(fd)));
        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        if self.files.remove(&handle).is_none() && self.directories.remove(&handle).is_none() {
            return Err(StatusCode::Failure);
        }
        Ok(ok(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let file = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        file.seek(io::SeekFrom::Start(offset))
            .await
            .map_err(io_status)?;
        let requested = usize::try_from(len)
            .map_err(|_| StatusCode::BadMessage)?
            .min(MAX_READ_SIZE);
        let mut data = vec![0; requested];
        let count = file.read(&mut data).await.map_err(io_status)?;
        if count == 0 {
            return Err(StatusCode::Eof);
        }
        data.truncate(count);
        Ok(Data { id, data })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let file = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        file.seek(io::SeekFrom::Start(offset))
            .await
            .map_err(io_status)?;
        file.write_all(&data).await.map_err(io_status)?;
        Ok(ok(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        if self.path(&path)? == Path::new(".") {
            let stat = fstat(&self.root).map_err(status_code)?;
            return Ok(Attrs {
                id,
                attrs: attributes(&stat),
            });
        }
        let (parent, leaf) = self.parent(&path)?;
        let stat = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(status_code)?;
        Ok(Attrs {
            id,
            attrs: attributes(&stat),
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let path = self.path(&path)?;
        let fd = self.open_path(&path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())?;
        let stat = fstat(fd).map_err(status_code)?;
        Ok(Attrs {
            id,
            attrs: attributes(&stat),
        })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let file = self.files.get(&handle).ok_or(StatusCode::Failure)?;
        let stat = fstat(file).map_err(status_code)?;
        Ok(Attrs {
            id,
            attrs: attributes(&stat),
        })
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let file = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        if let Some(size) = attrs.size {
            file.set_len(size).await.map_err(io_status)?;
        }
        set_attributes(&*file, &attrs)?;
        Ok(ok(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        self.reserve_handle()?;
        let path = self.path(&path)?;
        let fd = self.open_path(
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let directory = Dir::new(fd).map_err(status_code)?;
        let handle = Self::handle();
        self.directories.insert(handle.clone(), directory);
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let directory = self
            .directories
            .get_mut(&handle)
            .ok_or(StatusCode::Failure)?;
        let mut files = Vec::with_capacity(MAX_DIRECTORY_ENTRIES);
        while files.len() < MAX_DIRECTORY_ENTRIES {
            let Some(entry) = directory.next() else {
                break;
            };
            let entry = entry.map_err(status_code)?;
            let name = entry.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            let stat = statat(
                directory.fd().map_err(status_code)?,
                name,
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(status_code)?;
            files.push(File::new(name.to_string_lossy(), attributes(&stat)));
        }
        if files.is_empty() {
            Err(StatusCode::Eof)
        } else {
            Ok(Name { id, files })
        }
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        let (parent, leaf) = self.parent(&filename)?;
        unlinkat(parent, leaf, AtFlags::empty()).map_err(status_code)?;
        Ok(ok(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let (parent, leaf) = self.parent(&path)?;
        let mode = Mode::from_bits_truncate(attrs.permissions.unwrap_or(0o777) & SAFE_MODE_MASK);
        mkdirat(parent, leaf, mode).map_err(status_code)?;
        Ok(ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        let (parent, leaf) = self.parent(&path)?;
        unlinkat(parent, leaf, AtFlags::REMOVEDIR).map_err(status_code)?;
        Ok(ok(id))
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let path = self.path(&path)?;
        if let Err(error) = self.open_path(&path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty()) {
            if error != StatusCode::NoSuchFile {
                return Err(error);
            }
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            self.open_path(
                parent,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
        }
        let display = if path == Path::new(".") {
            "/".to_string()
        } else {
            format!("/{}", path.display())
        };
        Ok(Name {
            id,
            files: vec![File::dummy(display)],
        })
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        let (old_parent, old_leaf) = self.parent(&oldpath)?;
        let (new_parent, new_leaf) = self.parent(&newpath)?;
        renameat_with(
            old_parent,
            old_leaf,
            new_parent,
            new_leaf,
            RenameFlags::NOREPLACE,
        )
        .map_err(status_code)?;
        Ok(ok(id))
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let (parent, leaf) = self.parent(&path)?;
        let target = readlinkat(parent, leaf, Vec::new()).map_err(status_code)?;
        let target = OsString::from_vec(target.into_bytes());
        Ok(Name {
            id,
            files: vec![File::dummy(target.to_string_lossy())],
        })
    }

    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, Self::Error> {
        let (parent, leaf) = self.parent(&linkpath)?;
        symlinkat(OsStr::new(&targetpath), parent, leaf).map_err(status_code)?;
        Ok(ok(id))
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let path = self.path(&path)?;
        let flags = if attrs.size.is_some() {
            OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NONBLOCK
        } else {
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK
        };
        let fd = self.open_path(&path, flags, Mode::empty())?;
        ensure_setstat_target(&fd, attrs.size.is_some())?;
        if let Some(size) = attrs.size {
            StdFile::from(fd.try_clone().map_err(io_status)?)
                .set_len(size)
                .map_err(io_status)?;
        }
        set_attributes(&fd, &attrs)?;
        Ok(ok(id))
    }
}

pub(crate) async fn serve<S>(stream: S, root: PathBuf) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let handler = SftpHandler::new(&root, done_tx).into_diagnostic()?;
    russh_sftp::server::run_with_config(
        stream,
        handler,
        russh_sftp::server::Config {
            max_client_packet_len: MAX_PACKET_SIZE,
        },
    )
    .await;
    let _ = done_rx.await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh_sftp::client::SftpSession;
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::Duration;

    async fn client(root: &Path) -> SftpSession {
        let (done_tx, _done_rx) = tokio::sync::oneshot::channel();
        let handler = SftpHandler::new(root, done_tx).unwrap();
        let (client_stream, server_stream) = tokio::io::duplex(1024 * 1024);
        russh_sftp::server::run_with_config(
            server_stream,
            handler,
            russh_sftp::server::Config {
                max_client_packet_len: MAX_PACKET_SIZE,
            },
        )
        .await;
        SftpSession::new(client_stream).await.unwrap()
    }

    #[tokio::test]
    async fn adapter_round_trips_files() {
        let root = tempfile::tempdir().unwrap();
        let client = client(root.path()).await;
        let mut file = client
            .open_with_flags(
                "hello.txt",
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE | OpenFlags::READ,
            )
            .await
            .unwrap();
        file.write_all(b"hello from sftp").await.unwrap();
        file.rewind().await.unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).await.unwrap();
        assert_eq!(contents, "hello from sftp");
        drop(file);

        let mut file = client.open("hello.txt").await.unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).await.unwrap();
        assert_eq!(contents, "hello from sftp");
    }

    #[tokio::test]
    async fn adapter_creates_entries_at_virtual_root() {
        let root = tempfile::tempdir().unwrap();
        let client = client(root.path()).await;

        client.create_dir("incoming").await.unwrap();

        assert!(root.path().join("incoming").is_dir());
    }

    #[tokio::test]
    async fn realpath_accepts_a_missing_leaf_under_an_existing_directory() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("incoming")).unwrap();
        let client = client(root.path()).await;

        let canonical = client.canonicalize("incoming/tree").await.unwrap();

        assert_eq!(canonical, PathBuf::from("/incoming/tree"));
    }

    #[tokio::test]
    async fn adapter_rejects_parent_and_symlink_escapes() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(parent.path().join("outside"), b"secret").unwrap();
        std::os::unix::fs::symlink("../outside", root.join("escape")).unwrap();
        let client = client(&root).await;

        assert!(client.metadata("../outside").await.is_err());
        assert!(client.metadata("escape").await.is_err());
        assert!(client.open("escape").await.is_err());
    }

    #[tokio::test]
    async fn standard_rename_preserves_an_existing_destination() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("source"), b"source contents").unwrap();
        std::fs::write(root.path().join("destination"), b"destination contents").unwrap();
        let client = client(root.path()).await;

        assert!(client.rename("source", "destination").await.is_err());
        assert_eq!(
            std::fs::read(root.path().join("source")).unwrap(),
            b"source contents"
        );
        assert_eq!(
            std::fs::read(root.path().join("destination")).unwrap(),
            b"destination contents"
        );

        client.rename("source", "renamed").await.unwrap();
        assert_eq!(
            std::fs::read(root.path().join("renamed")).unwrap(),
            b"source contents"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fifo_open_fails_without_blocking() {
        let root = tempfile::tempdir().unwrap();
        let fifo = root.path().join("fifo");
        rustix::fs::mkfifoat(rustix::fs::CWD, &fifo, Mode::from_bits_truncate(0o600)).unwrap();
        let client = client(root.path()).await;

        let result = tokio::time::timeout(Duration::from_secs(1), client.open("fifo")).await;
        if result.is_err() {
            let _ = openat(
                rustix::fs::CWD,
                &fifo,
                OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            );
        }

        assert!(matches!(result, Ok(Err(_))));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fifo_setstat_fails_without_blocking() {
        let root = tempfile::tempdir().unwrap();
        let fifo = root.path().join("fifo");
        rustix::fs::mkfifoat(rustix::fs::CWD, &fifo, Mode::from_bits_truncate(0o600)).unwrap();
        let client = client(root.path()).await;

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            client.set_metadata("fifo", FileAttributes::default()),
        )
        .await;
        if result.is_err() {
            let _ = openat(
                rustix::fs::CWD,
                &fifo,
                OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            );
        }

        assert!(matches!(result, Ok(Err(_))));
    }

    #[tokio::test]
    async fn setstat_preserves_directory_metadata_support() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("directory")).unwrap();
        let client = client(root.path()).await;
        let attrs = FileAttributes {
            permissions: Some(0o700),
            ..FileAttributes::default()
        };

        client.set_metadata("directory", attrs).await.unwrap();

        let mode = std::fs::metadata(root.path().join("directory"))
            .unwrap()
            .permissions()
            .mode()
            & SAFE_MODE_MASK;
        assert_eq!(mode, 0o700);
    }
}
