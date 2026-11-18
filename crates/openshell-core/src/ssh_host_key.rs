// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SSH host-key verification for sandbox connections.
//!
//! The fingerprint the gateway publishes is the authority. A per-sandbox
//! `known_hosts` file is a cache that must hash to that fingerprint, and `ssh`
//! enforces it with `StrictHostKeyChecking=yes`. This module owns the
//! fingerprint format, the pin location and file format, the `ssh` options,
//! the `ssh-proxy` flags, and the scan of the server's key exchange reply.

use std::fmt;
use std::fs;
use std::io::{self, Write as _};
use std::path::{MAIN_SEPARATOR, Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};

use crate::forward::shell_escape;
use crate::proto::CreateSshSessionResponse;

const FINGERPRINT_PREFIX: &str = "SHA256:";
const UNVERIFIED: &str = "unverified";
const ALLOW_UNVERIFIED_ENV: &str = "OPENSHELL_SSH_ALLOW_UNVERIFIED_HOST_KEY";
const HOST_KEY_ALGORITHM: &str = "ssh-ed25519";
const PIN_HEADER: &str =
    "# Managed by OpenShell. Rewritten from the gateway-published fingerprint; do not edit.\n";
/// `string "ssh-ed25519"`, then the length prefix of the 32-byte key.
const ED25519_BLOB_PREFIX: &[u8] = b"\0\0\0\x0bssh-ed25519\0\0\0\x20";
const ED25519_KEY_LEN: usize = 32;
const MAX_BANNER_LINE_LEN: usize = 8192;
/// The padding length byte plus one payload byte, up to the largest packet
/// `ssh` accepts.
const PACKET_LENGTHS: std::ops::RangeInclusive<usize> = 2..=262_144;
const MSG_KEXINIT: u8 = 20;
const KEXINIT_COOKIE_LEN: usize = 16;
const KEXINIT_NAME_LISTS: usize = 10;
const MSG_NEWKEYS: u8 = 21;
/// The key exchange reply of every method but group exchange, where it is the
/// group instead.
const MSG_KEX_REPLY: u8 = 31;
const MSG_KEX_GEX_REPLY: u8 = 33;

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// SHA-256 of an SSH public key blob. Text form: `SHA256:` followed by 43
/// characters of unpadded standard base64.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HostKeyFingerprint([u8; 32]);

impl FromStr for HostKeyFingerprint {
    type Err = HostKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.strip_prefix(FINGERPRINT_PREFIX)
            .and_then(|encoded| STANDARD_NO_PAD.decode(encoded).ok())
            .and_then(|digest| <[u8; 32]>::try_from(digest).ok())
            .map(Self)
            .ok_or(HostKeyError::BadFingerprint)
    }
}

impl fmt::Display for HostKeyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{FINGERPRINT_PREFIX}{}", STANDARD_NO_PAD.encode(self.0))
    }
}

impl HostKeyFingerprint {
    /// Hashes the blob exactly as it appears in the server's key exchange
    /// reply and in a `known_hosts` line.
    pub fn of_blob(blob: &[u8]) -> Result<Self, HostKeyError> {
        openshell_crypto::sha256(blob)
            .map(Self)
            .map_err(|err| HostKeyError::Crypto(err.to_string()))
    }
}

/// What `ssh-proxy` must see before it forwards the server's key exchange
/// reply. Text form: a fingerprint, or `unverified`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HostKeyExpectation {
    Fingerprint(HostKeyFingerprint),
    /// Only when the gateway published nothing and the user opted in.
    AcceptAny,
}

impl FromStr for HostKeyExpectation {
    type Err = HostKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == UNVERIFIED {
            Ok(Self::AcceptAny)
        } else {
            s.parse().map(Self::Fingerprint)
        }
    }
}

impl fmt::Display for HostKeyExpectation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fingerprint(fingerprint) => fingerprint.fmt(f),
            Self::AcceptAny => f.write_str(UNVERIFIED),
        }
    }
}

impl HostKeyExpectation {
    /// Interprets the fingerprint field of a gateway response.
    /// `allow_unverified` decides only what an empty field means.
    pub fn from_published(
        published: &str,
        sandbox: &str,
        allow_unverified: bool,
    ) -> Result<Self, HostKeyError> {
        if !published.is_empty() {
            published.parse().map(Self::Fingerprint)
        } else if allow_unverified {
            Ok(Self::AcceptAny)
        } else {
            Err(HostKeyError::Unpublished {
                sandbox: sandbox.to_string(),
            })
        }
    }
}

/// Whether a sandbox with no published fingerprint may be reached unverified:
/// only when `OPENSHELL_SSH_ALLOW_UNVERIFIED_HOST_KEY` is `1`.
pub fn allow_unverified_host_key() -> bool {
    std::env::var(ALLOW_UNVERIFIED_ENV).is_ok_and(|value| value == "1")
}

#[derive(Debug, thiserror::Error)]
pub enum HostKeyError {
    #[error(
        "sandbox '{sandbox}' has no published SSH host key, so its SSH server cannot be verified.\n  \
         If the gateway predates sandbox SSH identities, upgrade it. Otherwise stop and start the sandbox so the gateway assigns a key.\n  \
         To connect without verification, set {ALLOW_UNVERIFIED_ENV}=1."
    )]
    Unpublished { sandbox: String },
    #[error("SSH host key fingerprint is not 'SHA256:' followed by 43 unpadded base64 characters")]
    BadFingerprint,
    #[error(
        "SSH host key mismatch for sandbox '{sandbox}' (workspace '{workspace}')\n  \
         gateway published: {expected}\n  \
         server presented:  {presented}\n\
         The SSH server reached through the gateway is not this sandbox's. The handshake was not forwarded.\n\
         Do not connect. Compare the published value with `openshell --workspace {} sandbox get {} --output json`, then stop and start the sandbox.\n\
         If the mismatch persists, contact the gateway operator.",
        shell_escape(.workspace),
        shell_escape(.sandbox)
    )]
    Mismatch {
        sandbox: String,
        workspace: String,
        expected: HostKeyFingerprint,
        presented: HostKeyFingerprint,
    },
    #[error("malformed SSH stream from the sandbox: {0}")]
    Malformed(&'static str),
    #[error(
        "SSH known-hosts path '{}' cannot be used: it must be absolute, be built from plain gateway, \
         sandbox and workspace names, and contain no '%', '\"', '\\', \"${{\" or newline",
        .0.display()
    )]
    UnusablePath(PathBuf),
    #[error("SSH known-hosts file: {0}")]
    Io(#[from] io::Error),
    #[error("SSH host key fingerprint could not be computed: {0}")]
    Crypto(String),
}

/// The sandbox an SSH connection is for. Keys the pin file.
#[derive(Clone, Copy, Debug)]
pub struct SandboxSshTarget<'a> {
    pub gateway: &'a str,
    pub workspace: &'a str,
    pub sandbox: &'a str,
}

/// `openshell-<sandbox>.<workspace>`: the `Host` alias of a generated SSH
/// config block, the `HostKeyAlias` of every connection, and the host field of
/// the pin line.
pub fn host_key_alias(sandbox: &str, workspace: &str) -> String {
    format!("openshell-{sandbox}.{workspace}")
}

/// One `known_hosts` file holding at most one key line for one alias.
#[derive(Debug)]
pub struct KnownHostsPin {
    path: PathBuf,
    sandbox: String,
    workspace: String,
}

impl KnownHostsPin {
    /// `<openshell config dir>/known_hosts/<gateway>/<alias>`, with the gateway
    /// name flattened to one directory name.
    pub fn for_target(target: &SandboxSshTarget<'_>) -> Result<Self, HostKeyError> {
        let config_dir = crate::paths::openshell_config_dir()
            .map_err(|err| io::Error::other(err.to_string()))?;
        Self::under(&std::path::absolute(config_dir)?, target)
    }

    /// The `ssh-proxy` side: the path the `ssh` invocation or config block
    /// handed over.
    pub fn at(path: PathBuf, sandbox: &str, workspace: &str) -> Result<Self, HostKeyError> {
        // `ssh` expands `%` tokens and `${VAR}` in both UserKnownHostsFile and
        // ProxyCommand, a quote or newline would end the value early, and a
        // backslash escapes the character after it. Where the backslash
        // separates path components, rejecting it would reject every path.
        let expands_or_breaks = |text: &str| {
            text.contains(['%', '"', '\n'])
                || text.contains("${")
                || (MAIN_SEPARATOR != '\\' && text.contains('\\'))
        };
        // A relative path would let `ssh` and `ssh-proxy` resolve different
        // files, and would make the working directory the pin directory.
        let usable = path.is_absolute()
            && path.file_name().is_some()
            && path.to_str().is_some_and(|text| !expands_or_breaks(text));
        if usable {
            Ok(Self {
                path,
                sandbox: sandbox.to_string(),
                workspace: workspace.to_string(),
            })
        } else {
            Err(HostKeyError::UnusablePath(path))
        }
    }

    fn under(config_dir: &Path, target: &SandboxSshTarget<'_>) -> Result<Self, HostKeyError> {
        let alias = host_key_alias(target.sandbox, target.workspace);
        // A gateway reached by its endpoint alone is named by its URL.
        let gateway = target.gateway.replace(
            |ch: char| !ch.is_ascii_alphanumeric() && !matches!(ch, '.' | '-' | '_'),
            "_",
        );
        let path = config_dir.join("known_hosts").join(&gateway).join(&alias);
        let is_one_component = |name: &str| Path::new(name).file_name() == Some(name.as_ref());
        if !is_one_component(&gateway) || !is_one_component(&alias) {
            return Err(HostKeyError::UnusablePath(path));
        }
        Self::at(path, target.sandbox, target.workspace)
    }

    fn alias(&self) -> String {
        host_key_alias(&self.sandbox, &self.workspace)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The options of every sandbox SSH connection that decide which host key
    /// it trusts, in the order they are passed. Rendered as `-o key=value` on
    /// a command line and as `key value` lines in a config block.
    pub fn ssh_options(&self) -> Vec<(&'static str, String)> {
        vec![
            ("StrictHostKeyChecking", "yes".to_string()),
            // Quoted, so that no `ssh` release splits the path at whitespace,
            // `=` or an apostrophe.
            ("UserKnownHostsFile", format!("\"{}\"", self.path.display())),
            ("GlobalKnownHostsFile", "/dev/null".to_string()),
            ("HostKeyAlias", self.alias()),
            ("HostKeyAlgorithms", HOST_KEY_ALGORITHM.to_string()),
            ("VerifyHostKeyDNS", "no".to_string()),
            ("UpdateHostKeys", "no".to_string()),
        ]
    }

    /// Rewrites the file header-only when it holds anything other than one key
    /// hashing to `fingerprint`. With no fingerprint, no key is kept.
    fn forget_unless(&self, fingerprint: Option<&HostKeyFingerprint>) -> io::Result<()> {
        // Decided from one read: a second read could see the key another
        // connection stored in between, and the rewrite would erase it.
        let trusts_nothing_else = self.read()?.is_some_and(|content| {
            content == PIN_HEADER.as_bytes()
                || self
                    .key_blob(&content)
                    .zip(fingerprint)
                    .is_some_and(|(blob, fingerprint)| {
                        HostKeyFingerprint::of_blob(&blob).is_ok_and(|kept| kept == *fingerprint)
                    })
        });
        if trusts_nothing_else {
            Ok(())
        } else {
            self.replace(PIN_HEADER)
        }
    }

    /// No-op when the content is already identical; otherwise a temp file
    /// (0600) in the same directory, then a rename.
    fn store(&self, blob: &[u8]) -> io::Result<()> {
        let content = format!("{}{}\n", self.key_line_prefix(), STANDARD.encode(blob));
        if self.read()?.is_some_and(|kept| kept == content.as_bytes()) {
            return Ok(());
        }
        self.replace(&content)
    }

    fn key_line_prefix(&self) -> String {
        format!("{PIN_HEADER}{} {HOST_KEY_ALGORITHM} ", self.alias())
    }

    /// The key blob, when `content` is exactly what [`Self::store`] writes.
    fn key_blob(&self, content: &[u8]) -> Option<Vec<u8>> {
        content
            .strip_prefix(self.key_line_prefix().as_bytes())
            .and_then(|rest| rest.strip_suffix(b"\n"))
            .and_then(|encoded| STANDARD.decode(encoded).ok())
    }

    fn read(&self) -> io::Result<Option<Vec<u8>>> {
        match fs::read(&self.path) {
            Ok(content) => Ok(Some(content)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(self.with_path(&err)),
        }
    }

    fn replace(&self, content: &str) -> io::Result<()> {
        self.write_then_rename(content)
            .map_err(|err| self.with_path(&err))
    }

    fn write_then_rename(&self, content: &str) -> io::Result<()> {
        let dir = self.path.parent().ok_or(io::ErrorKind::InvalidInput)?;
        create_owner_only_dir(dir)?;
        // Unique among the writers of this process. `create_new` refuses a
        // file or link someone else left there.
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp_path = dir.join(format!(".{}.{sequence}.tmp", std::process::id()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let replaced = options
            .open(&temp_path)
            .and_then(|mut file| file.write_all(content.as_bytes()))
            .and_then(|()| fs::rename(&temp_path, &self.path));
        if replaced.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        replaced
    }

    fn with_path(&self, err: &io::Error) -> io::Error {
        io::Error::new(err.kind(), format!("{}: {err}", self.path.display()))
    }
}

fn create_owner_only_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// The host-key decision for one SSH connection.
#[derive(Debug)]
pub struct HostKeyCheck {
    expectation: HostKeyExpectation,
    pin: KnownHostsPin,
}

impl HostKeyCheck {
    /// For the CLI and TUI, before `ssh` is spawned. Leaves the pin holding
    /// nothing `ssh` could trust except the key the gateway published.
    pub fn for_session(
        session: &CreateSshSessionResponse,
        target: &SandboxSshTarget<'_>,
        allow_unverified: bool,
    ) -> Result<Self, HostKeyError> {
        let expectation = HostKeyExpectation::from_published(
            &session.host_key_fingerprint,
            target.sandbox,
            allow_unverified,
        )?;
        Self::for_relay(expectation, KnownHostsPin::for_target(target)?)
    }

    /// For `ssh-proxy`, before the first byte is relayed.
    pub fn for_relay(
        expectation: HostKeyExpectation,
        pin: KnownHostsPin,
    ) -> Result<Self, HostKeyError> {
        pin.forget_unless(match &expectation {
            HostKeyExpectation::Fingerprint(fingerprint) => Some(fingerprint),
            HostKeyExpectation::AcceptAny => None,
        })?;
        Ok(Self { expectation, pin })
    }

    #[must_use]
    pub fn unverified_warning(&self, sandbox: &str) -> Option<String> {
        matches!(self.expectation, HostKeyExpectation::AcceptAny).then(|| {
            format!(
                "warning: SSH host key of sandbox '{sandbox}' is NOT verified (the gateway published no fingerprint)"
            )
        })
    }

    pub(crate) fn ssh_options(&self) -> Vec<(&'static str, String)> {
        self.pin.ssh_options()
    }

    /// `["--host-key", <expectation>, "--known-hosts", <path>]`
    pub(crate) fn proxy_flags(&self) -> [String; 4] {
        [
            "--host-key".to_string(),
            self.expectation.to_string(),
            "--known-hosts".to_string(),
            self.pin.path.display().to_string(),
        ]
    }

    pub fn into_gate(self) -> HostKeyGate {
        HostKeyGate {
            check: self,
            phase: GatePhase::Banner,
            buffer: Vec::new(),
        }
    }

    /// Pins `blob`, unless a fingerprint is expected and `blob` does not hash
    /// to it.
    fn admit(&self, blob: &[u8]) -> Result<(), HostKeyError> {
        if let HostKeyExpectation::Fingerprint(expected) = self.expectation {
            let presented = HostKeyFingerprint::of_blob(blob)?;
            if presented != expected {
                return Err(HostKeyError::Mismatch {
                    sandbox: self.pin.sandbox.clone(),
                    workspace: self.pin.workspace.clone(),
                    expected,
                    presented,
                });
            }
        }
        self.pin.store(blob)?;
        Ok(())
    }

    /// The phase after one cleartext packet from the server. Every packet
    /// outside the one accepted order is refused.
    fn phase_after(
        &self,
        awaited: GatePhase,
        message: u8,
        fields: &[u8],
    ) -> Result<GatePhase, HostKeyError> {
        let host_key = matches!(message, MSG_KEX_REPLY | MSG_KEX_GEX_REPLY)
            .then(|| ed25519_host_key(fields))
            .flatten();
        match (awaited, message, host_key) {
            (GatePhase::KexInit, MSG_KEXINIT, _) if first_kex_packet_follows(fields) == Some(0) => {
                Ok(GatePhase::GroupOrReply)
            }
            (GatePhase::GroupOrReply | GatePhase::Reply, _, Some(blob)) => {
                self.admit(blob)?;
                Ok(GatePhase::NewKeys)
            }
            (GatePhase::GroupOrReply, MSG_KEX_REPLY, None) => Ok(GatePhase::Reply),
            (GatePhase::NewKeys, MSG_NEWKEYS, _) => Ok(GatePhase::Done),
            (GatePhase::GroupOrReply | GatePhase::Reply, MSG_NEWKEYS, _) => Err(
                HostKeyError::Malformed("key exchange finished without an Ed25519 host key"),
            ),
            _ => Err(HostKeyError::Malformed(
                "packet outside the key exchange order",
            )),
        }
    }
}

/// The server-to-client side of the `ssh-proxy` relay. Holds back the server's
/// key exchange reply until the host key in it is checked and pinned.
#[derive(Debug)]
pub struct HostKeyGate {
    check: HostKeyCheck,
    phase: GatePhase,
    /// Bytes not yet released. Its head is the line or packet being decided.
    buffer: Vec<u8>,
}

/// What the gate waits for: the identification line, then the cleartext
/// packets of a key exchange in the only order the server may send them. `ssh`
/// can discard a packet outside this order, so a gate that let one through
/// could be shown one host key while `ssh` acts on another.
#[derive(Clone, Copy, Debug)]
enum GatePhase {
    Banner,
    KexInit,
    /// The reply, or before it the group of a group exchange.
    GroupOrReply,
    Reply,
    NewKeys,
    Done,
}

impl HostKeyGate {
    /// Feed bytes read from the gateway; returns the bytes that may be written
    /// to `ssh` now. Lines are released whole up to the `SSH-` identification
    /// line. Then exactly these packets are released whole, in this order:
    /// KEXINIT, the group of a group exchange if there is one, the key
    /// exchange reply once its Ed25519 host key is pinned, and NEWKEYS.
    /// Everything after NEWKEYS passes through.
    ///
    /// On an error nothing from this call is released, and every later call
    /// fails on the same line or packet.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, HostKeyError> {
        self.buffer.extend_from_slice(chunk);
        let mut released = Vec::new();
        while let Some(len) = self.releasable()? {
            released.extend(self.buffer.drain(..len));
        }
        Ok(released)
    }

    /// The length of the buffer's head that may be released, or `None` when
    /// deciding needs more bytes. An error leaves the head in place.
    fn releasable(&mut self) -> Result<Option<usize>, HostKeyError> {
        match self.phase {
            GatePhase::Banner => {
                let head = &self.buffer[..self.buffer.len().min(MAX_BANNER_LINE_LEN)];
                let Some(newline) = head.iter().position(|&byte| byte == b'\n') else {
                    return if head.len() == MAX_BANNER_LINE_LEN {
                        Err(HostKeyError::Malformed("identification line is too long"))
                    } else {
                        Ok(None)
                    };
                };
                if head.starts_with(b"SSH-") {
                    self.phase = GatePhase::KexInit;
                }
                Ok(Some(newline + 1))
            }
            GatePhase::Done => Ok((!self.buffer.is_empty()).then_some(self.buffer.len())),
            awaited => {
                let Some((length, rest)) = self.buffer.split_first_chunk::<4>() else {
                    return Ok(None);
                };
                let length = usize::try_from(u32::from_be_bytes(*length))
                    .ok()
                    .filter(|length| PACKET_LENGTHS.contains(length))
                    .ok_or(HostKeyError::Malformed("packet length is out of range"))?;
                let Some(packet) = rest.get(..length) else {
                    return Ok(None);
                };
                let padding = usize::from(packet[0]);
                let (message, fields) = packet
                    .get(1..length.saturating_sub(padding))
                    .and_then(<[u8]>::split_first)
                    .ok_or(HostKeyError::Malformed("packet padding leaves no payload"))?;
                self.phase = self.check.phase_after(awaited, *message, fields)?;
                Ok(Some(4 + length))
            }
        }
    }
}

/// The boolean that follows the cookie and the ten name-lists of a KEXINIT.
fn first_kex_packet_follows(fields: &[u8]) -> Option<u8> {
    let mut rest = fields.get(KEXINIT_COOKIE_LEN..)?;
    for _ in 0..KEXINIT_NAME_LISTS {
        let (length, after_length) = rest.split_first_chunk::<4>()?;
        rest = after_length.get(usize::try_from(u32::from_be_bytes(*length)).ok()?..)?;
    }
    rest.first().copied()
}

/// The first string of a key exchange reply, when it is exactly an Ed25519
/// public key blob.
fn ed25519_host_key(fields: &[u8]) -> Option<&[u8]> {
    let (length, rest) = fields.split_first_chunk::<4>()?;
    let blob = rest.get(..usize::try_from(u32::from_be_bytes(*length)).ok()?)?;
    let key = blob.strip_prefix(ED25519_BLOB_PREFIX)?;
    (key.len() == ED25519_KEY_LEN).then_some(blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_environment::{Environment, fixture_dir};

    const KEY_A: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    const FINGERPRINT_A: &str = "SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA";
    const KNOWN_HOSTS_KEY_A: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";
    const KEY_B: [u8; 32] = [
        255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240, 239, 238,
        237, 236, 235, 234, 233, 232, 231, 230, 229, 228, 227, 226, 225, 224,
    ];
    const FINGERPRINT_B: &str = "SHA256:LIHRKjP8oeafKrX0BHkvTYI/ZcB3tRHZHr9uyEhysws";
    const KNOWN_HOSTS_KEY_B: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAIP/+/fz7+vn49/b19PPy8fDv7u3s6+rp6Ofm5eTj4uHg";

    const TARGET: SandboxSshTarget<'static> = SandboxSshTarget {
        gateway: "prod",
        workspace: "default",
        sandbox: "my-sb",
    };

    fn ed25519_blob(key: [u8; 32]) -> Vec<u8> {
        let mut blob = Vec::new();
        for field in [HOST_KEY_ALGORITHM.as_bytes(), &key] {
            blob.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
            blob.extend_from_slice(field);
        }
        blob
    }

    fn fingerprint(text: &str) -> HostKeyFingerprint {
        text.parse().unwrap()
    }

    fn pin_in(config_dir: &Path) -> KnownHostsPin {
        KnownHostsPin::under(config_dir, &TARGET).unwrap()
    }

    fn pin_file(key: &str) -> String {
        format!("{PIN_HEADER}openshell-my-sb.default ssh-ed25519 {key}\n")
    }

    fn published(fingerprint: &str) -> CreateSshSessionResponse {
        CreateSshSessionResponse {
            host_key_fingerprint: fingerprint.to_string(),
            ..Default::default()
        }
    }

    fn with_config_dir(assertions: impl FnOnce(&Path)) {
        let config_home = fixture_dir().unwrap();
        Environment::new()
            .set("XDG_CONFIG_HOME", config_home.path())
            .run(|| assertions(&config_home.path().join("openshell")));
    }

    const BANNER: &[u8] = b"SSH-2.0-OpenShell_0.0.0\r\n";
    /// Stands in for the encrypted stream: read as a packet, its length is out
    /// of range.
    const ENCRYPTED: [u8; 48] = [0xff; 48];

    fn string(bytes: &[u8]) -> Vec<u8> {
        [&u32::try_from(bytes.len()).unwrap().to_be_bytes(), bytes].concat()
    }

    /// Four bytes of padding: the gate does not check block alignment.
    fn packet(payload: &[u8]) -> Vec<u8> {
        let length = u32::try_from(payload.len() + 5).unwrap().to_be_bytes();
        [&length[..], &[4], payload, &[0; 4]].concat()
    }

    fn kexinit() -> Vec<u8> {
        kexinit_ending(&[0; 5])
    }

    /// A KEXINIT whose ten name-lists are followed by `ending`: normally
    /// `first_kex_packet_follows` and the reserved word.
    fn kexinit_ending(ending: &[u8]) -> Vec<u8> {
        let mut payload = vec![20];
        payload.extend_from_slice(&[0x11; 16]);
        for length in [17, 11, 29, 29, 13, 13, 4, 4, 0, 0] {
            payload.extend(string(&vec![b'a'; length]));
        }
        payload.extend_from_slice(ending);
        packet(&payload)
    }

    fn group() -> Vec<u8> {
        let prime = [&[0][..], &[0xff; 256]].concat();
        packet(&[vec![31], string(&prime), string(&[2])].concat())
    }

    fn kex_reply(message: u8, host_key: &[u8]) -> Vec<u8> {
        let signature = [string(b"ssh-ed25519"), string(&[0x5a; 64])].concat();
        packet(
            &[
                vec![message],
                string(host_key),
                string(&[0x42; 32]),
                string(&signature),
            ]
            .concat(),
        )
    }

    fn newkeys() -> Vec<u8> {
        packet(&[21])
    }

    /// What the server sends before its reply, the reply, and what follows it.
    fn curve25519_exchange(host_key: [u8; 32]) -> [Vec<u8>; 3] {
        [
            [BANNER, &kexinit()].concat(),
            kex_reply(31, &ed25519_blob(host_key)),
            [newkeys(), ENCRYPTED.to_vec()].concat(),
        ]
    }

    fn group_exchange(host_key: [u8; 32]) -> [Vec<u8>; 3] {
        [
            [BANNER, &kexinit(), &group()].concat(),
            kex_reply(33, &ed25519_blob(host_key)),
            [newkeys(), ENCRYPTED.to_vec()].concat(),
        ]
    }

    fn gate_in(config_dir: &Path, expectation: &str) -> HostKeyGate {
        HostKeyCheck::for_relay(expectation.parse().unwrap(), pin_in(config_dir))
            .unwrap()
            .into_gate()
    }

    /// What the gate released, how it ended, and the pin file it left.
    fn relay<'a>(
        expectation: &str,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> (Vec<u8>, Result<(), HostKeyError>, Option<String>) {
        let config_dir = tempfile::tempdir().unwrap();
        let mut gate = gate_in(config_dir.path(), expectation);
        let mut released = Vec::new();
        let result = chunks.into_iter().try_for_each(|chunk| {
            released.extend(gate.push(chunk)?);
            Ok(())
        });
        let pin = fs::read_to_string(pin_in(config_dir.path()).path()).ok();
        (released, result, pin)
    }

    /// Every way to deliver `stream` in two chunks, then one byte at a time.
    fn every_split(stream: &[u8]) -> impl Iterator<Item = Vec<&[u8]>> {
        (0..=stream.len())
            .map(|at| vec![&stream[..at], &stream[at..]])
            .chain([stream.chunks(1).collect()])
    }

    #[test]
    fn fingerprint_of_blob_matches_fixed_vector() {
        let computed = HostKeyFingerprint::of_blob(&ed25519_blob(KEY_A)).unwrap();
        assert_eq!(computed.to_string(), FINGERPRINT_A);
        assert_eq!(fingerprint(FINGERPRINT_A), computed);
        assert_ne!(fingerprint(FINGERPRINT_B), computed);
    }

    #[test]
    fn fingerprint_rejects_every_other_text_form() {
        for text in [
            "",
            "SHA256:",
            "ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA",
            "sha256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA",
            "SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA=",
            "SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncC",
            "SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCAA",
            "SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCB",
            "SHA256:ZkAslGjFiUHdGf_WUL8rQvkib4PTvQatUV0OUQSncCA",
            "SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA\n",
            " SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA",
            "MD5:b4:f6:6e:5f:3c:0a:9d:11:27:35:5d:42:8e:0c:71:aa",
        ] {
            assert!(
                matches!(
                    text.parse::<HostKeyFingerprint>(),
                    Err(HostKeyError::BadFingerprint)
                ),
                "{text:?}"
            );
        }
    }

    #[test]
    fn expectation_policy_never_changes_a_published_outcome() {
        for allow in [false, true] {
            assert_eq!(
                HostKeyExpectation::from_published(FINGERPRINT_A, "my-sb", allow).unwrap(),
                HostKeyExpectation::Fingerprint(fingerprint(FINGERPRINT_A)),
                "{allow}"
            );
            for malformed in ["unverified", "SHA256:inconsistent", "MD5:00:11"] {
                assert!(
                    matches!(
                        HostKeyExpectation::from_published(malformed, "my-sb", allow),
                        Err(HostKeyError::BadFingerprint)
                    ),
                    "{malformed:?} {allow}"
                );
            }
        }
    }

    #[test]
    fn unverified_policy_allows_only_when_the_variable_is_one() {
        Environment::new()
            .set(ALLOW_UNVERIFIED_ENV, "1")
            .run(|| assert!(allow_unverified_host_key()));
        for value in ["", "0", "true", "yes", "11"] {
            Environment::new()
                .set(ALLOW_UNVERIFIED_ENV, value)
                .run(|| assert!(!allow_unverified_host_key()));
        }
        Environment::new()
            .remove(ALLOW_UNVERIFIED_ENV)
            .run(|| assert!(!allow_unverified_host_key()));
    }

    #[test]
    fn pin_for_target_resolves_a_relative_config_dir_against_the_working_directory() {
        Environment::new()
            .set("XDG_CONFIG_HOME", "relative/.config")
            .run(|| {
                let pin = KnownHostsPin::for_target(&TARGET).unwrap();
                assert_eq!(
                    pin.path(),
                    std::env::current_dir().unwrap().join(
                        "relative/.config/openshell/known_hosts/prod/openshell-my-sb.default"
                    )
                );
            });
    }

    #[test]
    fn pin_for_a_gateway_named_by_its_endpoint_lives_in_one_directory() {
        let config_dir = Path::new("/home/u/.config/openshell");
        for (gateway, directory) in [
            ("http://127.0.0.1:18080", "http___127.0.0.1_18080"),
            ("https://gw.example.com/a b%", "https___gw.example.com_a_b_"),
            ("../../etc", ".._.._etc"),
        ] {
            let target = SandboxSshTarget { gateway, ..TARGET };
            assert_eq!(
                KnownHostsPin::under(config_dir, &target).unwrap().path(),
                config_dir
                    .join("known_hosts")
                    .join(directory)
                    .join("openshell-my-sb.default"),
                "gateway {gateway:?}"
            );
        }
    }

    #[test]
    fn pin_rejects_names_that_are_not_one_path_component() {
        let config_dir = Path::new("/home/u/.config/openshell");
        for (gateway, workspace, sandbox) in [
            ("", "default", "my-sb"),
            (".", "default", "my-sb"),
            ("..", "default", "my-sb"),
            ("prod", "default", "a/b"),
            ("prod", "../x", "my-sb"),
            ("prod", "x/", "my-sb"),
        ] {
            let target = SandboxSshTarget {
                gateway,
                workspace,
                sandbox,
            };
            assert!(
                matches!(
                    KnownHostsPin::under(config_dir, &target),
                    Err(HostKeyError::UnusablePath(_))
                ),
                "{target:?}"
            );
        }
    }

    #[test]
    fn pin_rejects_paths_ssh_would_expand_or_split() {
        for path in [
            "/home/100%/pin",
            "/home/a\"b/pin",
            "/home/${HOME}/pin",
            "/home/a\nb/pin",
            #[cfg(unix)]
            "/home/a\\b/pin",
            "relative/pin",
            "",
            "/",
            "/tmp/..",
        ] {
            assert!(
                matches!(
                    KnownHostsPin::at(PathBuf::from(path), "my-sb", "default"),
                    Err(HostKeyError::UnusablePath(_))
                ),
                "{path:?}"
            );
        }
    }

    /// The pin directory is created owner-only; a directory that already
    /// exists keeps its mode.
    #[cfg(unix)]
    #[test]
    fn pin_store_creates_owner_only_files_and_leaves_existing_directories_alone() {
        use std::os::unix::fs::PermissionsExt as _;
        let shared = tempfile::tempdir().unwrap();
        fs::set_permissions(shared.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;

        for pin in [shared.path().join("pin"), shared.path().join("new/pin")] {
            let pin = KnownHostsPin::at(pin, "my-sb", "default").unwrap();
            pin.store(&ed25519_blob(KEY_A)).unwrap();
            assert_eq!(mode(pin.path()), 0o600);
        }
        assert_eq!(mode(&shared.path().join("new")), 0o700);
        assert_eq!(mode(shared.path()), 0o755);
    }

    #[test]
    fn pin_drops_anything_that_is_not_exactly_one_matching_key() {
        let matching = pin_file(KNOWN_HOSTS_KEY_A);
        let other_line = format!("openshell-my-sb.default ssh-ed25519 {KNOWN_HOSTS_KEY_B}\n");
        for content in [
            String::new(),
            "not a known_hosts file".to_string(),
            format!("{matching}{other_line}"),
            format!("{PIN_HEADER}{other_line}{}", &matching[PIN_HEADER.len()..]),
            format!("{PIN_HEADER}* ssh-ed25519 {KNOWN_HOSTS_KEY_A}\n"),
            format!("{PIN_HEADER}openshell-other.default ssh-ed25519 {KNOWN_HOSTS_KEY_A}\n"),
            format!(
                "{PIN_HEADER}@cert-authority openshell-my-sb.default ssh-ed25519 {KNOWN_HOSTS_KEY_A}\n"
            ),
            format!("{PIN_HEADER}openshell-my-sb.default ssh-ed25519 not-base64\n"),
            matching[PIN_HEADER.len()..].to_string(),
            matching.trim_end().to_string(),
        ] {
            let config_dir = tempfile::tempdir().unwrap();
            let pin = pin_in(config_dir.path());
            fs::create_dir_all(pin.path().parent().unwrap()).unwrap();
            fs::write(pin.path(), &content).unwrap();

            pin.forget_unless(Some(&fingerprint(FINGERPRINT_A)))
                .unwrap();

            assert_eq!(
                fs::read_to_string(pin.path()).unwrap(),
                PIN_HEADER,
                "{content:?}"
            );
        }
    }

    /// Before `ssh` can read the pin, it holds the published key or no key.
    #[test]
    fn check_for_session_keeps_only_the_published_key() {
        with_config_dir(|config_dir| {
            let pin = pin_in(config_dir);
            let path = pin.path().display().to_string();
            for (stored, kept) in [
                (KEY_B, PIN_HEADER.to_string()),
                (KEY_A, pin_file(KNOWN_HOSTS_KEY_A)),
            ] {
                pin.store(&ed25519_blob(stored)).unwrap();

                let check =
                    HostKeyCheck::for_session(&published(FINGERPRINT_A), &TARGET, false).unwrap();

                assert_eq!(fs::read_to_string(pin.path()).unwrap(), kept);
                assert_eq!(check.unverified_warning("my-sb"), None);
                assert_eq!(
                    check.proxy_flags(),
                    ["--host-key", FINGERPRINT_A, "--known-hosts", path.as_str()]
                );
            }
        });
    }

    #[test]
    fn check_for_session_refuses_an_unpublished_key_without_touching_the_pin() {
        with_config_dir(|config_dir| {
            let error = HostKeyCheck::for_session(&published(""), &TARGET, false).unwrap_err();

            assert_eq!(
                error.to_string(),
                "sandbox 'my-sb' has no published SSH host key, so its SSH server cannot be verified.\n  \
                 If the gateway predates sandbox SSH identities, upgrade it. Otherwise stop and start the sandbox so the gateway assigns a key.\n  \
                 To connect without verification, set OPENSHELL_SSH_ALLOW_UNVERIFIED_HOST_KEY=1."
            );
            assert!(!config_dir.exists());
        });
    }

    #[test]
    fn check_for_session_never_trusts_a_cached_pin_when_unverified() {
        with_config_dir(|config_dir| {
            let pin = pin_in(config_dir);
            pin.store(&ed25519_blob(KEY_A)).unwrap();

            let check = HostKeyCheck::for_session(&published(""), &TARGET, true).unwrap();

            assert_eq!(fs::read_to_string(pin.path()).unwrap(), PIN_HEADER);
            assert_eq!(
                check.unverified_warning("my-sb").unwrap(),
                "warning: SSH host key of sandbox 'my-sb' is NOT verified (the gateway published no fingerprint)"
            );
            assert_eq!(check.proxy_flags()[..2], ["--host-key", "unverified"]);
        });
    }

    /// Other connections to the sandbox start while one stores the key and
    /// hands the reply to `ssh`, which must then find the key in the pin.
    #[test]
    fn check_for_relay_keeps_the_key_another_connection_just_stored() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct StopOnDrop<'a>(&'a AtomicBool);
        impl Drop for StopOnDrop<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }

        let config_dir = tempfile::tempdir().unwrap();
        let pin = pin_in(config_dir.path());
        let stream = curve25519_exchange(KEY_A).concat();
        let stop = AtomicBool::new(false);
        pin.forget_unless(None).unwrap();

        std::thread::scope(|scope| {
            let _stop_others = StopOnDrop(&stop);
            for _ in 0..4 {
                scope.spawn(|| {
                    while !stop.load(Ordering::Relaxed) {
                        gate_in(config_dir.path(), FINGERPRINT_A);
                    }
                });
            }
            for connection in 0..500 {
                pin.forget_unless(None).unwrap();
                let mut gate = gate_in(config_dir.path(), FINGERPRINT_A);

                assert_eq!(gate.push(&stream).unwrap(), stream, "{connection}");
                assert_eq!(
                    fs::read_to_string(pin.path()).unwrap(),
                    pin_file(KNOWN_HOSTS_KEY_A),
                    "{connection}"
                );
            }
        });
    }

    /// Asserts that `stream` is refused as `is_expected` says, that nothing
    /// past `before` is released and that the pin file is left as `pin`,
    /// however `stream` is split.
    fn assert_refused(
        name: &str,
        expectation: &str,
        before: &[u8],
        stream: &[u8],
        is_expected: impl Fn(&HostKeyError) -> bool,
        pin: &str,
    ) {
        for chunks in every_split(stream) {
            let at = chunks[0].len();
            let (released, result, kept) = relay(expectation, chunks);

            assert!(
                result.as_ref().is_err_and(&is_expected),
                "{name} split at {at}: {result:?}"
            );
            assert!(before.starts_with(&released), "{name} split at {at}");
            assert_eq!(kept.as_deref(), Some(pin), "{name} split at {at}");
        }
    }

    #[test]
    fn gate_relays_an_exchange_unchanged_and_pins_its_key() {
        let curve = curve25519_exchange(KEY_A).concat();
        let gex = group_exchange(KEY_A).concat();
        let other = curve25519_exchange(KEY_B).concat();
        let greeted = [&b"Welcome\r\nnotice: maintenance at noon\n"[..], &curve].concat();
        for (name, expectation, stream, key) in [
            ("curve25519", FINGERPRINT_A, &curve, KNOWN_HOSTS_KEY_A),
            ("group exchange", FINGERPRINT_A, &gex, KNOWN_HOSTS_KEY_A),
            ("unverified", "unverified", &other, KNOWN_HOSTS_KEY_B),
            ("greeting", FINGERPRINT_A, &greeted, KNOWN_HOSTS_KEY_A),
        ] {
            for chunks in every_split(stream) {
                let at = chunks[0].len();
                let (released, result, pin) = relay(expectation, chunks);

                assert!(result.is_ok(), "{name} split at {at}");
                assert_eq!(&released, stream, "{name} split at {at}");
                assert_eq!(pin, Some(pin_file(key)), "{name} split at {at}");
            }
        }
    }

    #[test]
    fn gate_holds_the_reply_until_its_key_is_pinned() {
        let [before, reply, after] = curve25519_exchange(KEY_A);
        let (reply_head, reply_last_byte) = reply.split_at(reply.len() - 1);
        let config_dir = tempfile::tempdir().unwrap();
        let pin = pin_in(config_dir.path());
        let mut gate = gate_in(config_dir.path(), FINGERPRINT_A);

        assert_eq!(gate.push(&before).unwrap(), before);
        assert_eq!(gate.push(reply_head).unwrap(), b"");
        assert_eq!(fs::read_to_string(pin.path()).unwrap(), PIN_HEADER);

        assert_eq!(gate.push(reply_last_byte).unwrap(), reply);
        assert_eq!(
            fs::read_to_string(pin.path()).unwrap(),
            pin_file(KNOWN_HOSTS_KEY_A)
        );
        assert_eq!(gate.push(&after).unwrap(), after);
    }

    #[test]
    fn gate_withholds_a_reply_carrying_another_key() {
        for exchange in [curve25519_exchange(KEY_B), group_exchange(KEY_B)] {
            assert_refused(
                "another key",
                FINGERPRINT_A,
                &exchange[0],
                &exchange.concat(),
                |error| {
                    matches!(
                        error,
                        HostKeyError::Mismatch { expected, presented, .. }
                            if *expected == fingerprint(FINGERPRINT_A)
                                && *presented == fingerprint(FINGERPRINT_B)
                    )
                },
                PIN_HEADER,
            );
        }
    }

    #[test]
    fn gate_fails_when_new_keys_come_before_an_ed25519_host_key() {
        let rsa = [string(b"ssh-rsa"), string(&[1, 0, 1]), string(&[0x7f; 257])].concat();
        let short = [string(b"ssh-ed25519"), string(&KEY_A[..31])].concat();
        let truncated = ed25519_blob(KEY_A)[..50].to_vec();
        let trailing = [ed25519_blob(KEY_A), vec![0]].concat();
        let mut befores = vec![
            [BANNER, &kexinit()].concat(),
            [BANNER, &kexinit(), &group()].concat(),
        ];
        befores.extend(
            [rsa, short, truncated, trailing, Vec::new()]
                .map(|host_key| [BANNER, &kexinit(), &kex_reply(31, &host_key)].concat()),
        );
        for before in befores {
            let stream = [before.as_slice(), &newkeys(), &ENCRYPTED].concat();
            for expectation in [FINGERPRINT_A, "unverified"] {
                assert_refused(
                    "no host key",
                    expectation,
                    &before,
                    &stream,
                    |error| matches!(error, HostKeyError::Malformed(NO_HOST_KEY)),
                    PIN_HEADER,
                );
            }
        }
    }

    const NO_HOST_KEY: &str = "key exchange finished without an Ed25519 host key";
    const OUT_OF_ORDER: &str = "packet outside the key exchange order";

    /// `ssh` discards a decoy, a packet it does not expect or was told to
    /// skip, and would act on the reply behind it.
    #[test]
    fn gate_rejects_a_packet_outside_the_key_exchange_order() {
        let ignore = packet(&[2, 0, 0, 0, 0]);
        let reply = kex_reply(31, &ed25519_blob(KEY_A));
        let other = kex_reply(31, &ed25519_blob(KEY_B));
        let rsa = [string(b"ssh-rsa"), string(&[1, 0, 1]), string(&[0x7f; 257])].concat();
        let decoy_first = [reply.as_slice(), &kexinit(), &other].concat();
        let other_gex = kex_reply(33, &ed25519_blob(KEY_B));
        let rsa_gex = kex_reply(33, &rsa);
        let wrong_guess = [&kexinit_ending(&[1, 0, 0, 0, 0])[..], &reply, &other].concat();
        let after_kexinit = [BANNER, &kexinit()].concat();
        let after_group = [BANNER, &kexinit(), &group()].concat();
        let after_reply = [BANNER, &kexinit(), &reply].concat();
        let after_group_reply = [BANNER, &kexinit(), &group(), &reply].concat();
        let pinned = pin_file(KNOWN_HOSTS_KEY_A);
        for (name, before, offending) in [
            ("decoy before KEXINIT", BANNER, &decoy_first),
            ("decoy as the announced wrong guess", BANNER, &wrong_guess),
            ("decoy before the reply", &after_reply, &other),
            ("decoy after the group", &after_group_reply, &other_gex),
            ("IGNORE first", BANNER, &ignore),
            ("NEWKEYS first", BANNER, &newkeys()),
            ("KEXINIT cut short", BANNER, &kexinit_ending(&[])),
            ("IGNORE before the reply", &after_kexinit, &ignore),
            ("second KEXINIT", &after_kexinit, &kexinit()),
            ("second group", &after_group, &group()),
            ("non-Ed25519 group reply", &after_group, &rsa_gex),
            ("IGNORE before NEWKEYS", &after_reply, &ignore),
            ("second reply", &after_reply, &reply),
        ] {
            assert_refused(
                name,
                FINGERPRINT_A,
                before,
                &[before, offending, &newkeys(), &ENCRYPTED].concat(),
                |error| matches!(error, HostKeyError::Malformed(OUT_OF_ORDER)),
                if before.ends_with(&reply) {
                    &pinned
                } else {
                    PIN_HEADER
                },
            );
        }
    }

    #[test]
    fn gate_stays_closed_after_a_refusal() {
        let [before, reply, after] = curve25519_exchange(KEY_B);
        for refused in [
            [before.as_slice(), &reply].concat(),
            [BANNER, &kexinit_ending(&[1, 0, 0, 0, 0])].concat(),
        ] {
            let config_dir = tempfile::tempdir().unwrap();
            let mut gate = gate_in(config_dir.path(), FINGERPRINT_A);
            let first = gate.push(&refused).unwrap_err().to_string();

            for later in [after.as_slice(), b"", &curve25519_exchange(KEY_A).concat()] {
                assert_eq!(gate.push(later).unwrap_err().to_string(), first);
            }
            assert_eq!(
                fs::read_to_string(pin_in(config_dir.path()).path()).unwrap(),
                PIN_HEADER
            );
        }
    }

    #[test]
    fn gate_rejects_a_malformed_packet() {
        let length = |length: u32| [&length.to_be_bytes()[..], &[0; 16]].concat();
        let padded = |padding: u8| vec![0, 0, 0, 2, padding, 31];
        let mut long_line = b"SSH-2.0-".to_vec();
        long_line.resize(8192, b'a');
        for (before, rest, expected) in [
            (BANNER, length(0), "packet length is out of range"),
            (BANNER, length(1), "packet length is out of range"),
            (BANNER, length(262_145), "packet length is out of range"),
            (BANNER, length(u32::MAX), "packet length is out of range"),
            (BANNER, padded(1), "packet padding leaves no payload"),
            (BANNER, padded(9), "packet padding leaves no payload"),
            (b"".as_slice(), long_line, "identification line is too long"),
        ] {
            assert_refused(
                expected,
                FINGERPRINT_A,
                before,
                &[before, &rest].concat(),
                |error| matches!(error, HostKeyError::Malformed(message) if *message == expected),
                PIN_HEADER,
            );
        }
    }
}
