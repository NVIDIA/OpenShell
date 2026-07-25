// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Safe image identity resolution and creation-time persistence.

use miette::{Context, IntoDiagnostic, Result};
use openshell_core::sandbox_env::{IdentitySource, ResolvedAgentIdentity};
use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
#[cfg(any(test, target_os = "linux"))]
use std::path::PathBuf;
use std::path::{Component, Path};
use std::sync::OnceLock;

const PASSWD_PATH: &str = "/etc/passwd";
const GROUP_PATH: &str = "/etc/group";
pub const IDENTITY_STATE_PATH: &str = "/var/lib/openshell/agent-identity.json";
const IDENTITY_STATE_VERSION: u32 = 1;
const MAX_ACCOUNT_FILE_SIZE: u64 = 1024 * 1024;
const MAX_ACCOUNT_LINE_SIZE: usize = 8 * 1024;
const MAX_ACCOUNT_FIELD_SIZE: usize = 1024;
const MAX_STATE_FILE_SIZE: u64 = 16 * 1024;
#[cfg(target_os = "linux")]
const MAX_ID_MAP_FILE_SIZE: u64 = 64 * 1024;

static RESOLVED_IDENTITY: OnceLock<ResolvedAgentIdentity> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
enum IdentityRequest {
    Image {
        image_user: String,
        image_id: String,
    },
    Fixed {
        uid: u32,
        gid: u32,
        image_id: String,
    },
}

impl IdentityRequest {
    fn from_env() -> Result<Option<Self>> {
        let Some(source) = std::env::var_os(openshell_core::sandbox_env::IDENTITY_SOURCE) else {
            return Ok(None);
        };
        let source = source
            .into_string()
            .map_err(|_| miette::miette!("OPENSHELL_IDENTITY_SOURCE is not valid UTF-8"))?
            .parse::<IdentitySource>()
            .map_err(|error| miette::miette!(error))?;

        match source {
            IdentitySource::Image => {
                let image_user = required_env(openshell_core::sandbox_env::IMAGE_USER)?;
                let image_id = required_env(openshell_core::sandbox_env::IMAGE_ID)?;
                validate_metadata_value(openshell_core::sandbox_env::IMAGE_ID, &image_id)?;
                Ok(Some(Self::Image {
                    image_user,
                    image_id,
                }))
            }
            IdentitySource::Fixed => {
                let image_id = required_env(openshell_core::sandbox_env::IMAGE_ID)?;
                validate_metadata_value(openshell_core::sandbox_env::IMAGE_ID, &image_id)?;
                let uid = parse_fixed_id(
                    openshell_core::sandbox_env::SANDBOX_UID,
                    &required_env(openshell_core::sandbox_env::SANDBOX_UID)?,
                )?;
                let gid = parse_fixed_id(
                    openshell_core::sandbox_env::SANDBOX_GID,
                    &required_env(openshell_core::sandbox_env::SANDBOX_GID)?,
                )?;
                Ok(Some(Self::Fixed { uid, gid, image_id }))
            }
        }
    }

    const fn source(&self) -> IdentitySource {
        match self {
            Self::Image { .. } => IdentitySource::Image,
            Self::Fixed { .. } => IdentitySource::Fixed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PersistedIdentity {
    version: u32,
    identity: ResolvedAgentIdentity,
    image_user: Option<String>,
}

#[derive(Debug, Clone)]
struct PasswdEntry {
    name: String,
    uid: u32,
    gid: u32,
}

#[derive(Debug, Clone)]
struct GroupEntry {
    name: String,
    gid: u32,
}

/// Resolve or reload the protected agent identity metadata.
///
/// `None` means `OPENSHELL_IDENTITY_SOURCE` was absent and callers must retain
/// the legacy policy identity behavior.
pub fn resolve_and_persist_agent_identity() -> Result<Option<ResolvedAgentIdentity>> {
    let request = IdentityRequest::from_env()?;
    let identity = resolve_and_persist_at(
        request.as_ref(),
        Path::new(PASSWD_PATH),
        Path::new(GROUP_PATH),
        Path::new(IDENTITY_STATE_PATH),
        true,
        |identity| validate_user_namespace_mappings(identity.uid, identity.gid),
    )?;
    if let Some(identity) = identity.as_ref() {
        let installed = RESOLVED_IDENTITY.get_or_init(|| identity.clone());
        if installed != identity {
            return Err(miette::miette!(
                "resolved agent identity changed after initialization"
            ));
        }
    }
    Ok(identity)
}

/// Presentation name selected during image/fixed identity resolution.
#[must_use]
pub fn resolved_presentation_user() -> Option<&'static str> {
    RESOLVED_IDENTITY
        .get()
        .map(|identity| identity.presentation_user.as_str())
}

/// Resolve an OCI `USER` declaration using alternate account-file paths.
///
/// This helper never invokes libc NSS and is suitable for focused tests or
/// callers resolving an unpacked rootfs.
pub fn resolve_image_identity_at(
    image_user: &str,
    image_id: &str,
    passwd_path: &Path,
    group_path: &Path,
) -> Result<ResolvedAgentIdentity> {
    validate_metadata_value(openshell_core::sandbox_env::IMAGE_ID, image_id)?;
    let (user, group) = parse_oci_user(image_user)?;

    let (uid, primary_gid, presentation_user) = if let Some(uid) = parse_numeric_id(user, "UID")? {
        let primary_gid = if group.is_none() {
            let entries = read_passwd(passwd_path)?;
            Some(unique_passwd_by_uid(&entries, uid)?.ok_or_else(|| {
                    miette::miette!(
                        "OCI USER '{image_user}' uses numeric UID {uid} without an explicit group, but /etc/passwd has no matching entry"
                    )
                })?.gid)
        } else {
            None
        };
        (uid, primary_gid, uid.to_string())
    } else {
        if user == "root" {
            return Err(miette::miette!("OCI USER must not select root"));
        }
        let entries = read_passwd(passwd_path)?;
        let entry = unique_passwd_by_name(&entries, user)?.ok_or_else(|| {
            miette::miette!("OCI USER name '{user}' was not found in /etc/passwd")
        })?;
        (entry.uid, Some(entry.gid), user.to_string())
    };

    let gid = match group {
        Some(group) => {
            if let Some(gid) = parse_numeric_id(group, "GID")? {
                gid
            } else {
                if group == "root" {
                    return Err(miette::miette!("OCI USER group must not select root"));
                }
                let entries = read_group(group_path)?;
                unique_group_by_name(&entries, group)?
                    .ok_or_else(|| {
                        miette::miette!("OCI USER group '{group}' was not found in /etc/group")
                    })?
                    .gid
            }
        }
        None => primary_gid.ok_or_else(|| {
            miette::miette!("OCI USER '{image_user}' did not resolve a primary GID")
        })?,
    };

    reject_root_identity(uid, gid, image_user)?;
    Ok(ResolvedAgentIdentity {
        uid,
        gid,
        presentation_user,
        source: IdentitySource::Image,
        image_id: Some(image_id.to_string()),
    })
}

fn resolve_and_persist_at(
    request: Option<&IdentityRequest>,
    passwd_path: &Path,
    group_path: &Path,
    state_path: &Path,
    require_root_owner: bool,
    validate_mapping: impl Fn(&ResolvedAgentIdentity) -> Result<()>,
) -> Result<Option<ResolvedAgentIdentity>> {
    let Some(request) = request else {
        return Ok(None);
    };

    if let Some(state) = load_state(state_path, require_root_owner)? {
        validate_persisted(&state, request)?;
        validate_mapping(&state.identity)?;
        return Ok(Some(state.identity));
    }

    let (identity, image_user) = match request {
        IdentityRequest::Image {
            image_user,
            image_id,
        } => (
            resolve_image_identity_at(image_user, image_id, passwd_path, group_path)?,
            Some(image_user.clone()),
        ),
        IdentityRequest::Fixed { uid, gid, image_id } => {
            reject_root_identity(*uid, *gid, "fixed identity")?;
            (
                ResolvedAgentIdentity {
                    uid: *uid,
                    gid: *gid,
                    presentation_user: uid.to_string(),
                    source: IdentitySource::Fixed,
                    image_id: Some(image_id.clone()),
                },
                None,
            )
        }
    };
    let state = PersistedIdentity {
        version: IDENTITY_STATE_VERSION,
        identity: identity.clone(),
        image_user,
    };
    validate_mapping(&identity)?;
    persist_state(state_path, &state, require_root_owner)?;
    Ok(Some(identity))
}

fn validate_persisted(state: &PersistedIdentity, request: &IdentityRequest) -> Result<()> {
    if state.version != IDENTITY_STATE_VERSION {
        return Err(miette::miette!(
            "unsupported agent identity state version {}; expected {}",
            state.version,
            IDENTITY_STATE_VERSION
        ));
    }
    if state.identity.source != request.source() {
        return Err(miette::miette!(
            "persisted identity source '{}' does not match requested source '{}'",
            state.identity.source,
            request.source()
        ));
    }
    reject_root_identity(state.identity.uid, state.identity.gid, "persisted identity")?;

    match request {
        IdentityRequest::Image {
            image_user,
            image_id,
        } => {
            if state.identity.image_id.as_deref() != Some(image_id)
                || state.image_user.as_deref() != Some(image_user)
            {
                return Err(miette::miette!(
                    "persisted image identity metadata does not match OPENSHELL_IMAGE_ID/OPENSHELL_IMAGE_USER"
                ));
            }
        }
        IdentityRequest::Fixed { uid, gid, image_id } => {
            if state.identity.uid != *uid
                || state.identity.gid != *gid
                || state.identity.image_id.as_deref() != Some(image_id)
                || state.image_user.is_some()
            {
                return Err(miette::miette!(
                    "persisted fixed identity does not match OPENSHELL_SANDBOX_UID/OPENSHELL_SANDBOX_GID/OPENSHELL_IMAGE_ID"
                ));
            }
        }
    }
    Ok(())
}

fn required_env(name: &str) -> Result<String> {
    let value = std::env::var(name).map_err(|_| miette::miette!("{name} is required"))?;
    if value.is_empty() {
        return Err(miette::miette!("{name} must not be empty"));
    }
    Ok(value)
}

fn validate_metadata_value(name: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_ACCOUNT_FIELD_SIZE
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(miette::miette!("{name} contains an invalid value"));
    }
    Ok(())
}

fn parse_fixed_id(name: &str, value: &str) -> Result<u32> {
    if !openshell_policy::is_valid_sandbox_identity(value) || value == "sandbox" {
        return Err(miette::miette!(
            "{name} must be a numeric identity in range [{}, {}]",
            openshell_policy::MIN_SANDBOX_UID,
            openshell_policy::MAX_SANDBOX_UID
        ));
    }
    value
        .parse::<u32>()
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid {name}"))
}

fn parse_oci_user(value: &str) -> Result<(&str, Option<&str>)> {
    if value.is_empty() {
        return Err(miette::miette!(
            "OCI USER is empty; declare a non-root user"
        ));
    }
    if value.trim() != value || value.chars().any(char::is_whitespace) {
        return Err(miette::miette!("OCI USER must not contain whitespace"));
    }
    let mut fields = value.split(':');
    let user = fields.next().unwrap_or_default();
    let group = fields.next();
    if user.is_empty() || group == Some("") || fields.next().is_some() {
        return Err(miette::miette!(
            "malformed OCI USER '{value}'; expected user or user:group"
        ));
    }
    validate_identity_token(user, "user")?;
    if let Some(group) = group {
        validate_identity_token(group, "group")?;
    }
    Ok((user, group))
}

fn validate_identity_token(value: &str, kind: &str) -> Result<()> {
    if value.len() > MAX_ACCOUNT_FIELD_SIZE
        || value
            .bytes()
            .any(|byte| byte == b'\0' || byte == b'\n' || byte == b'\r')
    {
        return Err(miette::miette!("OCI USER {kind} field is invalid"));
    }
    Ok(())
}

fn parse_numeric_id(value: &str, kind: &str) -> Result<Option<u32>> {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(None);
    }
    let id = value
        .parse::<u32>()
        .into_diagnostic()
        .wrap_err_with(|| format!("OCI USER {kind} is outside the supported range"))?;
    if id == u32::MAX {
        return Err(miette::miette!(
            "OCI USER {kind} must not use the reserved value {}",
            u32::MAX
        ));
    }
    Ok(Some(id))
}

fn reject_root_identity(uid: u32, gid: u32, declaration: &str) -> Result<()> {
    if uid == 0 || gid == 0 {
        return Err(miette::miette!(
            "{declaration} resolves to prohibited root identity {uid}:{gid}"
        ));
    }
    Ok(())
}

/// One extent from Linux `/proc/*/{uid,gid}_map`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdMapRange {
    pub inside_start: u64,
    pub outside_start: u64,
    pub length: u64,
}

/// Parse a Linux user-namespace ID map with overflow checks.
pub fn parse_id_map(contents: &str, map_name: &str) -> Result<Vec<IdMapRange>> {
    let mut ranges = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() != 3 {
            return Err(miette::miette!(
                "malformed {map_name} at line {}: expected three integer fields",
                index + 1
            ));
        }
        let parse_field = |field: &str| -> Result<u64> {
            field.parse::<u64>().into_diagnostic().wrap_err_with(|| {
                format!(
                    "malformed {map_name} at line {}: invalid integer",
                    index + 1
                )
            })
        };
        let range = IdMapRange {
            inside_start: parse_field(fields[0])?,
            outside_start: parse_field(fields[1])?,
            length: parse_field(fields[2])?,
        };
        if range.length == 0
            || range.inside_start.checked_add(range.length).is_none()
            || range.outside_start.checked_add(range.length).is_none()
        {
            return Err(miette::miette!(
                "malformed {map_name} at line {}: zero-length or overflowing range",
                index + 1
            ));
        }
        ranges.push(range);
    }
    if ranges.is_empty() {
        return Err(miette::miette!("{map_name} contains no mappings"));
    }
    Ok(ranges)
}

/// Verify that a namespace-visible ID is covered by a parsed map.
pub fn validate_id_is_mapped(id: u32, ranges: &[IdMapRange], map_name: &str) -> Result<()> {
    let id = u64::from(id);
    if ranges.iter().any(|range| {
        range
            .inside_start
            .checked_add(range.length)
            .is_some_and(|end| id >= range.inside_start && id < end)
    }) {
        return Ok(());
    }
    Err(miette::miette!(
        "identity ID {id} is not mapped by {map_name}"
    ))
}

/// Validate UID/GID mappings using alternate proc-map paths.
#[cfg(target_os = "linux")]
pub fn validate_user_namespace_mappings_at(
    uid: u32,
    gid: u32,
    uid_map_path: &Path,
    gid_map_path: &Path,
) -> Result<()> {
    let uid_map = read_utf8_bounded_regular_file(uid_map_path, MAX_ID_MAP_FILE_SIZE)?;
    let gid_map = read_utf8_bounded_regular_file(gid_map_path, MAX_ID_MAP_FILE_SIZE)?;
    validate_id_is_mapped(uid, &parse_id_map(&uid_map, "uid_map")?, "uid_map")?;
    validate_id_is_mapped(gid, &parse_id_map(&gid_map, "gid_map")?, "gid_map")
}

/// Validate UID/GID mappings for the current Linux user namespace.
#[cfg(target_os = "linux")]
pub fn validate_user_namespace_mappings(uid: u32, gid: u32) -> Result<()> {
    let proc_dir = PathBuf::from(format!("/proc/{}", std::process::id()));
    validate_user_namespace_mappings_at(
        uid,
        gid,
        &proc_dir.join("uid_map"),
        &proc_dir.join("gid_map"),
    )
}

/// Non-Linux platforms retain their existing identity behavior.
#[cfg(not(target_os = "linux"))]
pub fn validate_user_namespace_mappings(_uid: u32, _gid: u32) -> Result<()> {
    Ok(())
}

fn read_passwd(path: &Path) -> Result<Vec<PasswdEntry>> {
    parse_account_lines(path, 7, |fields, line| {
        let uid = parse_account_id(fields[2], "UID", path, line)?;
        let gid = parse_account_id(fields[3], "GID", path, line)?;
        Ok(PasswdEntry {
            name: fields[0].to_string(),
            uid,
            gid,
        })
    })
}

fn read_group(path: &Path) -> Result<Vec<GroupEntry>> {
    parse_account_lines(path, 4, |fields, line| {
        let gid = parse_account_id(fields[2], "GID", path, line)?;
        Ok(GroupEntry {
            name: fields[0].to_string(),
            gid,
        })
    })
}

fn parse_account_lines<T>(
    path: &Path,
    expected_fields: usize,
    mut parse: impl FnMut(&[&str], usize) -> Result<T>,
) -> Result<Vec<T>> {
    let bytes = read_bounded_regular_file(path, MAX_ACCOUNT_FILE_SIZE)?;
    let contents = std::str::from_utf8(&bytes)
        .into_diagnostic()
        .wrap_err_with(|| format!("account file {} is not valid UTF-8", path.display()))?;
    let mut entries = Vec::new();
    for (index, raw_line) in contents.split('\n').enumerate() {
        let line_number = index + 1;
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() > MAX_ACCOUNT_LINE_SIZE {
            return Err(miette::miette!(
                "account file {} line {line_number} exceeds {} bytes",
                path.display(),
                MAX_ACCOUNT_LINE_SIZE
            ));
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() != expected_fields
            || fields[0].is_empty()
            || fields
                .iter()
                .any(|field| field.len() > MAX_ACCOUNT_FIELD_SIZE)
        {
            return Err(miette::miette!(
                "malformed account entry in {} at line {line_number}",
                path.display()
            ));
        }
        entries.push(parse(&fields, line_number)?);
    }
    Ok(entries)
}

fn parse_account_id(value: &str, kind: &str, path: &Path, line: usize) -> Result<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(miette::miette!(
            "malformed {kind} in {} at line {line}",
            path.display()
        ));
    }
    let value = value
        .parse::<u32>()
        .into_diagnostic()
        .wrap_err_with(|| format!("malformed {kind} in {} at line {line}", path.display()))?;
    if value == u32::MAX {
        return Err(miette::miette!(
            "reserved {kind} value in {} at line {line}",
            path.display()
        ));
    }
    Ok(value)
}

fn unique_passwd_by_name<'a>(
    entries: &'a [PasswdEntry],
    name: &str,
) -> Result<Option<&'a PasswdEntry>> {
    let matches: Vec<_> = entries.iter().filter(|entry| entry.name == name).collect();
    let Some(entry) = unique_match(matches, "passwd name", name)? else {
        return Ok(None);
    };
    reject_duplicate_passwd_uid(entries, entry.uid)?;
    Ok(Some(entry))
}

fn unique_passwd_by_uid(entries: &[PasswdEntry], uid: u32) -> Result<Option<&PasswdEntry>> {
    let matches: Vec<_> = entries.iter().filter(|entry| entry.uid == uid).collect();
    unique_match(matches, "passwd UID", &uid.to_string())
}

fn reject_duplicate_passwd_uid(entries: &[PasswdEntry], uid: u32) -> Result<()> {
    if entries.iter().filter(|entry| entry.uid == uid).count() > 1 {
        return Err(miette::miette!("duplicate passwd UID {uid}"));
    }
    Ok(())
}

fn unique_group_by_name<'a>(
    entries: &'a [GroupEntry],
    name: &str,
) -> Result<Option<&'a GroupEntry>> {
    let matches: Vec<_> = entries.iter().filter(|entry| entry.name == name).collect();
    let Some(entry) = unique_match(matches, "group name", name)? else {
        return Ok(None);
    };
    if entries
        .iter()
        .filter(|candidate| candidate.gid == entry.gid)
        .count()
        > 1
    {
        return Err(miette::miette!("duplicate group GID {}", entry.gid));
    }
    Ok(Some(entry))
}

fn unique_match<'a, T>(matches: Vec<&'a T>, kind: &str, value: &str) -> Result<Option<&'a T>> {
    match matches.as_slice() {
        [] => Ok(None),
        [entry] => Ok(Some(*entry)),
        _ => Err(miette::miette!("duplicate {kind} '{value}'")),
    }
}

fn read_bounded_regular_file(path: &Path, max_size: u64) -> Result<Vec<u8>> {
    let file = open_regular_file_no_follow(path)?;
    let metadata = file.metadata().into_diagnostic()?;
    if metadata.len() > max_size {
        return Err(miette::miette!(
            "{} exceeds the {} byte size limit",
            path.display(),
            max_size
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(max_size + 1)
        .read_to_end(&mut bytes)
        .into_diagnostic()?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_size {
        return Err(miette::miette!(
            "{} exceeds the {} byte size limit",
            path.display(),
            max_size
        ));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn read_utf8_bounded_regular_file(path: &Path, max_size: u64) -> Result<String> {
    String::from_utf8(read_bounded_regular_file(path, max_size)?)
        .into_diagnostic()
        .wrap_err_with(|| format!("{} is not valid UTF-8", path.display()))
}

fn load_state(path: &Path, require_root_owner: bool) -> Result<Option<PersistedIdentity>> {
    let Some((parent, name)) = open_parent_directory(path, false, Mode::empty())? else {
        return Ok(None);
    };
    let state = load_state_from_parent(&parent, &name, path, require_root_owner)?;
    if state.is_some() {
        validate_state_directory(&parent, path, require_root_owner)?;
    }
    Ok(state)
}

fn load_state_from_parent(
    parent: &OwnedFd,
    name: &OsStr,
    display_path: &Path,
    require_root_owner: bool,
) -> Result<Option<PersistedIdentity>> {
    let fd = match rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => {
            return Err(miette::miette!(
                "failed to open identity state {} without following symlinks: {error}",
                display_path.display()
            ));
        }
    };
    let file = File::from(fd);
    validate_state_metadata(
        display_path,
        &file.metadata().into_diagnostic()?,
        require_root_owner,
    )?;
    let mut bytes = Vec::new();
    file.take(MAX_STATE_FILE_SIZE + 1)
        .read_to_end(&mut bytes)
        .into_diagnostic()?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_STATE_FILE_SIZE {
        return Err(miette::miette!("agent identity state file is oversized"));
    }
    let state = decode_state(&bytes)?;
    Ok(Some(state))
}

fn persist_state(path: &Path, state: &PersistedIdentity, require_root_owner: bool) -> Result<()> {
    let (parent, name) = open_parent_directory(path, true, Mode::from_raw_mode(0o700))?
        .ok_or_else(|| miette::miette!("identity state path parent is unavailable"))?;
    prepare_state_directory(&parent, path, require_root_owner)?;
    let bytes = encode_state(state)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_STATE_FILE_SIZE {
        return Err(miette::miette!("agent identity state exceeds size limit"));
    }
    let temp_name = OsString::from(format!(".agent-identity-{}.tmp", uuid::Uuid::new_v4()));
    let temp_fd = rustix::fs::openat(
        &parent,
        &temp_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|error| {
        miette::miette!("failed to create exclusive identity state temp file: {error}")
    })?;
    let mut file = File::from(temp_fd);
    let write_result = (|| -> Result<()> {
        file.write_all(&bytes).into_diagnostic()?;
        file.write_all(b"\n").into_diagnostic()?;
        rustix::fs::fsync(&file).into_diagnostic()?;
        validate_state_metadata(
            path,
            &file.metadata().into_diagnostic()?,
            require_root_owner,
        )
    })();
    drop(file);
    if let Err(error) = write_result {
        let _ = rustix::fs::unlinkat(&parent, &temp_name, AtFlags::empty());
        return Err(error);
    }

    match publish_state_no_replace(&parent, &temp_name, &name) {
        Ok(()) => {
            rustix::fs::fsync(&parent).into_diagnostic()?;
            Ok(())
        }
        Err(rustix::io::Errno::EXIST) => {
            let _ = rustix::fs::unlinkat(&parent, &temp_name, AtFlags::empty());
            let existing = load_state_from_parent(&parent, &name, path, require_root_owner)?
                .ok_or_else(|| miette::miette!("identity state disappeared during publication"))?;
            if existing != *state {
                return Err(miette::miette!(
                    "concurrent identity state does not match resolved identity"
                ));
            }
            rustix::fs::fsync(&parent).into_diagnostic()?;
            Ok(())
        }
        Err(error) => {
            let _ = rustix::fs::unlinkat(&parent, &temp_name, AtFlags::empty());
            Err(miette::miette!(
                "failed to publish identity state atomically: {error}"
            ))
        }
    }
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn publish_state_no_replace(
    parent: &OwnedFd,
    temp_name: &OsStr,
    state_name: &OsStr,
) -> rustix::io::Result<()> {
    rustix::fs::renameat_with(
        parent,
        temp_name,
        parent,
        state_name,
        RenameFlags::NOREPLACE,
    )
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn publish_state_no_replace(
    parent: &OwnedFd,
    temp_name: &OsStr,
    state_name: &OsStr,
) -> rustix::io::Result<()> {
    rustix::fs::linkat(parent, temp_name, parent, state_name, AtFlags::empty())?;
    rustix::fs::unlinkat(parent, temp_name, AtFlags::empty())
}

fn encode_state(state: &PersistedIdentity) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "version": state.version,
        "identity": state.identity,
        "image_user": state.image_user,
    }))
    .into_diagnostic()
}

fn decode_state(bytes: &[u8]) -> Result<PersistedIdentity> {
    let mut value: serde_json::Value = serde_json::from_slice(bytes)
        .into_diagnostic()
        .wrap_err("failed to parse persisted agent identity")?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| miette::miette!("persisted agent identity must be a JSON object"))?;
    let version = object
        .remove("version")
        .and_then(|value| value.as_u64())
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| miette::miette!("persisted agent identity has an invalid version"))?;
    let identity = serde_json::from_value(
        object
            .remove("identity")
            .ok_or_else(|| miette::miette!("persisted agent identity is missing identity"))?,
    )
    .into_diagnostic()
    .wrap_err("persisted agent identity has an invalid identity record")?;
    let image_user = match object.remove("image_user") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value)) => Some(value),
        Some(_) => {
            return Err(miette::miette!(
                "persisted agent identity has invalid image_user metadata"
            ));
        }
    };
    Ok(PersistedIdentity {
        version,
        identity,
        image_user,
    })
}

fn prepare_state_directory(
    directory: &OwnedFd,
    state_path: &Path,
    require_root_owner: bool,
) -> Result<()> {
    let stat = rustix::fs::fstat(directory).into_diagnostic()?;
    if require_root_owner && stat.st_uid != 0 {
        return Err(miette::miette!(
            "identity state directory {} must be root-owned",
            state_path.parent().unwrap_or(state_path).display()
        ));
    }
    rustix::fs::fchmod(directory, Mode::from_raw_mode(0o700)).into_diagnostic()?;
    Ok(())
}

fn validate_state_directory(
    directory: &OwnedFd,
    state_path: &Path,
    require_root_owner: bool,
) -> Result<()> {
    let stat = rustix::fs::fstat(directory).into_diagnostic()?;
    if require_root_owner && stat.st_uid != 0 {
        return Err(miette::miette!(
            "identity state directory {} must be root-owned",
            state_path.parent().unwrap_or(state_path).display()
        ));
    }
    if stat.st_mode & 0o777 != 0o700 {
        return Err(miette::miette!(
            "identity state directory {} must have mode 0700",
            state_path.parent().unwrap_or(state_path).display()
        ));
    }
    Ok(())
}

fn validate_state_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
    require_root_owner: bool,
) -> Result<()> {
    if !metadata.file_type().is_file() {
        return Err(miette::miette!(
            "identity state {} must be a regular file",
            path.display()
        ));
    }
    if metadata.mode() & 0o777 != 0o600 {
        return Err(miette::miette!(
            "identity state {} must have mode 0600",
            path.display()
        ));
    }
    if require_root_owner && metadata.uid() != 0 {
        return Err(miette::miette!(
            "identity state {} must be root-owned",
            path.display()
        ));
    }
    Ok(())
}

fn open_regular_file_no_follow(path: &Path) -> Result<File> {
    let (parent, name) = open_parent_directory(path, false, Mode::empty())?
        .ok_or_else(|| miette::miette!("parent of {} does not exist", path.display()))?;
    let fd = rustix::fs::openat(
        &parent,
        &name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| {
        miette::miette!(
            "failed to open {} without following symlinks: {error}",
            path.display()
        )
    })?;
    let file = File::from(fd);
    if !file.metadata().into_diagnostic()?.file_type().is_file() {
        return Err(miette::miette!("{} must be a regular file", path.display()));
    }
    Ok(file)
}

/// Prepare a read-write path and own a newly created final directory through
/// its already-verified descriptor. Existing paths retain their ownership.
pub(crate) fn prepare_read_write_path_owned(
    path: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<bool> {
    prepare_read_write_path_owned_with(path, uid, gid, fchown_fd)
}

fn prepare_read_write_path_owned_with(
    path: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
    own: impl FnOnce(&OwnedFd, Option<u32>, Option<u32>) -> Result<()>,
) -> Result<bool> {
    let (parent, name) = open_parent_directory(path, true, Mode::from_raw_mode(0o777))?
        .ok_or_else(|| miette::miette!("directory parent is unavailable: {}", path.display()))?;
    match rustix::fs::openat(
        &parent,
        &name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(_) => Ok(false),
        Err(rustix::io::Errno::NOENT) => {
            let created = match rustix::fs::mkdirat(&parent, &name, Mode::from_raw_mode(0o777)) {
                Ok(()) => true,
                Err(rustix::io::Errno::EXIST) => false,
                Err(error) => {
                    return Err(miette::miette!(
                        "failed to create directory {} safely: {error}",
                        path.display()
                    ));
                }
            };
            let directory = rustix::fs::openat(
                &parent,
                &name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|error| {
                miette::miette!(
                    "failed to verify created directory {} without following symlinks: {error}",
                    path.display()
                )
            })?;
            if created {
                own(&directory, uid, gid)?;
            }
            Ok(created)
        }
        Err(error) => Err(miette::miette!(
            "refusing unsafe directory path {}: {error}",
            path.display()
        )),
    }
}

/// Own one existing directory through a descriptor-relative, no-follow open.
pub(crate) fn chown_directory_no_follow(
    path: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<bool> {
    chown_directory_no_follow_with(path, uid, gid, fchown_fd)
}

fn chown_directory_no_follow_with(
    path: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
    own: impl FnOnce(&OwnedFd, Option<u32>, Option<u32>) -> Result<()>,
) -> Result<bool> {
    let Some((parent, name)) = open_parent_directory(path, false, Mode::empty())? else {
        return Ok(false);
    };
    let directory = match rustix::fs::openat(
        &parent,
        &name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(directory) => directory,
        Err(rustix::io::Errno::NOENT) => return Ok(false),
        Err(error) => {
            return Err(miette::miette!(
                "failed to open directory {} without following symlinks: {error}",
                path.display()
            ));
        }
    };
    own(&directory, uid, gid)?;
    Ok(true)
}

fn fchown_fd(fd: &OwnedFd, uid: Option<u32>, gid: Option<u32>) -> Result<()> {
    rustix::fs::fchown(
        fd,
        uid.map(rustix::fs::Uid::from_raw),
        gid.map(rustix::fs::Gid::from_raw),
    )
    .into_diagnostic()
}

fn open_parent_directory(
    path: &Path,
    create: bool,
    create_mode: Mode,
) -> Result<Option<(OwnedFd, OsString)>> {
    let name = path
        .file_name()
        .ok_or_else(|| miette::miette!("path has no final component: {}", path.display()))?
        .to_os_string();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    Ok(open_directory_path(parent, create, create_mode)?.map(|directory| (directory, name)))
}

fn open_directory_path(path: &Path, create: bool, create_mode: Mode) -> Result<Option<OwnedFd>> {
    let start = if path.is_absolute() { "/" } else { "." };
    let mut directory: OwnedFd = File::open(start).into_diagnostic()?.into();
    for component in path.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            Component::ParentDir | Component::Prefix(_) => {
                return Err(miette::miette!(
                    "path contains an unsafe component: {}",
                    path.display()
                ));
            }
        };
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
        directory = match rustix::fs::openat(&directory, name, flags, Mode::empty()) {
            Ok(next) => next,
            Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
            Err(rustix::io::Errno::NOENT) => {
                match rustix::fs::mkdirat(&directory, name, create_mode) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => {
                        return Err(miette::miette!(
                            "failed to create directory component '{}' in {}: {error}",
                            name.to_string_lossy(),
                            path.display()
                        ));
                    }
                }
                rustix::fs::openat(&directory, name, flags, Mode::empty()).map_err(|error| {
                    miette::miette!(
                        "failed to verify directory component '{}' in {} without following symlinks: {error}",
                        name.to_string_lossy(),
                        path.display()
                    )
                })?
            }
            Err(error) => {
                return Err(miette::miette!(
                    "refusing path {} with symlink or non-directory ancestor '{}': {error}",
                    path.display(),
                    name.to_string_lossy()
                ));
            }
        };
    }
    Ok(Some(directory))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;

    fn account_files(passwd: &str, group: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let passwd_path = root.join("passwd");
        let group_path = root.join("group");
        std::fs::write(&passwd_path, passwd).unwrap();
        std::fs::write(&group_path, group).unwrap();
        (dir, passwd_path, group_path)
    }

    #[test]
    fn resolves_all_oci_user_forms() {
        let (_dir, passwd, group) =
            account_files("app:x:1234:1235::/home/app:/bin/sh\n", "staff:x:2345:\n");
        let cases = [
            ("app", 1234, 1235, "app"),
            ("app:staff", 1234, 2345, "app"),
            ("app:2345", 1234, 2345, "app"),
            ("1234:staff", 1234, 2345, "1234"),
            ("1234", 1234, 1235, "1234"),
            ("1234:2345", 1234, 2345, "1234"),
        ];
        for (declaration, uid, gid, presentation) in cases {
            let identity =
                resolve_image_identity_at(declaration, "sha256:test", &passwd, &group).unwrap();
            assert_eq!((identity.uid, identity.gid), (uid, gid), "{declaration}");
            assert_eq!(identity.presentation_user, presentation, "{declaration}");
        }
    }

    #[test]
    fn numeric_pair_does_not_require_account_files() {
        let missing = Path::new("/definitely/missing/account-file");
        let identity =
            resolve_image_identity_at("1234:2345", "sha256:test", missing, missing).unwrap();
        assert_eq!((identity.uid, identity.gid), (1234, 2345));
    }

    #[test]
    fn rejects_empty_malformed_root_and_accountless_uid() {
        let (_dir, passwd, group) = account_files(
            "root:x:0:0::/root:/bin/sh\nrootish:x:0:1000::/:/bin/sh\n",
            "root:x:0:\n",
        );
        for declaration in [
            "",
            ":",
            "app:",
            "app:staff:extra",
            " app",
            "root",
            "rootish",
            "1234",
        ] {
            assert!(
                resolve_image_identity_at(declaration, "sha256:test", &passwd, &group).is_err(),
                "{declaration:?} should fail"
            );
        }
        assert!(resolve_image_identity_at("1234:0", "sha256:test", &passwd, &group).is_err());
    }

    #[test]
    fn rejects_malformed_and_duplicate_matching_account_entries() {
        let (_dir, passwd, group) = account_files(
            "app:x:1234:1235::/home/app:/bin/sh\nmalformed\n",
            "staff:x:2345:\n",
        );
        assert!(resolve_image_identity_at("app", "sha256:test", &passwd, &group).is_err());

        std::fs::write(
            &passwd,
            "app:x:1234:1235::/home/app:/bin/sh\nother:x:1234:1235::/home/other:/bin/sh\n",
        )
        .unwrap();
        assert!(resolve_image_identity_at("app", "sha256:test", &passwd, &group).is_err());

        std::fs::write(&passwd, "app:x:1234:1235::/home/app:/bin/sh\n").unwrap();
        std::fs::write(&group, "staff:x:2345:\nother:x:2345:\n").unwrap();
        assert!(resolve_image_identity_at("app:staff", "sha256:test", &passwd, &group).is_err());
    }

    #[test]
    fn rejects_symlink_non_regular_and_oversized_account_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let real = root.join("real-passwd");
        let link = root.join("passwd-link");
        std::fs::write(&real, "app:x:1234:1235::/:/bin/sh\n").unwrap();
        symlink(&real, &link).unwrap();
        assert!(resolve_image_identity_at("app", "sha256:test", &link, &real).is_err());
        assert!(resolve_image_identity_at("app", "sha256:test", &root, &real).is_err());

        let oversized = root.join("oversized");
        std::fs::write(
            &oversized,
            vec![b'x'; usize::try_from(MAX_ACCOUNT_FILE_SIZE + 1).unwrap()],
        )
        .unwrap();
        assert!(resolve_image_identity_at("app", "sha256:test", &oversized, &real).is_err());

        let long_line = root.join("long-line");
        let mut contents = "app:x:1234:1235::/home/app:/bin/sh".to_string();
        contents.push_str(&"x".repeat(MAX_ACCOUNT_LINE_SIZE));
        std::fs::write(&long_line, contents).unwrap();
        assert!(resolve_image_identity_at("app", "sha256:test", &long_line, &real).is_err());
    }

    #[test]
    fn rejects_account_file_with_symlink_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let real_dir = root.join("real-etc");
        let linked_dir = root.join("linked-etc");
        std::fs::create_dir(&real_dir).unwrap();
        std::fs::write(
            real_dir.join("passwd"),
            "app:x:1234:1235::/home/app:/bin/sh\n",
        )
        .unwrap();
        symlink(&real_dir, &linked_dir).unwrap();

        assert!(
            resolve_image_identity_at(
                "app:1235",
                "sha256:test",
                &linked_dir.join("passwd"),
                &real_dir.join("group"),
            )
            .is_err()
        );
    }

    #[test]
    fn image_resolution_does_not_modify_account_files() {
        let passwd_contents = "app:x:1234:1235::/home/app:/bin/sh\n";
        let group_contents = "staff:x:2345:\n";
        let (_dir, passwd, group) = account_files(passwd_contents, group_contents);

        resolve_image_identity_at("app:staff", "sha256:test", &passwd, &group).unwrap();

        assert_eq!(std::fs::read_to_string(passwd).unwrap(), passwd_contents);
        assert_eq!(std::fs::read_to_string(group).unwrap(), group_contents);
    }

    #[test]
    fn persisted_identity_is_reused_and_metadata_must_match() {
        let (dir, passwd, group) =
            account_files("app:x:1234:1235::/home/app:/bin/sh\n", "staff:x:2345:\n");
        let state = dir
            .path()
            .canonicalize()
            .unwrap()
            .join("state/agent-identity.json");
        let request = IdentityRequest::Image {
            image_user: "app".into(),
            image_id: "sha256:first".into(),
        };
        let identity =
            resolve_and_persist_at(Some(&request), &passwd, &group, &state, false, |_| Ok(()))
                .unwrap()
                .unwrap();
        assert_eq!((identity.uid, identity.gid), (1234, 1235));
        assert_eq!(std::fs::metadata(&state).unwrap().mode() & 0o777, 0o600);

        std::fs::write(&passwd, "app:x:9999:9999::/home/app:/bin/sh\n").unwrap();
        let restarted =
            resolve_and_persist_at(Some(&request), &passwd, &group, &state, false, |_| Ok(()))
                .unwrap()
                .unwrap();
        assert_eq!(restarted, identity);

        let changed = IdentityRequest::Image {
            image_user: "app".into(),
            image_id: "sha256:changed".into(),
        };
        assert!(
            resolve_and_persist_at(Some(&changed), &passwd, &group, &state, false, |_| Ok(()),)
                .is_err()
        );
    }

    #[test]
    fn missing_identity_source_preserves_legacy_behavior_without_state_access() {
        let inaccessible = Path::new("/definitely/missing/legacy-state");
        assert_eq!(
            resolve_and_persist_at(
                None,
                inaccessible,
                inaccessible,
                inaccessible,
                true,
                |_| Ok(()),
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn fixed_identity_is_persisted_and_checked_on_restart() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir
            .path()
            .canonicalize()
            .unwrap()
            .join("state/agent-identity.json");
        let request = IdentityRequest::Fixed {
            uid: 4321,
            gid: 5432,
            image_id: "sha256:fixed".into(),
        };
        let identity = resolve_and_persist_at(
            Some(&request),
            Path::new("/missing-passwd"),
            Path::new("/missing-group"),
            &state,
            false,
            |_| Ok(()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(identity.source, IdentitySource::Fixed);
        assert_eq!((identity.uid, identity.gid), (4321, 5432));
        assert_eq!(identity.image_id.as_deref(), Some("sha256:fixed"));

        let changed = IdentityRequest::Fixed {
            uid: 4321,
            gid: 9999,
            image_id: "sha256:fixed".into(),
        };
        assert!(
            resolve_and_persist_at(
                Some(&changed),
                Path::new("/missing-passwd"),
                Path::new("/missing-group"),
                &state,
                false,
                |_| Ok(()),
            )
            .is_err()
        );

        let changed_image = IdentityRequest::Fixed {
            uid: 4321,
            gid: 5432,
            image_id: "sha256:changed".into(),
        };
        assert!(
            resolve_and_persist_at(
                Some(&changed_image),
                Path::new("/missing-passwd"),
                Path::new("/missing-group"),
                &state,
                false,
                |_| Ok(()),
            )
            .is_err()
        );
    }

    #[test]
    fn id_map_parser_handles_full_map_gaps_and_overflow() {
        let full = parse_id_map("0 0 4294967295\n", "uid_map").unwrap();
        validate_id_is_mapped(0, &full, "uid_map").unwrap();
        validate_id_is_mapped(u32::MAX - 1, &full, "uid_map").unwrap();
        let error = validate_id_is_mapped(u32::MAX, &full, "uid_map").unwrap_err();
        assert!(error.to_string().contains("4294967295"));
        assert!(error.to_string().contains("uid_map"));

        let segmented = parse_id_map("0 100000 1000\n2000 200000 1000\n", "gid_map").unwrap();
        validate_id_is_mapped(2500, &segmented, "gid_map").unwrap();
        let error = validate_id_is_mapped(1500, &segmented, "gid_map").unwrap_err();
        assert!(error.to_string().contains("1500"));
        assert!(error.to_string().contains("gid_map"));

        assert!(parse_id_map("18446744073709551615 0 2\n", "uid_map").is_err());
        assert!(parse_id_map("0 0 0\n", "uid_map").is_err());
        assert!(parse_id_map("0 0\n", "uid_map").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn user_namespace_mapping_validation_accepts_alternate_paths() {
        let dir = tempfile::tempdir().unwrap();
        let uid_map = dir.path().join("uid_map");
        let gid_map = dir.path().join("gid_map");
        std::fs::write(&uid_map, "0 100000 65536\n").unwrap();
        std::fs::write(&gid_map, "0 200000 65536\n").unwrap();

        validate_user_namespace_mappings_at(1234, 2345, &uid_map, &gid_map).unwrap();
        let error =
            validate_user_namespace_mappings_at(70_000, 2345, &uid_map, &gid_map).unwrap_err();
        assert!(error.to_string().contains("70000"));
        assert!(error.to_string().contains("uid_map"));
    }

    #[test]
    fn mapping_failure_prevents_state_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir
            .path()
            .canonicalize()
            .unwrap()
            .join("state/agent-identity.json");
        let request = IdentityRequest::Fixed {
            uid: 4321,
            gid: 5432,
            image_id: "sha256:fixed".into(),
        };
        let error = resolve_and_persist_at(
            Some(&request),
            Path::new("/missing-passwd"),
            Path::new("/missing-group"),
            &state,
            false,
            |_| Err(miette::miette!("identity ID 4321 is not mapped by uid_map")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("uid_map"));
        assert!(!state.exists());
    }

    #[test]
    fn state_publication_is_no_replace_and_ignores_partial_temp() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir
            .path()
            .canonicalize()
            .unwrap()
            .join("state/agent-identity.json");
        let state = PersistedIdentity {
            version: IDENTITY_STATE_VERSION,
            identity: ResolvedAgentIdentity {
                uid: 4321,
                gid: 5432,
                presentation_user: "app".into(),
                source: IdentitySource::Image,
                image_id: Some("sha256:image".into()),
            },
            image_user: Some("app".into()),
        };
        std::fs::create_dir_all(state_path.parent().unwrap()).unwrap();
        std::fs::write(
            state_path
                .parent()
                .unwrap()
                .join(".agent-identity-partial.tmp"),
            b"partial",
        )
        .unwrap();

        persist_state(&state_path, &state, false).unwrap();
        persist_state(&state_path, &state, false).unwrap();
        assert_eq!(load_state(&state_path, false).unwrap(), Some(state.clone()));

        let mut conflicting = state;
        conflicting.identity.uid = 9999;
        assert!(persist_state(&state_path, &conflicting, false).is_err());
        assert_eq!(
            load_state(&state_path, false)
                .unwrap()
                .unwrap()
                .identity
                .uid,
            4321
        );
    }

    #[test]
    fn state_path_rejects_symlink_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let real = root.join("real");
        let linked = root.join("linked");
        std::fs::create_dir(&real).unwrap();
        symlink(&real, &linked).unwrap();
        let state_path = linked.join("nested/agent-identity.json");
        let state = PersistedIdentity {
            version: IDENTITY_STATE_VERSION,
            identity: ResolvedAgentIdentity {
                uid: 4321,
                gid: 5432,
                presentation_user: "4321".into(),
                source: IdentitySource::Fixed,
                image_id: Some("sha256:fixed".into()),
            },
            image_user: None,
        };

        assert!(persist_state(&state_path, &state, false).is_err());
        assert!(!real.join("nested/agent-identity.json").exists());
    }

    #[test]
    fn persisted_state_rejects_insecure_parent_mode() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir
            .path()
            .canonicalize()
            .unwrap()
            .join("state/agent-identity.json");
        let state = PersistedIdentity {
            version: IDENTITY_STATE_VERSION,
            identity: ResolvedAgentIdentity {
                uid: 4321,
                gid: 5432,
                presentation_user: "4321".into(),
                source: IdentitySource::Fixed,
                image_id: Some("sha256:fixed".into()),
            },
            image_user: None,
        };
        persist_state(&state_path, &state, false).unwrap();
        std::fs::set_permissions(
            state_path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        assert!(load_state(&state_path, false).is_err());
    }

    #[test]
    fn new_read_write_path_ownership_uses_open_descriptor_after_substitution() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let requested = root.join("requested");
        let moved = root.join("opened-directory");
        let substitution_target = root.join("substitution-target");
        std::fs::create_dir(&substitution_target).unwrap();
        let hook_called = std::cell::Cell::new(false);

        let created = prepare_read_write_path_owned_with(
            &requested,
            Some(1234),
            Some(2345),
            |fd, uid, gid| {
                let opened_inode = rustix::fs::fstat(fd).into_diagnostic()?.st_ino;
                std::fs::rename(&requested, &moved).into_diagnostic()?;
                symlink(&substitution_target, &requested).into_diagnostic()?;

                assert_eq!(opened_inode, std::fs::metadata(&moved).unwrap().ino());
                assert_ne!(opened_inode, std::fs::metadata(&requested).unwrap().ino());
                assert_eq!(uid, Some(1234));
                assert_eq!(gid, Some(2345));
                hook_called.set(true);
                Ok(())
            },
        )
        .unwrap();

        assert!(created);
        assert!(hook_called.get());
        assert!(
            std::fs::symlink_metadata(requested)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn existing_read_write_path_never_invokes_ownership_hook() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().canonicalize().unwrap().join("existing");
        std::fs::create_dir(&existing).unwrap();

        let created = prepare_read_write_path_owned_with(
            &existing,
            Some(1234),
            Some(2345),
            |_fd, _uid, _gid| panic!("existing path ownership must be preserved"),
        )
        .unwrap();

        assert!(!created);
    }

    #[test]
    fn sandbox_root_ownership_uses_descriptor_and_does_not_descend() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let temp_root = dir.path().canonicalize().unwrap();
        let sandbox = temp_root.join("sandbox");
        let moved = temp_root.join("opened-sandbox");
        let substitution_target = temp_root.join("substitution-target");
        std::fs::create_dir(&sandbox).unwrap();
        std::fs::write(sandbox.join("child"), b"unchanged").unwrap();
        std::fs::create_dir(&substitution_target).unwrap();
        let hook_count = std::cell::Cell::new(0);

        let opened =
            chown_directory_no_follow_with(&sandbox, Some(1234), Some(2345), |fd, uid, gid| {
                let opened_inode = rustix::fs::fstat(fd).into_diagnostic()?.st_ino;
                std::fs::rename(&sandbox, &moved).into_diagnostic()?;
                symlink(&substitution_target, &sandbox).into_diagnostic()?;

                assert_eq!(opened_inode, std::fs::metadata(&moved).unwrap().ino());
                assert_ne!(opened_inode, std::fs::metadata(&sandbox).unwrap().ino());
                assert_eq!(uid, Some(1234));
                assert_eq!(gid, Some(2345));
                hook_count.set(hook_count.get() + 1);
                Ok(())
            })
            .unwrap();

        assert!(opened);
        assert_eq!(hook_count.get(), 1);
        assert_eq!(std::fs::read(moved.join("child")).unwrap(), b"unchanged");
    }

    #[test]
    fn sandbox_root_ownership_rejects_symlink_ancestor() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let temp_root = dir.path().canonicalize().unwrap();
        let real = temp_root.join("real");
        let linked = temp_root.join("linked");
        std::fs::create_dir(&real).unwrap();
        std::fs::create_dir(real.join("sandbox")).unwrap();
        symlink(&real, &linked).unwrap();

        let error = chown_directory_no_follow_with(
            &linked.join("sandbox"),
            Some(1234),
            Some(2345),
            |_fd, _uid, _gid| panic!("symlink ancestor must be rejected before ownership"),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("symlink or non-directory ancestor")
        );
    }
}
