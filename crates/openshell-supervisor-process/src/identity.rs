// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver identity normalization and OCI `USER` resolution.

use crate::process::ResolvedProcessIdentity;
use miette::{IntoDiagnostic, Result};
use openshell_core::policy::SandboxPolicy;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const PASSWD_PATH: &str = "/etc/passwd";
const GROUP_PATH: &str = "/etc/group";
const MAX_ACCOUNT_FILE_SIZE: u64 = 1024 * 1024;
const MAX_ACCOUNT_LINE_SIZE: usize = 8 * 1024;
const MAX_ACCOUNT_FIELD_SIZE: usize = 1024;

/// Identity input selected by the active compute driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverIdentity {
    /// Platform-selected identity used by Kubernetes and `OpenShift`.
    Resolved { uid: u32, gid: u32 },
    /// Raw OCI `Config.User` selected by Docker and Podman.
    OciUser { declaration: String },
    /// Drivers with no authoritative identity metadata.
    None,
}

impl DriverIdentity {
    /// Normalize the protected driver environment into one identity variant.
    pub fn from_env() -> Result<Self> {
        let oci_user = optional_utf8_env(openshell_core::sandbox_env::OCI_IMAGE_USER)?;
        let uid = optional_nonempty_utf8_env(openshell_core::sandbox_env::SANDBOX_UID)?;
        let gid = optional_nonempty_utf8_env(openshell_core::sandbox_env::SANDBOX_GID)?;
        Self::from_values(oci_user, uid, gid)
    }

    fn from_values(
        oci_user: Option<String>,
        uid: Option<String>,
        gid: Option<String>,
    ) -> Result<Self> {
        // Resolved-identity drivers explicitly clear the OCI declaration so
        // an image-baked or user-supplied value cannot select the OCI path.
        // Preserve an empty declaration when no resolved pair is present:
        // Docker and Podman use that state to reject images without USER.
        let oci_user = if oci_user.as_deref() == Some("") && (uid.is_some() || gid.is_some()) {
            None
        } else {
            oci_user
        };

        match (oci_user, uid, gid) {
            (Some(declaration), None, None) => Ok(Self::OciUser { declaration }),
            (None, Some(uid), Some(gid)) => {
                let uid = uid.parse::<u32>().ok().filter(|uid| {
                    (openshell_policy::MIN_SANDBOX_UID..=openshell_policy::MAX_SANDBOX_UID)
                        .contains(uid)
                });
                let gid = gid.parse::<u32>().ok().filter(|gid| {
                    (openshell_policy::MIN_SANDBOX_UID..=openshell_policy::MAX_SANDBOX_UID)
                        .contains(gid)
                });
                let (Some(uid), Some(gid)) = (uid, gid) else {
                    return Err(miette::miette!(
                        "driver UID/GID must be numeric identities in range [{}, {}]",
                        openshell_policy::MIN_SANDBOX_UID,
                        openshell_policy::MAX_SANDBOX_UID
                    ));
                };
                Ok(Self::Resolved { uid, gid })
            }
            (None, None, None) => Ok(Self::None),
            (Some(_), _, _) => Err(miette::miette!(
                "{} conflicts with non-empty {}/{} driver identity",
                openshell_core::sandbox_env::OCI_IMAGE_USER,
                openshell_core::sandbox_env::SANDBOX_UID,
                openshell_core::sandbox_env::SANDBOX_GID
            )),
            (None, _, _) => Err(miette::miette!(
                "{} and {} must be supplied together",
                openshell_core::sandbox_env::SANDBOX_UID,
                openshell_core::sandbox_env::SANDBOX_GID
            )),
        }
    }
}

/// Apply a driver identity before any workload child becomes reachable.
pub fn resolve_process_identity(
    policy: &mut SandboxPolicy,
    driver_identity: &DriverIdentity,
) -> Result<ResolvedProcessIdentity> {
    match driver_identity {
        DriverIdentity::Resolved { uid, gid } => {
            policy.process.run_as_user = Some(uid.to_string());
            policy.process.run_as_group = Some(gid.to_string());
            // Kubernetes/OpenShift already supply numeric policy values and
            // retain their existing privilege-drop path.
            Ok(ResolvedProcessIdentity::default())
        }
        DriverIdentity::OciUser { declaration } => resolve_oci_process_identity_at(
            policy,
            declaration,
            Path::new(PASSWD_PATH),
            Path::new(GROUP_PATH),
        ),
        DriverIdentity::None => {
            // VM/offline drivers retain the pre-OCI per-field fallback. A
            // partial policy must never leave the omitted component at the
            // root supervisor identity.
            if policy
                .process
                .run_as_user
                .as_deref()
                .is_none_or(str::is_empty)
            {
                policy.process.run_as_user = Some("sandbox".into());
            }
            if policy
                .process
                .run_as_group
                .as_deref()
                .is_none_or(str::is_empty)
            {
                policy.process.run_as_group = Some("sandbox".into());
            }
            Ok(ResolvedProcessIdentity::default())
        }
    }
}

#[allow(clippy::similar_names)]
fn resolve_oci_process_identity_at(
    policy: &mut SandboxPolicy,
    declaration: &str,
    passwd_path: &Path,
    group_path: &Path,
) -> Result<ResolvedProcessIdentity> {
    let explicit_user = policy
        .process
        .run_as_user
        .as_deref()
        .is_some_and(|value| !value.is_empty());
    let explicit_group = policy
        .process
        .run_as_group
        .as_deref()
        .is_some_and(|value| !value.is_empty());

    if explicit_user && explicit_group {
        return Ok(ResolvedProcessIdentity::default());
    }

    let (oci_user, oci_group) = split_oci_declaration(declaration);
    let needs_primary_gid = !explicit_group && oci_group.is_none();
    let resolved_user = if !explicit_user || needs_primary_gid {
        Some(resolve_required_oci_user(
            oci_user,
            passwd_path,
            declaration,
            needs_primary_gid,
        )?)
    } else {
        None
    };

    let oci_uid = if explicit_user {
        None
    } else {
        Some(
            resolved_user
                .as_ref()
                .expect("omitted OCI user must have been resolved")
                .0,
        )
    };

    if !explicit_user {
        policy.process.run_as_user = Some(oci_user.to_string());
    }

    let oci_gid = if explicit_group {
        None
    } else {
        let (group_value, gid) = match oci_group {
            Some(group) if !group.is_empty() => {
                let gid = validate_oci_group(group, group_path, declaration)?;
                (group.to_string(), gid)
            }
            Some(_) => {
                return Err(miette::miette!(
                    "OCI USER '{declaration}' has an empty group component"
                ));
            }
            None => {
                let gid = resolved_user
                    .and_then(|(_, primary_gid)| primary_gid)
                    .ok_or_else(|| {
                    miette::miette!(
                        "OCI USER '{declaration}' uses a numeric UID without an explicit group, \
                         but /etc/passwd has no matching primary GID"
                    )
                })?;
                (gid.to_string(), gid)
            }
        };
        policy.process.run_as_group = Some(group_value);
        Some(gid)
    };

    Ok(ResolvedProcessIdentity::new(oci_uid, oci_gid))
}

fn split_oci_declaration(declaration: &str) -> (&str, Option<&str>) {
    declaration
        .split_once(':')
        .map_or((declaration, None), |(user, group)| (user, Some(group)))
}

fn resolve_required_oci_user(
    user: &str,
    passwd_path: &Path,
    declaration: &str,
    require_primary_gid: bool,
) -> Result<(u32, Option<u32>)> {
    if user.is_empty() {
        return Err(miette::miette!(
            "OCI USER is required because run_as_user is omitted"
        ));
    }
    validate_component(user, "OCI user")?;
    if user == "root" {
        return Err(miette::miette!("OCI USER '{declaration}' selects root"));
    }
    if let Ok(uid) = user.parse::<u32>() {
        if uid == 0 {
            return Err(miette::miette!("OCI USER '{declaration}' selects UID 0"));
        }
        let primary_gid = if require_primary_gid {
            find_passwd_by_uid(passwd_path, uid)?.map(|entry| entry.gid)
        } else {
            None
        };
        if primary_gid == Some(0) {
            return Err(miette::miette!(
                "OCI USER '{declaration}' resolves to prohibited primary GID 0"
            ));
        }
        return Ok((uid, primary_gid));
    }
    let entry = find_passwd_by_name(passwd_path, user)?
        .ok_or_else(|| miette::miette!("OCI USER name '{user}' was not found in /etc/passwd"))?;
    if entry.uid == 0 {
        return Err(miette::miette!(
            "OCI USER '{declaration}' resolves to prohibited UID 0"
        ));
    }
    if require_primary_gid && entry.gid == 0 {
        return Err(miette::miette!(
            "OCI USER '{declaration}' resolves to prohibited primary GID 0"
        ));
    }
    Ok((entry.uid, require_primary_gid.then_some(entry.gid)))
}

fn validate_oci_group(value: &str, group_path: &Path, declaration: &str) -> Result<u32> {
    validate_component(value, "OCI group")?;
    if value == "root" {
        return Err(miette::miette!(
            "OCI USER '{declaration}' selects root group"
        ));
    }
    let gid = if let Ok(gid) = value.parse::<u32>() {
        gid
    } else {
        find_group_by_name(group_path, value)?
            .ok_or_else(|| miette::miette!("OCI group '{value}' was not found in /etc/group"))?
            .gid
    };
    if gid == 0 {
        return Err(miette::miette!(
            "OCI USER '{declaration}' resolves to prohibited GID 0"
        ));
    }
    Ok(gid)
}

fn validate_component(value: &str, kind: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_ACCOUNT_FIELD_SIZE
        || value.trim() != value
        || value.chars().any(|ch| ch.is_control() || ch == ':')
    {
        return Err(miette::miette!("{kind} component '{value}' is malformed"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PasswdEntry {
    uid: u32,
    gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupEntry {
    gid: u32,
}

fn find_passwd_by_name(path: &Path, name: &str) -> Result<Option<PasswdEntry>> {
    find_unique(path, |fields| {
        (fields.first().copied() == Some(name)).then(|| parse_passwd(fields))
    })
}

fn find_passwd_by_uid(path: &Path, uid: u32) -> Result<Option<PasswdEntry>> {
    find_unique(path, |fields| {
        fields
            .get(2)
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|candidate| *candidate == uid)
            .map(|_| parse_passwd(fields))
    })
}

fn find_group_by_name(path: &Path, name: &str) -> Result<Option<GroupEntry>> {
    find_unique(path, |fields| {
        (fields.first().copied() == Some(name)).then(|| parse_group(fields))
    })
}

fn find_unique<T>(
    path: &Path,
    mut select: impl FnMut(&[&str]) -> Option<Result<T>>,
) -> Result<Option<T>> {
    let content = read_account_file(path)?;
    let mut found = None;
    for line in content.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() > MAX_ACCOUNT_LINE_SIZE {
            return Err(miette::miette!(
                "account file '{}' contains an oversized line",
                path.display()
            ));
        }
        let fields = line.split(':').collect::<Vec<_>>();
        if fields
            .iter()
            .any(|field| field.len() > MAX_ACCOUNT_FIELD_SIZE)
        {
            return Err(miette::miette!(
                "account file '{}' contains an oversized field",
                path.display()
            ));
        }
        let Some(candidate) = select(&fields) else {
            continue;
        };
        let candidate = candidate?;
        if found.replace(candidate).is_some() {
            return Err(miette::miette!(
                "account identity is ambiguous in '{}'",
                path.display()
            ));
        }
    }
    Ok(found)
}

fn parse_passwd(fields: &[&str]) -> Result<PasswdEntry> {
    if fields.len() != 7 {
        return Err(miette::miette!("matching /etc/passwd entry is malformed"));
    }
    Ok(PasswdEntry {
        uid: fields[2]
            .parse()
            .map_err(|_| miette::miette!("matching /etc/passwd UID is malformed"))?,
        gid: fields[3]
            .parse()
            .map_err(|_| miette::miette!("matching /etc/passwd GID is malformed"))?,
    })
}

fn parse_group(fields: &[&str]) -> Result<GroupEntry> {
    if fields.len() != 4 {
        return Err(miette::miette!("matching /etc/group entry is malformed"));
    }
    Ok(GroupEntry {
        gid: fields[2]
            .parse()
            .map_err(|_| miette::miette!("matching /etc/group GID is malformed"))?,
    })
}

fn read_account_file(path: &Path) -> Result<String> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .into_diagnostic()
        .map_err(|error| miette::miette!("failed to open '{}': {error}", path.display()))?;
    validate_account_file(&file, path)?;

    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_ACCOUNT_FILE_SIZE + 1)
        .read_to_end(&mut bytes)
        .into_diagnostic()?;
    if bytes.len() as u64 > MAX_ACCOUNT_FILE_SIZE {
        return Err(miette::miette!(
            "account file '{}' exceeds {MAX_ACCOUNT_FILE_SIZE} bytes",
            path.display()
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| miette::miette!("account file '{}' is not valid UTF-8", path.display()))
}

fn validate_account_file(file: &File, path: &Path) -> Result<()> {
    let metadata = file.metadata().into_diagnostic()?;
    if !metadata.is_file() {
        return Err(miette::miette!(
            "account path '{}' is not a regular file",
            path.display()
        ));
    }
    if metadata.len() > MAX_ACCOUNT_FILE_SIZE {
        return Err(miette::miette!(
            "account file '{}' exceeds {MAX_ACCOUNT_FILE_SIZE} bytes",
            path.display()
        ));
    }
    Ok(())
}

fn optional_utf8_env(name: &str) -> Result<Option<String>> {
    std::env::var_os(name)
        .map(|value| {
            value
                .into_string()
                .map_err(|_| miette::miette!("{name} is not valid UTF-8"))
        })
        .transpose()
}

fn optional_nonempty_utf8_env(name: &str) -> Result<Option<String>> {
    Ok(optional_utf8_env(name)?.filter(|value| !value.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::policy::SandboxPolicy;
    use std::fs;
    use tempfile::tempdir;

    fn account_files(
        passwd: &str,
        group: &str,
    ) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let passwd_path = dir.path().join("passwd");
        let group_path = dir.path().join("group");
        fs::write(&passwd_path, passwd).unwrap();
        fs::write(&group_path, group).unwrap();
        (dir, passwd_path, group_path)
    }

    fn policy(user: Option<&str>, group: Option<&str>) -> SandboxPolicy {
        let mut policy = SandboxPolicy {
            version: 1,
            filesystem: openshell_core::policy::FilesystemPolicy::default(),
            network: openshell_core::policy::NetworkPolicy::default(),
            landlock: openshell_core::policy::LandlockPolicy::default(),
            process: openshell_core::policy::ProcessPolicy::default(),
        };
        policy.process.run_as_user = user.map(str::to_string);
        policy.process.run_as_group = group.map(str::to_string);
        policy
    }

    #[test]
    fn per_field_policy_precedence_resolves_complete_pair() {
        let (_dir, passwd, group) = account_files(
            "app:x:1234:1235::/home/app:/bin/sh\nsandbox:x:2000:2001::/sandbox:/bin/sh\n",
            "staff:x:1235:\nsandbox:x:2001:\n",
        );
        let cases = [
            (
                Some("2000"),
                Some("2001"),
                "root",
                "2000",
                "2001",
                None,
                None,
            ),
            (
                Some("2000"),
                None,
                "app:staff",
                "2000",
                "staff",
                None,
                Some(1235),
            ),
            (
                None,
                Some("2001"),
                "app:root",
                "app",
                "2001",
                Some(1234),
                None,
            ),
            (
                None,
                None,
                "app:staff",
                "app",
                "staff",
                Some(1234),
                Some(1235),
            ),
            (None, None, "app", "app", "1235", Some(1234), Some(1235)),
        ];
        for (
            user,
            group_name,
            declaration,
            expected_user,
            expected_group,
            resolved_uid,
            resolved_gid,
        ) in cases
        {
            let mut policy = policy(user, group_name);
            let resolved =
                resolve_oci_process_identity_at(&mut policy, declaration, &passwd, &group).unwrap();
            assert_eq!(policy.process.run_as_user.as_deref(), Some(expected_user));
            assert_eq!(policy.process.run_as_group.as_deref(), Some(expected_group));
            assert_eq!(resolved.uid(), resolved_uid);
            assert_eq!(resolved.gid(), resolved_gid);
        }
    }

    #[test]
    fn numeric_pair_does_not_require_account_entries() {
        let dir = tempdir().unwrap();
        let passwd = dir.path().join("missing-passwd");
        let group = dir.path().join("missing-group");
        let mut policy = policy(None, None);
        let resolved =
            resolve_oci_process_identity_at(&mut policy, "1234:1235", &passwd, &group).unwrap();
        assert_eq!(policy.process.run_as_user.as_deref(), Some("1234"));
        assert_eq!(policy.process.run_as_group.as_deref(), Some("1235"));
        assert_eq!(
            resolved,
            ResolvedProcessIdentity::new(Some(1234), Some(1235))
        );
    }

    #[test]
    fn explicit_identity_is_preserved_without_inspecting_oci_or_accounts() {
        let dir = tempdir().unwrap();
        let mut policy = policy(Some("sandbox"), Some("sandbox"));

        let resolved = resolve_oci_process_identity_at(
            &mut policy,
            "root:root",
            &dir.path().join("missing-passwd"),
            &dir.path().join("missing-group"),
        )
        .unwrap();

        assert_eq!(policy.process.run_as_user.as_deref(), Some("sandbox"));
        assert_eq!(policy.process.run_as_group.as_deref(), Some("sandbox"));
        assert_eq!(resolved, ResolvedProcessIdentity::default());
    }

    #[test]
    fn driver_identity_inputs_are_mutually_exclusive_and_complete() {
        assert_eq!(
            DriverIdentity::from_values(Some("app".into()), None, None).unwrap(),
            DriverIdentity::OciUser {
                declaration: "app".into()
            }
        );
        assert_eq!(
            DriverIdentity::from_values(None, Some("1234".into()), Some("1235".into())).unwrap(),
            DriverIdentity::Resolved {
                uid: 1234,
                gid: 1235
            }
        );
        assert_eq!(
            DriverIdentity::from_values(
                Some(String::new()),
                Some("1234".into()),
                Some("1235".into())
            )
            .unwrap(),
            DriverIdentity::Resolved {
                uid: 1234,
                gid: 1235
            }
        );
        assert_eq!(
            DriverIdentity::from_values(Some(String::new()), None, None).unwrap(),
            DriverIdentity::OciUser {
                declaration: String::new()
            }
        );
        assert_eq!(
            DriverIdentity::from_values(None, None, None).unwrap(),
            DriverIdentity::None
        );
        assert!(
            DriverIdentity::from_values(
                Some("app".into()),
                Some("1234".into()),
                Some("1235".into())
            )
            .is_err()
        );
        assert!(DriverIdentity::from_values(None, Some("1234".into()), None).is_err());
    }

    #[test]
    fn no_driver_identity_completes_partial_policy_with_sandbox() {
        let cases = [
            (None, Some("staff"), "sandbox", "staff"),
            (Some("app"), None, "app", "sandbox"),
            (None, None, "sandbox", "sandbox"),
            (Some("app"), Some("staff"), "app", "staff"),
        ];

        for (user, group, expected_user, expected_group) in cases {
            let mut policy = policy(user, group);
            let resolved = resolve_process_identity(&mut policy, &DriverIdentity::None).unwrap();

            assert_eq!(policy.process.run_as_user.as_deref(), Some(expected_user));
            assert_eq!(policy.process.run_as_group.as_deref(), Some(expected_group));
            assert_eq!(resolved, ResolvedProcessIdentity::default());
        }
    }

    #[test]
    fn numeric_uid_uses_passwd_primary_gid() {
        let (_dir, passwd, group) = account_files("app:x:1234:4321::/home/app:/bin/sh\n", "");
        let mut policy = policy(None, None);
        let resolved =
            resolve_oci_process_identity_at(&mut policy, "1234", &passwd, &group).unwrap();
        assert_eq!(policy.process.run_as_group.as_deref(), Some("4321"));
        assert_eq!(
            resolved,
            ResolvedProcessIdentity::new(Some(1234), Some(4321))
        );
    }

    #[test]
    fn missing_unknown_ambiguous_and_root_identities_fail() {
        let (_dir, passwd, group) = account_files(
            "app:x:1234:1235::/home/app:/bin/sh\napp:x:2234:2235::/home/app2:/bin/sh\n",
            "staff:x:1235:\nstaff:x:2235:\n",
        );
        for declaration in ["", "unknown", "app", "9999", "0:1235", "1234:0"] {
            let mut policy = policy(None, None);
            assert!(
                resolve_oci_process_identity_at(&mut policy, declaration, &passwd, &group).is_err(),
                "{declaration:?} unexpectedly resolved"
            );
        }
    }

    #[test]
    fn selected_component_is_validated_independently() {
        let (_dir, passwd, group) =
            account_files("app:x:1234:1235::/home/app:/bin/sh\n", "staff:x:1235:\n");

        let mut explicit_user = policy(Some("1234"), None);
        let resolved =
            resolve_oci_process_identity_at(&mut explicit_user, "root:staff", &passwd, &group)
                .unwrap();
        assert_eq!(explicit_user.process.run_as_user.as_deref(), Some("1234"));
        assert_eq!(explicit_user.process.run_as_group.as_deref(), Some("staff"));
        assert_eq!(resolved, ResolvedProcessIdentity::new(None, Some(1235)));

        let mut explicit_group = policy(None, Some("1235"));
        let resolved =
            resolve_oci_process_identity_at(&mut explicit_group, "app:root", &passwd, &group)
                .unwrap();
        assert_eq!(explicit_group.process.run_as_user.as_deref(), Some("app"));
        assert_eq!(explicit_group.process.run_as_group.as_deref(), Some("1235"));
        assert_eq!(resolved, ResolvedProcessIdentity::new(Some(1234), None));
    }

    #[test]
    fn named_oci_components_mapping_to_root_are_rejected() {
        let (_dir, passwd, group) = account_files(
            "root_alias:x:0:1235::/root:/bin/sh\napp:x:1234:1235::/home/app:/bin/sh\n",
            "root_alias:x:0:\nstaff:x:1235:\n",
        );

        let mut root_user = policy(None, None);
        assert!(
            resolve_oci_process_identity_at(&mut root_user, "root_alias:staff", &passwd, &group)
                .is_err()
        );

        let mut root_group = policy(None, None);
        assert!(
            resolve_oci_process_identity_at(&mut root_group, "app:root_alias", &passwd, &group)
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn account_file_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;

        let (_dir, passwd, group) =
            account_files("app:x:1234:1235::/home/app:/bin/sh\n", "staff:x:1235:\n");
        let link = passwd.with_file_name("passwd-link");
        symlink(&passwd, &link).unwrap();

        let mut policy = policy(None, None);
        assert!(resolve_oci_process_identity_at(&mut policy, "app:staff", &link, &group).is_err());
    }
}
