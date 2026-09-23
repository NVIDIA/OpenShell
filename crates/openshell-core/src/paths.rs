// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Path utilities: XDG config directory resolution, permission helpers, and
//! lexical path normalization.
//!
//! All `OpenShell` crates should use [`xdg_config_dir`] from this module instead
//! of reimplementing the XDG lookup. The permission helpers ensure that
//! sensitive files (private keys, tokens) and the directories containing them
//! are created with restrictive modes. [`normalize_path`] performs purely
//! lexical normalization (no filesystem access, no symlink resolution).

use miette::{IntoDiagnostic, Result, WrapErr};
use std::path::{Path, PathBuf};

/// Resolve the XDG config base directory.
///
/// Returns `$XDG_CONFIG_HOME` if set, otherwise `$HOME/.config`.
pub fn xdg_config_dir() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(path));
    }
    #[cfg(target_os = "windows")]
    if let Ok(path) = std::env::var("APPDATA") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var("HOME")
        .into_diagnostic()
        .wrap_err("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config"))
}

/// The top-level `OpenShell` config directory: `$XDG_CONFIG_HOME/openshell/`.
pub fn openshell_config_dir() -> Result<PathBuf> {
    Ok(xdg_config_dir()?.join("openshell"))
}

/// Resolve the XDG state base directory.
///
/// Returns `$XDG_STATE_HOME` if set, otherwise `$HOME/.local/state`.
pub fn xdg_state_dir() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("XDG_STATE_HOME") {
        return Ok(PathBuf::from(path));
    }
    #[cfg(target_os = "windows")]
    if let Ok(path) = std::env::var("LOCALAPPDATA") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var("HOME")
        .into_diagnostic()
        .wrap_err("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local").join("state"))
}

/// The top-level `OpenShell` state directory: `$XDG_STATE_HOME/openshell/`.
pub fn openshell_state_dir() -> Result<PathBuf> {
    Ok(xdg_state_dir()?.join("openshell"))
}

/// Resolve the XDG data base directory.
///
/// Returns `$XDG_DATA_HOME` if set, otherwise `$HOME/.local/share`.
pub fn xdg_data_dir() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("XDG_DATA_HOME") {
        return Ok(PathBuf::from(path));
    }
    #[cfg(target_os = "windows")]
    if let Ok(path) = std::env::var("LOCALAPPDATA") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var("HOME")
        .into_diagnostic()
        .wrap_err("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local").join("share"))
}

/// Create a directory (and parents) with owner-only permissions (`0o700` on
/// Unix; an owner-only DACL with inheritance disabled on Windows).
///
/// This should be used for any directory that contains sensitive material
/// (tokens, private keys, certificates).
pub fn create_dir_restricted(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {}", path.display()))?;
    set_dir_owner_only(path)?;
    Ok(())
}

/// Restrict a directory to owner-only access: `0o700` on Unix, or an
/// owner-only DACL (with inherited ACEs stripped, and the ACE propagated to
/// children) on Windows.
pub fn set_dir_owner_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to set permissions on {}", path.display()))?;
    }
    #[cfg(windows)]
    windows_acl::restrict_to_current_user(path, true)?;
    Ok(())
}

/// Restrict a file to owner-only read/write: `0o600` on Unix, or an
/// owner-only DACL (with inherited ACEs stripped) on Windows.
pub fn set_file_owner_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to set permissions on {}", path.display()))?;
    }
    #[cfg(windows)]
    windows_acl::restrict_to_current_user(path, false)?;
    Ok(())
}

/// Ensure the parent directory of `path` exists with restricted permissions.
///
/// Equivalent to `create_dir_restricted(path.parent())` but handles the case
/// where `path` has no parent gracefully.
pub fn ensure_parent_dir_restricted(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_restricted(parent)?;
    }
    Ok(())
}

/// Check whether a file has permissions that are too open.
///
/// On Unix, returns `true` if the file has group or other read/write/execute
/// bits set, and `false` if the file's metadata cannot be read. On Windows,
/// returns `true` if the file's DACL grants access to any trustee other than
/// the current user, and also `true` (fails closed) if the ACL cannot be
/// inspected at all -- see the Windows doc comment below.
#[cfg(unix)]
pub fn is_file_permissions_too_open(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o077 != 0)
}

/// Check whether a file has permissions that are too open.
///
/// See the Unix doc comment above for the cross-platform contract. A Win32
/// inspection failure (missing `READ_CONTROL`, an invalid ACL, a token-query
/// failure, etc.) is treated as too open rather than safe: `unwrap_or(false)`
/// would turn every such failure into a security false negative, so this
/// fails closed instead.
#[cfg(windows)]
pub fn is_file_permissions_too_open(path: &Path) -> bool {
    windows_acl::has_foreign_trustee(path).unwrap_or(true)
}

/// Windows ACL/DACL implementation of the owner-only permission helpers
/// above. Confined to this submodule so the `unsafe` FFI surface stays out
/// of the rest of the crate, matching the precedent set by
/// `openshell-driver-mxc`'s ETW consumer.
#[cfg(windows)]
mod windows_acl {
    #![allow(unsafe_code)]

    use miette::{IntoDiagnostic, Result, WrapErr};
    use std::path::Path;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GetNamedSecurityInfoW, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW,
        SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetTokenInformation,
        IsValidAcl, NO_INHERITANCE, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows::Win32::System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
        ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::{HSTRING, PWSTR};

    /// An owned, `TOKEN_USER`-aligned buffer (backed by `Vec<u64>` purely for
    /// its alignment guarantee; the contents are opaque bytes filled in by
    /// `GetTokenInformation`).
    struct TokenUserBuf(Vec<u64>);

    /// Fetch the current process's user token info as an aligned buffer.
    ///
    /// Callers get the `PSID` out via [`sid_from_token_info`], which borrows
    /// from the returned buffer; keep it alive for as long as the `PSID` is
    /// used.
    fn current_user_token_info() -> Result<TokenUserBuf> {
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token)
                .into_diagnostic()
                .wrap_err("failed to open process token")?;
            let _guard = HandleGuard(token);

            let mut needed = 0u32;
            // First call is expected to fail with ERROR_INSUFFICIENT_BUFFER;
            // we only want the required buffer size out of it.
            let _ = GetTokenInformation(token, TokenUser, None, 0, &raw mut needed);
            if needed == 0 {
                return Err(miette::miette!("GetTokenInformation returned no size"));
            }
            let words = (needed as usize).div_ceil(size_of::<u64>());
            let mut buf = TokenUserBuf(vec![0u64; words]);
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.0.as_mut_ptr().cast()),
                needed,
                &raw mut needed,
            )
            .into_diagnostic()
            .wrap_err("failed to read current process token user")?;
            Ok(buf)
        }
    }

    /// Extract the `PSID` from a `TOKEN_USER` buffer produced by
    /// [`current_user_token_info`]. The `PSID` borrows from `buf`.
    fn sid_from_token_info(buf: &TokenUserBuf) -> PSID {
        // SAFETY: `buf` was sized and filled by `GetTokenInformation` for
        // `TokenUser` in `current_user_token_info`, and `Vec<u64>`'s 8-byte
        // alignment satisfies `TOKEN_USER`'s alignment requirement.
        let token_user = unsafe { &*buf.0.as_ptr().cast::<TOKEN_USER>() };
        token_user.User.Sid
    }

    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a valid handle owned by this guard.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    struct LocalFreeGuard(*mut core::ffi::c_void);
    impl Drop for LocalFreeGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was allocated by a Win32 API documented to
                // return LocalAlloc-owned memory (e.g. `SetEntriesInAclW`).
                let _ = unsafe { LocalFree(Some(HLOCAL(self.0))) };
            }
        }
    }

    /// Overwrite `path`'s DACL with a single, non-inherited ACE granting full
    /// control to the current user, stripping any inherited ACEs. `is_dir`
    /// controls whether the ACE propagates to children (directories only).
    /// When `path` has a foreign owner, ownership is also claimed; an object
    /// whose owner we cannot take produces an error rather than silently
    /// leaving their implicit `WRITE_DAC` right intact.
    pub(super) fn restrict_to_current_user(path: &Path, is_dir: bool) -> Result<()> {
        let token_info = current_user_token_info()?;
        let sid = sid_from_token_info(&token_info);

        let path_hstring = HSTRING::from(path.as_os_str());

        // Query the current owner to decide whether to include
        // OWNER_SECURITY_INFORMATION in the upcoming SetNamedSecurityInfoW
        // call. Requesting it unconditionally fails with ACCESS_DENIED
        // (0x80070005) when the current user already owns the file, because
        // WRITE_OWNER is not implied by being the object's owner.
        let mut current_owner = PSID::default();
        let mut owner_sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `path_hstring` is valid for the call; out-params are simple
        // pointers filled by the API on success. The security descriptor is
        // LocalAlloc-owned and freed below.
        unsafe {
            GetNamedSecurityInfoW(
                PWSTR::from_raw(path_hstring.as_ptr().cast_mut()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                Some(&raw mut current_owner),
                None,
                None,
                None,
                &raw mut owner_sd,
            )
        }
        .ok()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to query owner of {}", path.display()))?;
        let _owner_sd_guard = LocalFreeGuard(owner_sd.0);

        // SAFETY: both SIDs come from Windows APIs and are valid for this block.
        let already_owned = unsafe { EqualSid(sid, current_owner) }.is_ok();

        let trustee = TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: PWSTR(sid.0.cast()),
            ..Default::default()
        };

        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS.0,
            grfAccessMode: SET_ACCESS,
            grfInheritance: if is_dir {
                SUB_CONTAINERS_AND_OBJECTS_INHERIT
            } else {
                NO_INHERITANCE
            },
            Trustee: trustee,
        };

        let mut new_acl: *mut ACL = core::ptr::null_mut();
        // SAFETY: `entry` is a valid, fully-initialized EXPLICIT_ACCESS_W
        // whose Trustee SID borrows from `token_info`, kept alive for this
        // call. `new_acl` receives a LocalAlloc-owned pointer on success.
        unsafe { SetEntriesInAclW(Some(&[entry]), None, &raw mut new_acl) }
            .ok()
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to build ACL for {}", path.display()))?;
        let _acl_guard = LocalFreeGuard(new_acl.cast());

        // Include OWNER_SECURITY_INFORMATION only when the path has a foreign
        // owner. When the current user is already the owner the flag is
        // unnecessary and fails with ACCESS_DENIED on standard credentials.
        // When the owner is foreign we must either take ownership or reject
        // the path: a DACL-only update leaves the foreign owner's implicit
        // WRITE_DAC right intact, letting them later replace this DACL
        // (https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object).
        let security_info = if already_owned {
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION
        };
        let owner_arg = if already_owned { None } else { Some(sid) };

        // SAFETY: `path_hstring` is a valid, NUL-terminated wide string for
        // the lifetime of this call; `new_acl` is a valid ACL just built
        // above; `sid` borrows from `token_info`, kept alive for this call.
        // `PROTECTED_DACL_SECURITY_INFORMATION` strips inherited ACEs.
        unsafe {
            SetNamedSecurityInfoW(
                PWSTR::from_raw(path_hstring.as_ptr().cast_mut()),
                SE_FILE_OBJECT,
                security_info,
                owner_arg,
                None,
                Some(new_acl),
                None,
            )
        }
        .ok()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to set owner-only ACL on {}", path.display()))?;

        Ok(())
    }

    /// Test-only: explicitly set a NULL DACL on `path`, the Win32 API's own
    /// documented "grant everyone full access" state. Used to regression-test
    /// that [`has_foreign_trustee`] treats a NULL DACL as too open rather
    /// than conflating it with an unreadable/invalid ACL.
    #[cfg(test)]
    pub(super) fn set_null_dacl_for_test(path: &Path) -> Result<()> {
        let path_hstring = HSTRING::from(path.as_os_str());
        // SAFETY: `path_hstring` is valid for the duration of this call;
        // passing `None` for pdacl with `DACL_SECURITY_INFORMATION` set
        // explicitly requests a NULL DACL, per the documented Win32 contract.
        unsafe {
            SetNamedSecurityInfoW(
                PWSTR::from_raw(path_hstring.as_ptr().cast_mut()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
            )
        }
        .ok()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to set a NULL DACL on {}", path.display()))
    }

    /// Test-only: set a DACL containing a single `ACCESS_ALLOWED_OBJECT_ACE`
    /// (rather than the plain `ACCESS_ALLOWED_ACE` [`restrict_to_current_user`]
    /// writes) granting the current user access. Used to regression-test that
    /// [`has_foreign_trustee`] conservatively flags the non-basic
    /// access-allow ACE layouts (object/callback/callback-object) it doesn't
    /// parse, instead of silently skipping them as if they were a
    /// non-granting type like deny/audit.
    #[cfg(test)]
    pub(super) fn set_object_ace_dacl_for_test(path: &Path) -> Result<()> {
        use windows::Win32::Security::{
            ACE_FLAGS, ACL_REVISION, AddAccessAllowedObjectAce, InitializeAcl,
        };

        let token_info = current_user_token_info()?;
        let sid = sid_from_token_info(&token_info);

        // Oversized fixed buffer: plenty of room for an ACL header plus one
        // object ACE (which is wider than a plain ACE but still well under
        // 1 KiB even with a SID). Backed by `Vec<u64>` purely for its 8-byte
        // alignment guarantee, matching `TokenUserBuf` above -- `ACL` has a
        // stricter alignment than a `Vec<u8>` buffer provides.
        let mut acl_buf = vec![0u64; 128];
        let acl_len_bytes = size_of_val(acl_buf.as_slice());
        let acl_ptr = acl_buf.as_mut_ptr().cast::<ACL>();
        let acl_len = u32::try_from(acl_len_bytes).expect("test buffer size fits in u32");
        // SAFETY: `acl_ptr` points at `acl_len` bytes of writable memory
        // that outlives this call (owned by `acl_buf`, alive until this
        // function returns).
        unsafe { InitializeAcl(acl_ptr, acl_len, ACL_REVISION) }
            .into_diagnostic()
            .wrap_err("failed to initialize test ACL")?;
        // SAFETY: `acl_ptr` was just initialized above and has room for one
        // more ACE; `sid` borrows from `token_info`, kept alive for this
        // call. Passing `None` for both GUIDs still produces an ACE typed
        // `ACCESS_ALLOWED_OBJECT_ACE_TYPE` per the documented Win32 contract,
        // which is exactly the non-basic layout under test.
        unsafe {
            AddAccessAllowedObjectAce(
                acl_ptr,
                ACL_REVISION,
                ACE_FLAGS(0),
                FILE_ALL_ACCESS.0,
                None,
                None,
                sid,
            )
        }
        .into_diagnostic()
        .wrap_err("failed to add object ACE to test ACL")?;

        let path_hstring = HSTRING::from(path.as_os_str());
        // SAFETY: `path_hstring` is valid for the duration of this call;
        // `acl_ptr` is a valid, fully-built ACL from the calls above.
        unsafe {
            SetNamedSecurityInfoW(
                PWSTR::from_raw(path_hstring.as_ptr().cast_mut()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(acl_ptr),
                None,
            )
        }
        .ok()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to set an object-ACE DACL on {}", path.display()))
    }

    /// Returns `true` if `path`'s owner is not the current user, or if its
    /// DACL grants access to any trustee other than the current user.
    /// Returns `None` if the owner or ACL could not be read.
    pub(super) fn has_foreign_trustee(path: &Path) -> Option<bool> {
        let token_info = current_user_token_info().ok()?;
        let user_sid = sid_from_token_info(&token_info);

        let path_hstring = HSTRING::from(path.as_os_str());
        let mut owner: PSID = PSID::default();
        let mut dacl: *mut ACL = core::ptr::null_mut();
        let mut security_descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `path_hstring` is valid for the call; the out-params are
        // simple pointers filled in by the API on success. The security
        // descriptor (which both `owner` and `dacl` point into) is
        // LocalAlloc-owned and freed below.
        let status = unsafe {
            GetNamedSecurityInfoW(
                PWSTR::from_raw(path_hstring.as_ptr().cast_mut()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&raw mut owner),
                None,
                Some(&raw mut dacl),
                None,
                &raw mut security_descriptor,
            )
        };
        status.ok().ok()?;
        let _sd_guard = LocalFreeGuard(security_descriptor.0);

        // A foreign owner has implicit WRITE_DAC rights and can replace the
        // DACL at any time, so reject the path regardless of what the DACL
        // currently says.
        // SAFETY: both SIDs come from Windows APIs and are valid for this call.
        let owner_is_current_user = unsafe { EqualSid(user_sid, owner) }.is_ok();
        if !owner_is_current_user {
            return Some(true);
        }

        // A NULL DACL is a real, distinct state from "unreadable ACL": per
        // the Win32 contract, it means the object grants full access to
        // everyone -- the most permissive state possible -- so it must be
        // flagged as too open, not treated as safe.
        if dacl.is_null() {
            return Some(true);
        }
        if unsafe { !IsValidAcl(dacl).as_bool() } {
            return None;
        }

        let mut size_info = ACL_SIZE_INFORMATION::default();
        // SAFETY: `dacl` was just validated above.
        unsafe {
            GetAclInformation(
                dacl,
                (&raw mut size_info).cast(),
                u32::try_from(size_of::<ACL_SIZE_INFORMATION>())
                    .expect("ACL_SIZE_INFORMATION size fits in u32"),
                AclSizeInformation,
            )
        }
        .ok()?;

        for index in 0..size_info.AceCount {
            let mut ace_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
            // SAFETY: `dacl` is valid and `index` is within `AceCount`.
            if unsafe { GetAce(dacl, index, &raw mut ace_ptr) }.is_err() {
                continue;
            }
            // SAFETY: `GetAce` returned a pointer to a valid ACE header.
            let header = unsafe { &*ace_ptr.cast::<ACE_HEADER>() };
            let ace_type = u32::from(header.AceType);
            if ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE
                || ace_type == ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                || ace_type == ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
            {
                // Windows also defines access-allowed object, callback, and
                // callback-object ACE variants (each with a different, wider
                // layout than plain ACCESS_ALLOWED_ACE), any of which may
                // grant rights to a foreign trustee. This audit doesn't parse
                // their layouts, so treat their mere presence as too open
                // rather than silently skip them -- a false positive here is
                // an unnecessary re-tightening, but a false negative is a
                // security hole. See the ACE type table:
                // https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
                return Some(true);
            }
            if ace_type != ACCESS_ALLOWED_ACE_TYPE {
                // Deny/audit/alarm ACE types don't grant access; skip them
                // for this "is anyone but me granted access" check.
                continue;
            }
            // SAFETY: header.AceType confirms this is an ACCESS_ALLOWED_ACE.
            let ace = unsafe { &*ace_ptr.cast::<ACCESS_ALLOWED_ACE>() };
            let ace_sid = PSID((&raw const ace.SidStart).cast_mut().cast());
            // SAFETY: both SIDs come from Windows APIs (`GetTokenInformation`
            // and `GetAce`) and are valid for the duration of this call.
            let is_owner = unsafe { EqualSid(user_sid, ace_sid) }.is_ok();
            if !is_owner {
                return Some(true);
            }
        }
        Some(false)
    }

    /// Test-only: returns `true` if `path`'s current owner SID equals the
    /// current process's user SID. Used to regression-test that
    /// [`restrict_to_current_user`] actually takes ownership of the object,
    /// not just its DACL.
    #[cfg(test)]
    pub(super) fn owner_is_current_user_for_test(path: &Path) -> Result<bool> {
        let token_info = current_user_token_info()?;
        let expected_sid = sid_from_token_info(&token_info);

        let path_hstring = HSTRING::from(path.as_os_str());
        let mut owner = PSID::default();
        let mut security_descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `path_hstring` is valid for the call; the out-params are
        // simple pointers filled in by the API on success. The security
        // descriptor `owner` points into is LocalAlloc-owned and freed below.
        let status = unsafe {
            GetNamedSecurityInfoW(
                PWSTR::from_raw(path_hstring.as_ptr().cast_mut()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                Some(&raw mut owner),
                None,
                None,
                None,
                &raw mut security_descriptor,
            )
        };
        status
            .ok()
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to query owner of {}", path.display()))?;
        let _sd_guard = LocalFreeGuard(security_descriptor.0);

        // SAFETY: both SIDs come from Windows APIs (`GetTokenInformation` and
        // `GetNamedSecurityInfoW`) and are valid for the duration of this
        // call.
        Ok(unsafe { EqualSid(expected_sid, owner) }.is_ok())
    }
}

/// Normalize a filesystem path by collapsing redundant separators
/// and removing trailing slashes, without requiring the path to exist on disk.
///
/// This is a lexical normalization only — it does NOT resolve symlinks or
/// check the filesystem. `..` components are preserved verbatim; callers that
/// need to reject parent traversal must validate separately. The normalized
/// representation always uses `/` so sandbox policy paths are host-independent.
pub fn normalize_path(path: &str) -> String {
    use std::path::Component;

    let p = Path::new(path);
    let mut normalized = PathBuf::new();
    for component in p.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            #[allow(clippy::path_buf_push_overwrite)]
            Component::RootDir => normalized.push("/"),
            Component::CurDir => {} // skip "."
            Component::ParentDir => {
                // Keep ".." — validation will catch it separately
                normalized.push("..");
            }
            Component::Normal(c) => normalized.push(c),
        }
    }
    let normalized = normalized.to_string_lossy();
    #[cfg(target_os = "windows")]
    {
        normalized.replace('\\', "/")
    }
    #[cfg(not(target_os = "windows"))]
    {
        normalized.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xdg_config_dir_respects_env() {
        // This test checks the logic — actual env var mutation is unsafe so
        // we rely on the integration tests in openshell-bootstrap for full
        // round-trip testing.
        let result = xdg_config_dir();
        assert!(result.is_ok());
    }

    #[test]
    fn openshell_config_dir_appends_openshell() {
        let dir = openshell_config_dir().unwrap();
        assert!(
            dir.ends_with("openshell"),
            "expected path ending with 'openshell', got: {dir:?}"
        );
    }

    #[test]
    fn openshell_state_dir_appends_openshell() {
        let dir = openshell_state_dir().unwrap();
        assert!(
            dir.ends_with("openshell"),
            "expected path ending with 'openshell', got: {dir:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_dir_restricted_sets_0o700() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("restricted");
        create_dir_restricted(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "expected 0700, got {mode:04o}");
    }

    #[cfg(unix)]
    #[test]
    fn set_file_owner_only_sets_0o600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("secret");
        std::fs::write(&file, "secret-data").unwrap();
        set_file_owner_only(&file).unwrap();
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:04o}");
    }

    #[cfg(unix)]
    #[test]
    fn is_file_permissions_too_open_detects_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("open-file");
        std::fs::write(&file, "data").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(is_file_permissions_too_open(&file));
    }

    #[cfg(unix)]
    #[test]
    fn is_file_permissions_too_open_accepts_restricted() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("restricted-file");
        std::fs::write(&file, "data").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!is_file_permissions_too_open(&file));
    }

    #[cfg(windows)]
    #[test]
    fn create_dir_restricted_sets_owner_only_acl() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("restricted");
        create_dir_restricted(&dir).unwrap();
        assert!(
            !is_file_permissions_too_open(&dir),
            "expected owner-only ACL on {}",
            dir.display()
        );
    }

    #[cfg(windows)]
    #[test]
    fn set_file_owner_only_sets_owner_only_acl() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("secret");
        std::fs::write(&file, "secret-data").unwrap();
        set_file_owner_only(&file).unwrap();
        assert!(
            !is_file_permissions_too_open(&file),
            "expected owner-only ACL on {}",
            file.display()
        );
    }

    #[cfg(windows)]
    #[test]
    fn is_file_permissions_too_open_detects_world_readable() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("open-file");
        std::fs::write(&file, "data").unwrap();
        // Grant Everyone read access, mirroring the Unix 0o644 case: an ACE
        // for a trustee other than the current user.
        let status = std::process::Command::new("icacls")
            .arg(&file)
            .arg("/grant")
            .arg("Everyone:(R)")
            .status()
            .unwrap();
        assert!(status.success(), "icacls grant failed");
        assert!(is_file_permissions_too_open(&file));
    }

    #[cfg(windows)]
    #[test]
    fn is_file_permissions_too_open_accepts_restricted() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("restricted-file");
        std::fs::write(&file, "data").unwrap();
        set_file_owner_only(&file).unwrap();
        assert!(!is_file_permissions_too_open(&file));
    }

    #[cfg(windows)]
    #[test]
    fn is_file_permissions_too_open_detects_null_dacl() {
        // A NULL DACL is the Win32 API's own documented "grant everyone full
        // access" state -- the most permissive possible -- and is a distinct
        // condition from an unreadable/invalid ACL. Regression test for a
        // CodeRabbit-flagged bug where the two were conflated and a NULL
        // DACL was reported as safe.
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("null-dacl-file");
        std::fs::write(&file, "data").unwrap();

        windows_acl::set_null_dacl_for_test(&file).unwrap();

        assert!(
            is_file_permissions_too_open(&file),
            "a NULL DACL grants everyone full access and must be flagged as too open"
        );
    }

    #[cfg(windows)]
    #[test]
    fn restrict_to_current_user_also_takes_ownership() {
        // A DACL-only update leaves a foreign owner's implicit WRITE_DAC
        // right intact, letting them later replace the DACL we just set.
        // Regression test for a review comment on the owner-only ACL PR.
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("owned-file");
        std::fs::write(&file, "data").unwrap();

        set_file_owner_only(&file).unwrap();

        assert!(
            windows_acl::owner_is_current_user_for_test(&file).unwrap(),
            "restrict_to_current_user must take ownership, not just set the DACL"
        );
    }

    #[cfg(windows)]
    #[test]
    fn is_file_permissions_too_open_fails_closed_on_inspection_error() {
        // A nonexistent path can't have its ACL read, so GetNamedSecurityInfoW
        // fails. `unwrap_or(false)` would turn that failure into "safe";
        // fail closed instead -- an inspection failure is a security false
        // negative risk, not a green light.
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        assert!(is_file_permissions_too_open(&missing));
    }

    #[cfg(windows)]
    #[test]
    fn is_file_permissions_too_open_detects_object_ace_type() {
        // Windows also defines access-allowed object/callback/callback-object
        // ACE types, each wider than the plain ACCESS_ALLOWED_ACE this audit
        // parses. Any of them may grant rights to a foreign trustee, so their
        // mere presence must be flagged conservatively rather than silently
        // skipped as a non-granting (deny/audit) type would be.
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("object-ace-file");
        std::fs::write(&file, "data").unwrap();

        windows_acl::set_object_ace_dacl_for_test(&file).unwrap();

        assert!(
            is_file_permissions_too_open(&file),
            "an unparsed access-allow ACE layout must be conservatively flagged as too open"
        );
    }

    #[test]
    fn normalize_path_collapses_separators() {
        assert_eq!(normalize_path("/usr//lib"), "/usr/lib");
        assert_eq!(normalize_path("/usr/./lib"), "/usr/lib");
        assert_eq!(normalize_path("/tmp/"), "/tmp");
    }

    #[test]
    fn normalize_path_preserves_parent_dir() {
        // normalize_path preserves ".." — validation catches it separately
        assert_eq!(normalize_path("/usr/../etc"), "/usr/../etc");
    }
}
