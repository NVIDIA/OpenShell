// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    ffi::CStr,
    io,
    mem::MaybeUninit,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        Authorization::{
            ConvertSidToStringSidA, ConvertStringSecurityDescriptorToSecurityDescriptorA,
            SDDL_REVISION_1,
        },
        GetTokenInformation, SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    },
    System::{
        Pipes::GetNamedPipeServerProcessId,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

pub struct Listener(NamedPipeServer);

fn address(id: Uuid) -> String {
    format!(r"\\.\pipe\openshell-ssh-{id}")
}

#[repr(C)]
struct UserInfo {
    user: TOKEN_USER,
    sid: [u8; SECURITY_MAX_SID_SIZE as usize],
}

/// Read the process account SID. `TokenOwner` can instead designate a group.
#[allow(unsafe_code)]
fn current_user_sid() -> io::Result<String> {
    let mut token = ptr::null_mut();
    // SAFETY: token is writable and becomes an owned handle on success.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken returned a new handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut info = MaybeUninit::<UserInfo>::uninit();
    let mut len = 0;
    // SAFETY: info is aligned and large enough for TOKEN_USER and the largest SID.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            info.as_mut_ptr().cast(),
            u32::try_from(size_of::<UserInfo>()).map_err(io::Error::other)?,
            &raw mut len,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut text = ptr::null_mut();
    // SAFETY: GetTokenInformation initialized user, whose SID points into info.
    if unsafe { ConvertSidToStringSidA((*info.as_ptr()).user.User.Sid, &raw mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the function returns a LocalAlloc-owned, NUL-terminated ASCII SID.
    let sid = unsafe { CStr::from_ptr(text.cast()).to_string_lossy().into_owned() };
    unsafe { LocalFree(text.cast()) };
    Ok(sid)
}

impl Listener {
    #[allow(unsafe_code)]
    pub fn bind(id: Uuid) -> io::Result<Self> {
        // A protected DACL grants access only to the pipe owner. The default
        // pipe DACL also grants read access to Everyone.
        let sid = current_user_sid()?;
        let sddl = format!("O:{sid}D:P(A;;GA;;;{sid})\0");
        let mut descriptor = ptr::null_mut();
        // SAFETY: the input is NUL terminated and descriptor is a writable out pointer.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorA(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                .expect("SECURITY_ATTRIBUTES fits a DWORD"),
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        // SAFETY: the descriptor and attributes remain valid through CreateNamedPipeW.
        let pipe = unsafe {
            ServerOptions::new()
                .first_pipe_instance(true)
                .max_instances(1)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(address(id), (&raw mut attributes).cast())
        };
        // SAFETY: the conversion above allocated descriptor with LocalAlloc.
        unsafe { LocalFree(descriptor) };
        pipe.map(Self)
    }

    pub async fn accept(self) -> io::Result<NamedPipeServer> {
        self.0.connect().await?;
        Ok(self.0)
    }
}

#[allow(unsafe_code)]
pub fn connect(id: Uuid, expected_pid: u32) -> io::Result<NamedPipeClient> {
    let pipe = ClientOptions::new().open(address(id))?;
    let mut pid = 0;
    // SAFETY: pipe owns the live handle and pid is a writable DWORD.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &raw mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if pid != expected_pid {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(pipe)
}
