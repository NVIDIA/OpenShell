// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tie the lifetime of every sandbox process to the gateway process.
//!
//! With the MXC driver built into the gateway, the gateway starts `wxc-exec`,
//! `openshell-supervisor` and `openshell-windows-sandbox` for each sandbox. If
//! the gateway is killed (crash, `taskkill`, logoff), those processes used to
//! survive with no owner and, because they inherited the gateway's listening
//! socket, kept its port bound so a new gateway could not start.
//!
//! A Windows *job object* with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` fixes the
//! first half: the gateway puts itself in the job, every child it spawns
//! inherits membership, and Windows ends all members when the last handle to
//! the job closes, which happens when the gateway process ends for any reason.
//! (The listening sockets are also made non-inheritable; see
//! `openshell_server::gateway_listener`.)

/// Put the current process into a new kill-on-close job object.
///
/// Call this first thing in `main`, before anything is spawned. The job handle
/// is deliberately never closed: it must stay open for as long as the process
/// lives, and closing it (which only happens when the process exits) is what
/// triggers the clean-up. On other platforms this does nothing.
///
/// # Errors
///
/// Returns a description of the failing Win32 call. The caller decides whether
/// that is fatal; nested jobs are supported on Windows 8 and later, so this
/// normally only fails on unusual hosts.
pub fn kill_children_on_exit() -> Result<(), String> {
    #[cfg(windows)]
    {
        windows_impl::kill_children_on_exit()
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

#[cfg(windows)]
#[allow(unsafe_code)] // Win32 job object calls.
mod windows_impl {
    use std::mem::size_of;

    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;
    use windows::core::PCWSTR;

    pub(super) fn kill_children_on_exit() -> Result<(), String> {
        // SAFETY: plain Win32 calls with valid arguments; the info struct
        // outlives the call and `size_of` matches its type.
        unsafe {
            let job = CreateJobObjectW(None, PCWSTR::null())
                .map_err(|e| format!("CreateJobObjectW failed: {e}"))?;
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .map_err(|e| format!("job info size: {e}"))?,
            )
            .map_err(|e| format!("SetInformationJobObject failed: {e}"))?;
            AssignProcessToJobObject(job, GetCurrentProcess())
                .map_err(|e| format!("AssignProcessToJobObject failed: {e}"))?;
            // `job` is intentionally leaked (see the module docs).
            let _ = job;
        }
        Ok(())
    }
}

#[cfg(all(test, windows))]
#[allow(unsafe_code)] // Win32 job object query.
mod tests {
    use std::mem::size_of;

    use windows::Win32::System::JobObjects::{
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, QueryInformationJobObject,
    };

    #[test]
    fn puts_the_process_in_a_kill_on_close_job() {
        super::kill_children_on_exit().expect("job object");

        // A null job handle asks about the job the calling process is in; with
        // nested jobs that is the innermost one, i.e. the one just created.
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // SAFETY: `info` outlives the call and the size matches its type.
        unsafe {
            QueryInformationJobObject(
                None,
                JobObjectExtendedLimitInformation,
                (&raw mut info).cast(),
                u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).unwrap(),
                None,
            )
        }
        .expect("QueryInformationJobObject");
        assert_ne!(
            info.BasicLimitInformation.LimitFlags.0 & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0,
            0,
            "the process job must kill its members when closed"
        );
    }
}
