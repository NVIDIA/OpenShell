// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! One kill-on-close job object per sandbox generation.
//!
//! A generation's process tree is `openshell-supervisor`, `wxc-exec`, the
//! in-container `openshell-windows-sandbox` and the workload with its
//! children. Putting the root processes in a job with
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` makes Windows end the whole tree when
//! the last handle to the job closes: on stop/delete (explicit
//! [`GenerationJob::terminate`]), when the lifecycle task ends, or when the
//! driver's host process dies for any reason. Children inherit job membership
//! and `BREAKAWAY_OK` is not set, so nothing can leave the job.
//!
//! The root processes are created as members of the job
//! (`crate::child::spawn_in_job`), so there is no moment at which a process of the
//! generation exists outside its job, even if the driver is killed during the spawn.
//!
//! The job lives with the driver rather than with whichever process hosts it,
//! so the cleanup survives moving the driver out of the gateway.

// `pub(crate)` documents what the driver may use; this module is private.
#![allow(clippy::redundant_pub_crate)]

use std::io;
use std::mem::size_of;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};
use windows::core::PCWSTR;

use crate::child::{ChildCommand, GenerationChild};

/// Owns a kill-on-close job object. Dropping it ends every member process.
pub struct GenerationJob {
    handle: HANDLE,
}

// SAFETY: a job object handle is a process-wide kernel handle with no thread
// affinity; every operation used here is thread-safe.
#[allow(unsafe_code)]
unsafe impl Send for GenerationJob {}
#[allow(unsafe_code)]
unsafe impl Sync for GenerationJob {}

#[allow(unsafe_code)] // Win32 job object calls.
impl GenerationJob {
    pub(crate) fn new() -> io::Result<Self> {
        // SAFETY: plain Win32 calls with valid arguments; `info` outlives the
        // call and the size matches its type. No security attributes are
        // passed, so the handle is not inheritable and children cannot keep
        // the job open.
        unsafe {
            let handle = CreateJobObjectW(None, PCWSTR::null()).map_err(io::Error::from)?;
            let job = Self { handle };
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                job.handle,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .map_err(io::Error::other)?,
            )
            .map_err(io::Error::from)?;
            Ok(job)
        }
    }

    /// Start `command` as a member of this job.
    ///
    /// The process is created inside the job (the job is named in the
    /// `CreateProcessW` call), so it is never outside it. If it cannot be created
    /// there, the spawn fails and no process exists: a sandbox whose processes could
    /// outlive the driver must not start.
    ///
    /// Call inside a tokio runtime.
    pub(crate) fn spawn(&self, command: &ChildCommand) -> io::Result<GenerationChild> {
        crate::child::spawn_in_job(self.handle, command)
    }

    /// End every process in the job now.
    pub(crate) fn terminate(&self) {
        // SAFETY: valid job handle. An already-empty job is not an error worth
        // reporting.
        let _ = unsafe { TerminateJobObject(self.handle, 1) };
    }

    #[cfg(test)]
    pub(crate) fn raw(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for GenerationJob {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // Closing the last handle triggers KILL_ON_JOB_CLOSE.
        // SAFETY: `handle` came from `CreateJobObjectW` and is closed once.
        let _ = unsafe { CloseHandle(self.handle) };
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use std::time::Duration;

    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::JobObjects::IsProcessInJob;

    use super::*;
    use crate::child::{ChildStdio, spawn_suspended_in_job};

    fn sleeper() -> ChildCommand {
        let mut command = ChildCommand::new("cmd.exe");
        command
            .args(["/c", "ping -n 30 127.0.0.1 >nul"])
            .stdin(ChildStdio::Null)
            .stdout(ChildStdio::Null)
            .stderr(ChildStdio::Null);
        command
    }

    #[tokio::test]
    async fn spawned_process_runs_and_is_killed_by_terminate() {
        let job = GenerationJob::new().expect("job");
        let mut child = job.spawn(&sleeper()).expect("spawn in job");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(1), child.wait())
                .await
                .is_err(),
            "child should be running"
        );
        job.terminate();
        let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
            .await
            .expect("child ended after terminate")
            .unwrap();
        assert!(!status.success());
    }

    #[tokio::test]
    async fn dropping_the_job_kills_the_whole_tree() {
        let job = GenerationJob::new().expect("job");
        // cmd.exe starts ping.exe: a grandchild that inherits membership.
        let mut child = job.spawn(&sleeper()).expect("spawn in job");
        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(job);
        // Closing the job ends members with exit code 0, so only that the
        // process ended (not how) can be asserted.
        tokio::time::timeout(Duration::from_secs(10), child.wait())
            .await
            .expect("child ended after the job closed")
            .unwrap();
    }

    /// Fail closed: if the process cannot be created inside its job, the spawn fails
    /// instead of handing back a process that could outlive the driver.
    #[tokio::test]
    async fn an_unusable_job_fails_the_spawn() {
        let job = GenerationJob {
            handle: HANDLE::default(),
        };
        let error = job.spawn(&sleeper()).err().expect("must fail closed");
        assert!(
            error.to_string().contains("sandbox job"),
            "unexpected error: {error}"
        );
        std::mem::forget(job); // do not CloseHandle the invalid handle
    }

    /// The property the job exists for, and the case a review found: the process is a
    /// member of its job from the moment it exists, before it has run one instruction.
    /// A process created the ordinary way is not, so the check can fail.
    #[tokio::test]
    async fn child_is_a_member_of_its_job_before_it_runs() {
        let job = GenerationJob::new().expect("job");
        let (child, thread) =
            spawn_suspended_in_job(job.raw(), &sleeper()).expect("suspended spawn");
        let handle = HANDLE(child.raw_handle().expect("process handle"));
        let mut in_job = windows::core::BOOL::default();
        // SAFETY: both handles are valid for the call.
        unsafe { IsProcessInJob(handle, Some(job.raw()), &raw mut in_job) }
            .expect("IsProcessInJob");
        assert!(
            in_job.as_bool(),
            "a freshly created, not yet running child must already be in the job"
        );
        thread.resume().expect("resume");
        drop(child);

        // Negative control: a process created the ordinary way is not in the job.
        let mut outsider = tokio::process::Command::new("cmd.exe")
            .args(["/c", "ping -n 30 127.0.0.1 >nul"])
            .kill_on_drop(true)
            .spawn()
            .expect("outsider");
        let outsider_handle = HANDLE(outsider.raw_handle().expect("outsider handle"));
        let mut outsider_in_job = windows::core::BOOL::default();
        // SAFETY: both handles are valid for the call.
        unsafe { IsProcessInJob(outsider_handle, Some(job.raw()), &raw mut outsider_in_job) }
            .expect("IsProcessInJob");
        assert!(
            !outsider_in_job.as_bool(),
            "the check must be able to say no"
        );
        let _ = outsider.kill().await;
    }

    // ---- Hard-killing the process that owns the job ----

    /// Set (by the tests below) on the re-run of this test binary that plays the
    /// role of the driver's host process.
    const HOST_ENV: &str = "OPENSHELL_JOB_TEST_HOST";
    const STRESS_ENV: &str = "OPENSHELL_JOB_TEST_STRESS_EXE";

    fn is_alive(pid: u32) -> bool {
        use windows::Win32::Foundation::WAIT_TIMEOUT;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
        };
        // SAFETY: plain Win32 calls; the handle is closed before returning.
        unsafe {
            let Ok(handle) = OpenProcess(PROCESS_SYNCHRONIZE, false, pid) else {
                return false; // no such process any more
            };
            let alive = WaitForSingleObject(handle, 0) == WAIT_TIMEOUT;
            let _ = CloseHandle(handle);
            alive
        }
    }

    fn child_pids(parent: u32) -> Vec<u32> {
        // SAFETY: the snapshot is closed before returning; `dwSize` is set.
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();
            let mut entry = PROCESSENTRY32W {
                dwSize: u32::try_from(size_of::<PROCESSENTRY32W>()).unwrap(),
                ..Default::default()
            };
            let mut found = Vec::new();
            let mut more = Process32FirstW(snapshot, &raw mut entry).is_ok();
            while more {
                if entry.th32ParentProcessID == parent {
                    found.push(entry.th32ProcessID);
                }
                more = Process32NextW(snapshot, &raw mut entry).is_ok();
            }
            let _ = CloseHandle(snapshot);
            found
        }
    }

    /// How many running processes have this executable file name.
    fn count_named(exe_name: &str) -> usize {
        // SAFETY: the snapshot is closed before returning; `dwSize` is set.
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();
            let mut entry = PROCESSENTRY32W {
                dwSize: u32::try_from(size_of::<PROCESSENTRY32W>()).unwrap(),
                ..Default::default()
            };
            let mut count = 0;
            let mut more = Process32FirstW(snapshot, &raw mut entry).is_ok();
            while more {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                if String::from_utf16_lossy(&entry.szExeFile[..len]).eq_ignore_ascii_case(exe_name)
                {
                    count += 1;
                }
                more = Process32NextW(snapshot, &raw mut entry).is_ok();
            }
            let _ = CloseHandle(snapshot);
            count
        }
    }

    /// Plays the driver host: owns a job, starts a process tree in it, reports
    /// the PIDs, then waits to be killed. A no-op in a normal test run.
    #[tokio::test]
    async fn hard_kill_host_helper() {
        if std::env::var_os(HOST_ENV).is_none() {
            return;
        }
        let job = GenerationJob::new().expect("job");
        let child = job.spawn(&sleeper()).expect("spawn in job");
        let root = child.id().expect("pid");
        tokio::time::sleep(Duration::from_millis(700)).await; // let cmd start ping
        let grandchildren = child_pids(root)
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        println!("TREE {root} {grandchildren}");
        tokio::time::sleep(Duration::from_mins(2)).await;
        drop(job);
    }

    /// The property the job exists for: when the process that owns the job is
    /// hard-killed (no destructors, no cleanup code), Windows still ends every
    /// process in the tree, grandchildren included.
    #[tokio::test]
    async fn hard_killing_the_job_owner_ends_the_whole_tree() {
        use std::io::{BufRead as _, BufReader};
        use std::process::Stdio;
        if std::env::var_os(HOST_ENV).is_some() {
            return; // inside the helper run
        }
        let mut host = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "job::tests::hard_kill_host_helper",
                "--nocapture",
            ])
            .env(HOST_ENV, "1")
            .stdout(Stdio::piped())
            .spawn()
            .expect("start helper host");
        let mut lines = BufReader::new(host.stdout.take().unwrap()).lines();
        let tree: Vec<u32> = loop {
            let line = lines.next().expect("helper exited early").unwrap();
            if let Some(rest) = line.strip_prefix("TREE ") {
                break rest
                    .split([' ', ','])
                    .filter(|p| !p.is_empty())
                    .map(|p| p.parse().unwrap())
                    .collect();
            }
        };
        assert!(
            tree.len() >= 2,
            "expected the root and at least one grandchild, got {tree:?}"
        );
        assert!(tree.iter().all(|&pid| is_alive(pid)), "tree should be live");

        host.kill().expect("hard-kill the host");
        host.wait().unwrap();

        for _ in 0..100 {
            if tree.iter().all(|&pid| !is_alive(pid)) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("processes survived the hard kill of their job owner: {tree:?}");
    }

    /// A host that starts generations as fast as it can, keeping a few alive, until killed.
    /// A no-op in a normal test run.
    #[tokio::test]
    async fn spawn_loop_host_helper() {
        let Some(exe) = std::env::var_os(STRESS_ENV) else {
            return;
        };
        let mut live: std::collections::VecDeque<(GenerationJob, GenerationChild)> =
            std::collections::VecDeque::new();
        println!("READY");
        loop {
            let job = GenerationJob::new().expect("job");
            let mut command = ChildCommand::new(&exe);
            command
                .args(["/c", "ping -n 60 127.0.0.1 >nul"])
                .stdin(ChildStdio::Null)
                .stdout(ChildStdio::Null)
                .stderr(ChildStdio::Null);
            if let Ok(child) = job.spawn(&command) {
                live.push_back((job, child));
            }
            if live.len() > 6 {
                live.pop_front();
            }
        }
    }

    /// Hard-kill a host at many different moments while it is starting generations; no
    /// process of any generation may survive, including one killed mid-spawn.
    #[tokio::test]
    async fn hard_killing_a_host_mid_spawn_leaves_no_process() {
        use std::io::{BufRead as _, BufReader};
        use std::process::Stdio;
        if std::env::var_os(HOST_ENV).is_some() || std::env::var_os(STRESS_ENV).is_some() {
            return; // inside a helper run
        }
        // A copy of cmd.exe under a name nothing else has, so survivors are countable.
        let name = format!("mxc-job-stress-{}.exe", std::process::id());
        let exe = std::env::temp_dir().join(&name);
        let system = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32/cmd.exe");
        std::fs::copy(system, &exe).expect("copy cmd.exe");

        for trial in 0..12u64 {
            let mut host = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "job::tests::spawn_loop_host_helper",
                    "--nocapture",
                ])
                .env(STRESS_ENV, &exe)
                .stdout(Stdio::piped())
                .spawn()
                .expect("start stress host");
            let mut lines = BufReader::new(host.stdout.take().unwrap()).lines();
            while lines.next().expect("host exited early").unwrap() != "READY" {}
            // Different, unrelated delays so the kill lands at different points.
            tokio::time::sleep(Duration::from_millis(40 + (trial * 37) % 260)).await;
            host.kill().expect("hard-kill the host");
            host.wait().unwrap();

            let mut left = usize::MAX;
            for _ in 0..100 {
                left = count_named(&name);
                if left == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert_eq!(
                left, 0,
                "trial {trial}: {left} process(es) survived the hard kill of the host"
            );
        }
        let _ = std::fs::remove_file(&exe);
    }
}
