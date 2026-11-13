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
//! The job lives with the driver rather than with whichever process hosts it,
//! so the cleanup survives moving the driver out of the gateway.

use std::io;
use std::mem::size_of;

use tokio::process::{Child, Command};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};
use windows::core::PCWSTR;

const CREATE_SUSPENDED: u32 = 0x0000_0004;

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
    pub fn new() -> io::Result<Self> {
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

    /// Spawn `command` as a member of this job, with no window in which it can
    /// run (or start children) outside it.
    ///
    /// The process is created suspended, assigned to the job, then resumed.
    /// If it cannot be assigned it is killed and an error is returned: a
    /// sandbox whose processes could outlive the driver must not start.
    pub fn spawn(&self, command: &mut Command) -> io::Result<Child> {
        command.creation_flags(CREATE_SUSPENDED);
        let mut child = command.spawn()?;
        match self.adopt_and_resume(&child) {
            Ok(()) => Ok(child),
            Err(error) => {
                // Still suspended, so it has run no code. `kill_on_drop`
                // retries if this kill fails.
                let _ = child.start_kill();
                Err(error)
            }
        }
    }

    fn adopt_and_resume(&self, child: &Child) -> io::Result<()> {
        let pid = child
            .id()
            .ok_or_else(|| io::Error::other("child exited before it could be assigned to a job"))?;
        let raw = child
            .raw_handle()
            .ok_or_else(|| io::Error::other("child handle unavailable"))?;
        // SAFETY: `raw` is the live process handle owned by `child`.
        unsafe { AssignProcessToJobObject(self.handle, HANDLE(raw)) }.map_err(|error| {
            io::Error::other(format!("assign process {pid} to its sandbox job: {error}"))
        })?;
        resume_process(pid)
    }

    /// End every process in the job now.
    pub fn terminate(&self) {
        // SAFETY: valid job handle. An already-empty job is not an error worth
        // reporting.
        let _ = unsafe { TerminateJobObject(self.handle, 1) };
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

/// Resume every thread of a process created with `CREATE_SUSPENDED`.
#[allow(unsafe_code)] // Toolhelp and thread calls.
fn resume_process(pid: u32) -> io::Result<()> {
    // SAFETY: the snapshot handle is closed on every path; `entry` outlives the
    // calls and `dwSize` is set as the API requires.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).map_err(io::Error::from)?;
        let mut resumed = 0_u32;
        let mut result = Ok(());
        let mut entry = THREADENTRY32 {
            dwSize: u32::try_from(size_of::<THREADENTRY32>()).map_err(io::Error::other)?,
            ..Default::default()
        };
        let mut more = Thread32First(snapshot, &raw mut entry).is_ok();
        while more {
            if entry.th32OwnerProcessID == pid {
                match OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID) {
                    Ok(thread) => {
                        if ResumeThread(thread) == u32::MAX {
                            result = Err(io::Error::last_os_error());
                        } else {
                            resumed += 1;
                        }
                        let _ = CloseHandle(thread);
                    }
                    Err(error) => result = Err(io::Error::from(error)),
                }
            }
            more = Thread32Next(snapshot, &raw mut entry).is_ok();
        }
        let _ = CloseHandle(snapshot);
        result?;
        if resumed == 0 {
            return Err(io::Error::other(format!(
                "no thread of process {pid} could be resumed"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::process::Stdio;
    use std::time::Duration;

    use super::*;

    fn sleeper() -> Command {
        let mut command = Command::new("cmd.exe");
        command
            .args(["/c", "ping -n 30 127.0.0.1 >nul"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        command
    }

    #[tokio::test]
    async fn spawned_process_runs_and_is_killed_by_terminate() {
        let job = GenerationJob::new().expect("job");
        let mut child = job.spawn(&mut sleeper()).expect("spawn in job");
        // Resumed: it must still be running (not stuck suspended, not exited).
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            child.try_wait().unwrap().is_none(),
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
        let mut child = job.spawn(&mut sleeper()).expect("spawn in job");
        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(job);
        let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
            .await
            .expect("child ended after the job closed")
            .unwrap();
        // Closing the job ends members with exit code 0, so only that the
        // process ended (not how) can be asserted.
        let _ = status;
    }

    /// Fail closed: if the process cannot be assigned to the job, `spawn`
    /// returns an error (and kills the still-suspended child) instead of
    /// handing back a process that could outlive the driver.
    #[tokio::test]
    async fn assignment_failure_fails_the_spawn() {
        // An invalid job handle makes `AssignProcessToJobObject` fail.
        let job = GenerationJob {
            handle: HANDLE::default(),
        };
        let error = job.spawn(&mut sleeper()).expect_err("must fail closed");
        assert!(
            error.to_string().contains("assign process"),
            "unexpected error: {error}"
        );
        std::mem::forget(job); // do not CloseHandle the invalid handle
    }

    /// Set (by the test below) on the re-run of this test binary that plays the
    /// role of the driver's host process.
    const HOST_ENV: &str = "OPENSHELL_JOB_TEST_HOST";

    #[allow(unsafe_code)]
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

    #[allow(unsafe_code)]
    fn child_pids(parent: u32) -> Vec<u32> {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            PROCESSENTRY32, Process32First, Process32Next, TH32CS_SNAPPROCESS,
        };
        // SAFETY: the snapshot is closed before returning; `entry.dwSize` is set.
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();
            let mut entry = PROCESSENTRY32 {
                dwSize: u32::try_from(size_of::<PROCESSENTRY32>()).unwrap(),
                ..Default::default()
            };
            let mut found = Vec::new();
            let mut more = Process32First(snapshot, &raw mut entry).is_ok();
            while more {
                if entry.th32ParentProcessID == parent {
                    found.push(entry.th32ProcessID);
                }
                more = Process32Next(snapshot, &raw mut entry).is_ok();
            }
            let _ = CloseHandle(snapshot);
            found
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
        let child = job.spawn(&mut sleeper()).expect("spawn in job");
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
        if std::env::var_os(HOST_ENV).is_some() {
            return; // inside the helper run
        }
        let mut host = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "job::tests::hard_kill_host_helper", "--nocapture"])
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

    #[tokio::test]
    async fn a_failed_spawn_is_reported_not_swallowed() {
        let job = GenerationJob::new().expect("job");
        let mut command = Command::new("definitely-not-a-real-binary.exe");
        assert!(job.spawn(&mut command).is_err());
    }
}
