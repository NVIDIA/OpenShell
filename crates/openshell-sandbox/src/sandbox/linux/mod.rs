// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Linux sandbox implementation using Landlock and seccomp.

mod landlock;
mod seccomp;

use miette::Result;
use openshell_core::policy::SandboxPolicy;
use std::path::PathBuf;
use std::sync::Once;

pub use landlock::require_abi as require_landlock_abi;
pub use landlock::{LandlockReportFd, LandlockReportPipe};

/// Opaque handle to a prepared-but-not-yet-enforced sandbox.
/// Holds the Landlock ruleset with `PathFds` opened before child exec,
/// plus both seccomp filters already compiled to BPF programs.
pub struct PreparedSandbox {
    landlock: Vec<landlock::PreparedRuleset>,
    seccomp: seccomp::PreparedSeccomp,
}

/// Phase 1: Prepare sandbox restrictions with strict path opening.
///
/// Opens configured paths as the calling identity and handles failures according
/// to the policy's Landlock compatibility mode. Both seccomp filters are
/// compiled here as well, so the child never builds them after `fork`.
/// The capability-free launch path uses [`prepare_capability_free`] instead.
pub fn prepare(policy: &SandboxPolicy, workdir: Option<&str>) -> Result<PreparedSandbox> {
    let landlock = landlock::prepare(policy, workdir)?;
    let seccomp = seccomp::prepare(policy)?;
    Ok(PreparedSandbox {
        landlock: landlock.into_iter().collect(),
        seccomp,
    })
}

/// Phase 1 for already-unprivileged workloads.
///
/// Opens Landlock `PathFds` as the current workload UID and compiles the
/// seccomp filters.
pub fn prepare_current_user(
    policy: &SandboxPolicy,
    workdir: Option<&str>,
) -> Result<PreparedSandbox> {
    let landlock = landlock::prepare_current_user(policy, workdir)?;
    let seccomp = seccomp::prepare(policy)?;
    Ok(PreparedSandbox {
        landlock: landlock.into_iter().collect(),
        seccomp,
    })
}

/// Prepare the mandatory capability-free filesystem baseline plus the
/// optional user policy.
///
/// The baseline is always a hard requirement. It grants access to each
/// top-level filesystem entry independently while deliberately omitting the
/// driver-owned `/.openshell` hierarchy. Applying the user ruleset after the
/// baseline intersects the two policies; it can narrow the baseline but can
/// never make the private hierarchy visible.
pub fn prepare_capability_free(
    policy: &SandboxPolicy,
    workdir: Option<&str>,
) -> Result<PreparedSandbox> {
    let baseline = landlock::prepare_capability_free_baseline()?;
    let user = landlock::prepare_current_user(policy, workdir)?;
    let seccomp = seccomp::prepare(policy)?;
    let mut landlock = vec![baseline];
    landlock.extend(user);
    Ok(PreparedSandbox { landlock, seccomp })
}

/// Phase 2: Enforce prepared sandbox restrictions in the child before exec.
///
/// Calls `restrict_self()` for Landlock and installs the prebuilt seccomp
/// filters. Neither operation requires root privileges. Best-effort rulesets
/// that degrade are reported directly through the shared finding builder with
/// the full error chain: this path serves fresh processes (see `main.rs`),
/// never a forked child, so formatting the landlock error and the tracing
/// subscriber both work here.
pub fn enforce(prepared: PreparedSandbox) -> Result<()> {
    for ruleset in prepared.landlock {
        landlock::enforce_fresh(ruleset)?;
    }
    prepared.seccomp.install()?;
    Ok(())
}

/// Enforce the capability-free child filter stack.
///
/// Landlock precedes sandbox-TGID self-protection. The ordinary workload
/// filter is installed last. The final filter blocks any later seccomp
/// installation, so this order is mandatory for capability-free children.
///
/// A best-effort ruleset that degrades does not abort the spawn: its cause
/// is written to the report pipe as one fixed-size, async-signal-safe record
/// before the child self-protection filter is installed, so the `write(2)`
/// cannot block on the seccomp broker and the parent reports the finding
/// after spawn.
pub fn enforce_capability_free(
    prepared: PreparedSandbox,
    child_hardening: &mut crate::linux::child_seccomp::ChildHardeningProgram,
    report: LandlockReportFd,
) -> Result<()> {
    for ruleset in prepared.landlock {
        match landlock::enforce(ruleset)? {
            landlock::LandlockOutcome::Enforced => {}
            landlock::LandlockOutcome::Degraded(cause) => report.report_degraded(cause),
        }
    }
    child_hardening
        .install()
        .map_err(|error| miette::miette!("install child self-protection filter: {error}"))?;
    prepared.seccomp.install()?;
    Ok(())
}

/// Everything a spawned workload child installs between fork and exec.
///
/// Bundles the prepared Landlock rulesets and prebuilt seccomp filters
/// ([`PreparedSandbox`]) with the same-UID child self-protection program and
/// the Landlock report pipe's write end, so a spawn surface cannot wire one
/// without the other or silently drop the report channel. All compilation
/// and path opening happens at construction, parent-side; the forked child
/// only installs.
pub struct ChildSandboxInstall {
    prepared: Option<PreparedSandbox>,
    child_hardening: crate::linux::child_seccomp::ChildHardeningProgram,
    report: LandlockReportFd,
}

impl ChildSandboxInstall {
    /// Bundle a prepared sandbox (if any) with its child hardening program
    /// and the Landlock report pipe's write end.
    #[must_use]
    pub fn new(
        prepared: Option<PreparedSandbox>,
        child_hardening: crate::linux::child_seccomp::ChildHardeningProgram,
        report: LandlockReportFd,
    ) -> Self {
        Self {
            prepared,
            child_hardening,
            report,
        }
    }

    /// Enforce the bundled restrictions in the forked child before exec.
    ///
    /// A no-op when no sandbox was prepared, matching the previous optional
    /// plumbing: the child hardening program is only installed alongside a
    /// prepared sandbox.
    pub(crate) fn enforce(&mut self) -> Result<()> {
        let Some(prepared) = self.prepared.take() else {
            return Ok(());
        };
        enforce_capability_free(prepared, &mut self.child_hardening, self.report)
    }
}

/// Apply the supervisor seccomp prelude after privileged bootstrap completes.
pub fn apply_supervisor_prelude() -> Result<()> {
    seccomp::apply_supervisor_prelude()
}

/// Helpers shared by the `sandbox::linux` test modules.
#[cfg(test)]
pub(crate) mod test_support {
    use openshell_core::policy::{
        FilesystemPolicy, LandlockCompatibility, LandlockPolicy, NetworkPolicy, ProcessPolicy,
        SandboxPolicy,
    };
    use std::path::PathBuf;

    /// A policy with one best-effort Landlock ruleset over `read_only`.
    pub fn best_effort_policy(read_only: Vec<PathBuf>) -> SandboxPolicy {
        SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy {
                read_only,
                read_write: Vec::new(),
                include_workdir: false,
            },
            network: NetworkPolicy::default(),
            landlock: LandlockPolicy {
                compatibility: LandlockCompatibility::BestEffort,
            },
            process: ProcessPolicy::default(),
        }
    }

    /// Compile a filter that makes `landlock_restrict_self` fail with EPERM,
    /// so `enforce` takes its degradation path on a Landlock-capable host.
    pub fn build_restrict_self_blocking_filter() -> seccompiler::BpfProgram {
        use std::collections::BTreeMap;

        let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
        rules.entry(libc::SYS_landlock_restrict_self).or_default();
        let filter = seccompiler::SeccompFilter::new(
            rules,
            seccompiler::SeccompAction::Allow,
            seccompiler::SeccompAction::Errno(libc::EPERM as u32),
            std::env::consts::ARCH
                .try_into()
                .expect("supported architecture"),
        )
        .expect("compile restrict_self-blocking filter");
        filter
            .try_into()
            .expect("build restrict_self-blocking BPF program")
    }
}

/// Emit the `landlock-enforce-failed` finding for one degraded best-effort
/// ruleset.
///
/// Shared by the post-spawn drain reporter and the fresh-process
/// [`landlock::enforce_fresh`] path so the two transports cannot diverge.
/// Only call this where the tracing subscriber works — never between fork
/// and exec. `detail` is the failure rendering for the message: the drain
/// transport passes the errno-based cause rendering (the forked child cannot
/// format the landlock error, so only the errno crosses the report pipe),
/// while the fresh path passes the full error chain. The description keeps
/// the errno-based cause either way.
fn emit_landlock_enforce_failed(cause: landlock::DegradedCause, detail: &str) {
    openshell_ocsf::ocsf_emit!(
        openshell_ocsf::DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(openshell_ocsf::ActivityId::Open)
            .severity(openshell_ocsf::SeverityId::High)
            .confidence(openshell_ocsf::ConfidenceId::High)
            .is_alert(true)
            .finding_info(
                openshell_ocsf::FindingInfo::new(
                    "landlock-enforce-failed",
                    "Landlock restrict_self Failed",
                )
                .with_desc(&format!(
                    "Ruleset was prepared but restrict_self() failed ({cause}). \
                     Running WITHOUT filesystem restrictions. \
                     Set landlock.compatibility to 'hard_requirement' to make this fatal."
                )),
            )
            .message(format!(
                "Landlock restrict_self failed (best_effort): {detail}"
            ))
            .build()
    );
}

/// Probe Landlock availability and emit OCSF logs from the parent process.
///
/// This must be called **before** `pre_exec` / `fork()` so that the OCSF events
/// are emitted through the parent's tracing subscriber (the child process after
/// fork does not have a working tracing pipeline).
pub fn log_sandbox_readiness(policy: &SandboxPolicy, workdir: Option<&str>) {
    static PROBED: Once = Once::new();
    let mut already_probed = true;
    PROBED.call_once(|| already_probed = false);
    if already_probed {
        return;
    }

    let mut read_write = policy.filesystem.read_write.clone();
    let read_only = &policy.filesystem.read_only;

    if policy.filesystem.include_workdir
        && let Some(dir) = workdir
    {
        let workdir_path = PathBuf::from(dir);
        if !read_write.contains(&workdir_path) {
            read_write.push(workdir_path);
        }
    }

    let total_paths = read_only.len() + read_write.len();

    if total_paths == 0 {
        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(openshell_ocsf::SeverityId::Informational)
                .status(openshell_ocsf::StatusId::Success)
                .state(openshell_ocsf::StateId::Other, "skipped")
                .message("Landlock filesystem sandbox skipped: no paths configured".to_string())
                .build()
        );
        return;
    }

    let availability = landlock::probe_availability();
    if let landlock::LandlockAvailability::Available { abi } = &availability {
        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(openshell_ocsf::SeverityId::Informational)
                .status(openshell_ocsf::StatusId::Success)
                .state(openshell_ocsf::StateId::Enabled, "probed")
                .message(format!(
                    "Landlock filesystem sandbox available \
                     [abi:v{abi} compat:{:?} ro:{} rw:{}]",
                    policy.landlock.compatibility,
                    read_only.len(),
                    read_write.len(),
                ))
                .build()
        );
    } else {
        // Landlock is NOT available — this is the critical log that was
        // previously invisible because it only fired inside pre_exec.
        let is_best_effort = matches!(
            policy.landlock.compatibility,
            openshell_core::policy::LandlockCompatibility::BestEffort
        );
        let (desc, msg) = if is_best_effort {
            (
                format!(
                    "Sandbox will run WITHOUT filesystem restrictions: {availability}. \
                     Policy requests {total_paths} path rule(s) \
                     (ro:{} rw:{}) but Landlock cannot enforce them. \
                     Set landlock.compatibility to 'hard_requirement' to make this fatal.",
                    read_only.len(),
                    read_write.len(),
                ),
                format!(
                    "Landlock filesystem sandbox unavailable (best_effort, degraded): {availability}"
                ),
            )
        } else {
            (
                format!(
                    "Landlock is unavailable: {availability}. \
                     Policy requires {total_paths} path rule(s) \
                     (ro:{} rw:{}) with hard_requirement — sandbox startup will fail.",
                    read_only.len(),
                    read_write.len(),
                ),
                format!(
                    "Landlock filesystem sandbox unavailable (hard_requirement, will fail): {availability}"
                ),
            )
        };
        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(openshell_ocsf::ActivityId::Open)
                .severity(openshell_ocsf::SeverityId::High)
                .confidence(openshell_ocsf::ConfidenceId::High)
                .is_alert(true)
                .finding_info(
                    openshell_ocsf::FindingInfo::new(
                        "landlock-unavailable",
                        "Landlock Filesystem Sandbox Unavailable",
                    )
                    .with_desc(&desc),
                )
                .message(msg)
                .build()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::landlock::{DegradedCause, LandlockAvailability};
    use super::test_support::{best_effort_policy, build_restrict_self_blocking_filter};
    use super::*;
    use openshell_ocsf::test_support::OcsfCapture;
    use openshell_ocsf::{OcsfEvent, SeverityId};

    /// Check that one captured event is the `landlock-enforce-failed` finding
    /// for the given cause rendered through the given detail, or describe the
    /// mismatch.
    fn check_landlock_enforce_failed_finding(
        event: &OcsfEvent,
        cause: DegradedCause,
        detail: &str,
    ) -> Result<(), String> {
        let OcsfEvent::DetectionFinding(finding) = event else {
            return Err(format!("expected a DetectionFinding, got {event:?}"));
        };
        if finding.finding_info.uid != "landlock-enforce-failed" {
            return Err(format!(
                "unexpected finding uid: {}",
                finding.finding_info.uid
            ));
        }
        if finding.finding_info.title != "Landlock restrict_self Failed" {
            return Err(format!(
                "unexpected finding title: {}",
                finding.finding_info.title
            ));
        }
        if finding.base.severity != SeverityId::High {
            return Err(format!("unexpected severity: {:?}", finding.base.severity));
        }
        if finding.is_alert != Some(true) {
            return Err(format!("finding is not an alert: {:?}", finding.is_alert));
        }
        let expected_message = format!("Landlock restrict_self failed (best_effort): {detail}");
        if finding.base.message.as_deref() != Some(expected_message.as_str()) {
            return Err(format!(
                "unexpected message: {:?}, expected {expected_message:?}",
                finding.base.message
            ));
        }
        let Some(desc) = finding.finding_info.desc.as_deref() else {
            return Err("finding carries no description".to_string());
        };
        if !desc.contains(&format!("restrict_self() failed ({cause})")) {
            return Err(format!("description lost the degraded cause: {desc}"));
        }
        if !desc.contains("hard_requirement") {
            return Err(format!("description lost the remediation hint: {desc}"));
        }
        Ok(())
    }

    /// The post-spawn drain must emit one `landlock-enforce-failed` finding
    /// per degraded ruleset — not once per spawn — with the uid, title, High
    /// severity, and errno-based message and description downstream OCSF
    /// consumers rely on.
    #[test]
    #[allow(unsafe_code)]
    fn report_drain_emits_one_finding_per_degraded_ruleset() {
        let causes = [
            DegradedCause::Errno(libc::EPERM),
            DegradedCause::NoErrno,
            DegradedCause::Errno(libc::EACCES),
        ];
        let capture = OcsfCapture::default();
        let _guard = capture.install();

        let pipe = LandlockReportPipe::new().expect("create report pipe");
        let child_fd = pipe.child_fd();
        let mut drain = pipe.into_drain();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            for cause in causes {
                child_fd.report_degraded(cause);
            }
            unsafe { libc::_exit(0) };
        }
        let mut status: libc::c_int = 0;
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "record-writing child failed"
        );

        assert_eq!(
            drain.report_degradations(),
            causes.to_vec(),
            "drain must decode every record the child wrote"
        );

        let events = capture.events();
        assert_eq!(
            events.len(),
            causes.len(),
            "one finding must be emitted per degraded ruleset, not per spawn: {events:?}"
        );
        for (event, cause) in events.iter().zip(causes) {
            // The drain transport reports the errno-based rendering.
            check_landlock_enforce_failed_finding(event, cause, &cause.to_string())
                .unwrap_or_else(|error| panic!("drain emitted a wrong finding: {error}"));
        }
    }

    /// The fresh-process [`enforce`] path must report a degraded best-effort
    /// ruleset through the same `landlock-enforce-failed` finding the drain
    /// transport emits, so the two cannot diverge — and, unlike the drain,
    /// with the full landlock error chain, because a fresh process can
    /// format it. The probe installs an irreversible seccomp filter and
    /// emits OCSF, so it runs in a fresh copy of this test binary
    /// (env-marker re-exec) rather than a forked child of the multithreaded
    /// test harness, where emission is forbidden.
    #[test]
    #[allow(unsafe_code)]
    fn fresh_process_enforce_emits_the_detection_finding() {
        const CHILD_MARKER: &str = "OPENSHELL_TEST_FRESH_ENFORCE_FINDING_CHILD";
        if !matches!(
            landlock::probe_availability(),
            LandlockAvailability::Available { abi } if abi >= 3
        ) {
            return;
        }
        if std::env::var_os(CHILD_MARKER).is_some() {
            let root = tempfile::tempdir().unwrap();
            let policy = best_effort_policy(vec![root.path().to_path_buf()]);
            let prepared =
                prepare(&policy, None).expect("prepare sandbox with one best-effort ruleset");
            assert_eq!(prepared.landlock.len(), 1, "expected exactly one ruleset");
            let filter = build_restrict_self_blocking_filter();

            let capture = OcsfCapture::default();
            let _guard = capture.install();
            unsafe {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                seccompiler::apply_filter(&filter).expect("apply blocking filter");
            }
            enforce(prepared).expect("enforce must continue past a degraded ruleset");

            let events = capture.events();
            assert_eq!(
                events.len(),
                1,
                "expected exactly one finding for the degraded ruleset, got {}",
                events.len()
            );
            // The fresh path reports the full error chain: the landlock
            // crate's Display for the blocked restrict_self call, ending in
            // the same strerror rendering std produces for EPERM.
            let expected_detail = format!(
                "failed to restrict the calling thread: {}",
                std::io::Error::from_raw_os_error(libc::EPERM),
            );
            check_landlock_enforce_failed_finding(
                &events[0],
                DegradedCause::Errno(libc::EPERM),
                &expected_detail,
            )
            .unwrap_or_else(|error| {
                panic!("fresh-process enforce emitted a wrong finding: {error}")
            });
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sandbox::linux::tests::fresh_process_enforce_emits_the_detection_finding",
                "--nocapture",
            ])
            .env(CHILD_MARKER, "1")
            .status()
            .expect("run isolated fresh-process enforce emission test");
        assert!(
            status.success(),
            "isolated fresh-process enforce emission test failed"
        );
    }
}
