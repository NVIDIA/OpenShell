// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Status of a hosted sandbox instance, as the shared supervisor reports it
//! on the private `openshell.supervisor.host.v1` stream.

use serde::{Deserialize, Serialize};

use crate::proto::{SandboxInstancePhase, SandboxInstanceStatus};

/// Lifecycle phase of a hosted sandbox instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum SandboxInstancePhaseReport {
    Starting,
    Supervising,
    Stopping,
    Exited { exit_code: i32 },
    Failed { error: String },
}

impl SandboxInstancePhaseReport {
    /// Supervision has ended and cannot resume for this generation.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Exited { .. } | Self::Failed { .. })
    }
}

/// Status of one hosted sandbox instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxInstanceStatusReport {
    pub route: String,
    pub sandbox_id: String,
    #[serde(flatten)]
    pub phase: SandboxInstancePhaseReport,
    /// The gateway currently accepts this instance's supervision.
    pub ready: bool,
}

impl SandboxInstanceStatusReport {
    /// The wire form of this report.
    #[must_use]
    pub fn to_proto(&self) -> SandboxInstanceStatus {
        let (phase, exit_code, error) = match &self.phase {
            SandboxInstancePhaseReport::Starting => {
                (SandboxInstancePhase::Starting, 0, String::new())
            }
            SandboxInstancePhaseReport::Supervising => {
                (SandboxInstancePhase::Supervising, 0, String::new())
            }
            SandboxInstancePhaseReport::Stopping => {
                (SandboxInstancePhase::Stopping, 0, String::new())
            }
            SandboxInstancePhaseReport::Exited { exit_code } => {
                (SandboxInstancePhase::Exited, *exit_code, String::new())
            }
            SandboxInstancePhaseReport::Failed { error } => {
                (SandboxInstancePhase::Failed, 0, error.clone())
            }
        };
        SandboxInstanceStatus {
            route: self.route.clone(),
            sandbox_id: self.sandbox_id.clone(),
            phase: phase.into(),
            ready: self.ready,
            exit_code,
            error,
        }
    }

    /// Read a wire status. An unknown phase reads as a failure, so a newer
    /// host can never look healthy to an older gateway.
    #[must_use]
    pub fn from_proto(status: &SandboxInstanceStatus) -> Self {
        let phase = match SandboxInstancePhase::try_from(status.phase) {
            Ok(SandboxInstancePhase::Starting) => SandboxInstancePhaseReport::Starting,
            Ok(SandboxInstancePhase::Supervising) => SandboxInstancePhaseReport::Supervising,
            Ok(SandboxInstancePhase::Stopping) => SandboxInstancePhaseReport::Stopping,
            Ok(SandboxInstancePhase::Exited) => SandboxInstancePhaseReport::Exited {
                exit_code: status.exit_code,
            },
            Ok(SandboxInstancePhase::Failed) => SandboxInstancePhaseReport::Failed {
                error: status.error.clone(),
            },
            Ok(SandboxInstancePhase::Unspecified) | Err(_) => SandboxInstancePhaseReport::Failed {
                error: "sandbox instance reported an unknown phase".to_string(),
            },
        };
        let ready = status.ready && !phase.is_terminal();
        Self {
            route: status.route.clone(),
            sandbox_id: status.sandbox_id.clone(),
            phase,
            ready,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_reports_round_trip_and_unknown_phases_fail_closed() {
        for report in [
            SandboxInstanceStatusReport {
                route: "rt-a".to_string(),
                sandbox_id: "sandbox-a".to_string(),
                phase: SandboxInstancePhaseReport::Supervising,
                ready: true,
            },
            SandboxInstanceStatusReport {
                route: "rt-a".to_string(),
                sandbox_id: "sandbox-a".to_string(),
                phase: SandboxInstancePhaseReport::Exited { exit_code: 3 },
                ready: false,
            },
            SandboxInstanceStatusReport {
                route: "rt-a".to_string(),
                sandbox_id: "sandbox-a".to_string(),
                phase: SandboxInstancePhaseReport::Failed {
                    error: "boom".to_string(),
                },
                ready: false,
            },
        ] {
            assert_eq!(
                SandboxInstanceStatusReport::from_proto(&report.to_proto()),
                report
            );
        }
        let unknown = SandboxInstanceStatus {
            route: "rt-a".to_string(),
            sandbox_id: "sandbox-a".to_string(),
            phase: 99,
            ready: true,
            exit_code: 0,
            error: String::new(),
        };
        let report = SandboxInstanceStatusReport::from_proto(&unknown);
        assert!(report.phase.is_terminal());
        assert!(!report.ready);
    }
}
