// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Disruptions: named operations the runner applies to a booted environment
//! between the `seed` and `verify` phases of a continuity run.
//!
//! The registry here is the interface: the names `--disruption` and the CI
//! matrix use. How a disruption is carried out depends on how OpenShell is
//! installed, so the installer provides the implementation, an executable at
//! `<DISRUPTIONS_DIR>/<name>` in the guest that the runner runs as the login
//! user. An installer that doesn't provide a disruption doesn't support it,
//! and the runner says so before it seeds anything.
//!
//! The runner waits for the gateway to become ready again afterwards, so an
//! executable returns when it has made the change, not when the system has
//! recovered.

use anyhow::{Result, bail};

/// Where installers stage their disruptions in the guest.
pub const DISRUPTIONS_DIR: &str = "/var/lib/openshell-qualification/disruptions";

/// One disruption.
#[derive(Debug)]
pub struct Disruption {
    pub name: &'static str,
    /// What the disruption does, for `--help` and error messages.
    pub description: &'static str,
}

impl Disruption {
    /// Where the guest's installer stages this disruption.
    pub fn path(&self) -> String {
        format!("{DISRUPTIONS_DIR}/{}", self.name)
    }
}

const ALL: &[Disruption] = &[
    Disruption {
        name: "gateway-restart",
        description: "restart the gateway service",
    },
    Disruption {
        name: "upgrade",
        description: "upgrade to the candidate the installer staged (see deb-upgrade-source)",
    },
];

/// The disruption called `name`.
pub fn find(name: &str) -> Result<&'static Disruption> {
    if let Some(found) = ALL.iter().find(|d| d.name == name) {
        return Ok(found);
    }
    let known: Vec<_> = ALL
        .iter()
        .map(|d| format!("{} ({})", d.name, d.description))
        .collect();
    bail!(
        "unknown disruption {name:?}; choose one of: {}",
        known.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_a_known_disruption_and_names_the_choices_otherwise() {
        assert_eq!(find("gateway-restart").unwrap().name, "gateway-restart");
        let error = find("nope").unwrap_err().to_string();
        assert!(error.contains("gateway-restart"), "{error}");
    }

    #[test]
    fn stages_each_disruption_under_the_disruptions_directory() {
        assert_eq!(
            find("gateway-restart").unwrap().path(),
            "/var/lib/openshell-qualification/disruptions/gateway-restart"
        );
    }
}
