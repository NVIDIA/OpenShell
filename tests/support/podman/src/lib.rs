// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Podman helpers for driver suites.
//!
//! The environment runs a Podman gateway configured with one user-namespace
//! mode and publishes the mode in `OPENSHELL_TEST_PODMAN_USERNS`:
//!
//! | Value | Gateway `[openshell.drivers.podman]` setting |
//! |---|---|
//! | `default` | no `userns` |
//! | `auto` | `userns = "auto"` |
//! | `keep-id` | `userns = "keep-id"` |
//! | `private` | `userns = "private"`, `uidmap` and `gidmap` `["0:0:1", "1:1:65535"]` |
//!
//! Under `openshell-test-runner`, the tmachine
//! `fedora-podman-*-userns-*` environments set the mode and publish it
//! (`tests/tmachine/ansible/playbooks/drivers/podman/userns.yaml`). A
//! missing or unknown value fails the test; it never skips it.
//!
//! [`reference_uid_map`] runs a container with the same mode through Podman
//! directly, with the engine from the `container-engine-support` crate, so tests
//! compare `OpenShell` with Podman's own behavior rather than with a mapping
//! baked into the test.

use container_engine_support::Engine;
use testkit::{Error, Result, ResultExt as _};

pub const USERNS_ENV: &str = "OPENSHELL_TEST_PODMAN_USERNS";

/// The gateway's Podman user-namespace mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Userns {
    /// No `userns` setting: Podman's default.
    Default,
    Auto,
    KeepId,
    /// `private` with the explicit maps `0:0:1` and `1:1:65535`.
    Private,
}

impl Userns {
    /// Read [`USERNS_ENV`].
    pub fn from_env() -> Result<Self> {
        let value = std::env::var(USERNS_ENV).unwrap_or_default();
        testkit::ensure!(
            !value.is_empty(),
            "{USERNS_ENV} is not set; this suite needs the gateway's Podman user-namespace mode (see the podman-support crate docs)"
        );
        Self::parse(&value)
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "default" => Ok(Self::Default),
            "auto" => Ok(Self::Auto),
            "keep-id" => Ok(Self::KeepId),
            "private" => Ok(Self::Private),
            other => Err(Error::msg(format!(
                "{USERNS_ENV} is {other:?}; expected default, auto, keep-id or private"
            ))),
        }
    }

    /// The `podman run` arguments for the same user namespace as the gateway.
    pub fn podman_args(self) -> &'static [&'static str] {
        match self {
            Self::Default => &[],
            Self::Auto => &["--userns", "auto"],
            Self::KeepId => &["--userns", "keep-id"],
            // Podman infers a private namespace from explicit maps; its CLI
            // rejects combining --userns private with --uidmap/--gidmap.
            Self::Private => &[
                "--uidmap",
                "0:0:1",
                "--uidmap",
                "1:1:65535",
                "--gidmap",
                "0:0:1",
                "--gidmap",
                "1:1:65535",
            ],
        }
    }
}

/// The UID map, normalized by [`normalize_uid_map`], of a container Podman
/// runs from `image` in `userns`, pulling `image` if the engine's store
/// doesn't have it. The container is removed before this returns.
///
/// In `auto` mode Podman gives each running container its own range, so call
/// this before creating the sandbox it is compared with. The sandbox then gets
/// the range the removed reference container released.
pub async fn reference_uid_map(engine: &Engine, userns: Userns, image: &str) -> Result<String> {
    let mut args = vec!["run", "--rm", "--pull", "missing"];
    args.extend(userns.podman_args());
    args.extend(["--entrypoint", "/bin/cat", image, "/proc/self/uid_map"]);
    let output = engine
        .output(args)
        .await
        .context(format!("run a {userns:?} reference container"))?;
    normalize_uid_map(&output).ok_or_else(|| {
        Error::msg(format!(
            "the {userns:?} reference container printed no UID mappings:\n{output}"
        ))
    })
}

/// The mappings in `/proc/<pid>/uid_map` output, one `inside outside length`
/// per line, with adjacent ranges merged so equivalent maps compare equal.
/// Lines that aren't mappings are skipped. `None` if there are no mappings.
pub fn normalize_uid_map(value: &str) -> Option<String> {
    let mut mappings: Vec<(u64, u64, u64)> = Vec::new();
    for line in value.lines() {
        let fields = line
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<std::result::Result<Vec<_>, _>>();
        let Ok(fields) = fields else { continue };
        let [inside, outside, length] = fields.as_slice() else {
            continue;
        };
        if let Some(previous) = mappings.last_mut()
            && previous.0.checked_add(previous.2) == Some(*inside)
            && previous.1.checked_add(previous.2) == Some(*outside)
        {
            previous.2 += *length;
        } else {
            mappings.push((*inside, *outside, *length));
        }
    }
    (!mappings.is_empty()).then(|| {
        mappings
            .iter()
            .map(|(inside, outside, length)| format!("{inside} {outside} {length}"))
            .collect::<Vec<_>>()
            .join("\n")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adjacent_uid_ranges_match_a_combined_mapping() {
        assert_eq!(
            normalize_uid_map("0 0 1\n1 1 65535\n"),
            normalize_uid_map("0 0 65536\n")
        );
    }

    #[test]
    fn non_mapping_lines_are_skipped() {
        assert_eq!(
            normalize_uid_map("podman-userns-workspace-ok\n0 1000 1\n"),
            Some("0 1000 1".to_string())
        );
        assert_eq!(normalize_uid_map("no mappings\n"), None);
    }
}
