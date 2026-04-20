// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Clean-env mode for supervised container processes.
//!
//! When the sandbox is launched as an OCI container (VM driver with a
//! `template.image`), the guest init strips the OCI metadata vars it received
//! from the driver and repackages the final merged container env into
//! `OPENSHELL_CONTAINER_ENV_<i>` vars before exec'ing the supervisor. It also
//! sets `OPENSHELL_CONTAINER_MODE=1`.
//!
//! In that mode the supervisor does **not** let its own environ leak to the
//! child process. It starts the child with an empty baseline and applies only
//! a documented allowlist: the container env, provider/proxy/TLS env from
//! policy, `OPENSHELL_SANDBOX=1`, and minimal shell defaults (`HOME`, `PATH`,
//! `TERM`).

use std::collections::HashMap;
use tokio::process::Command;

/// Env var that gates clean-env behavior. Set by the guest init when the
/// supervisor is launching an OCI image.
pub(crate) const CONTAINER_MODE_ENV: &str = "OPENSHELL_CONTAINER_MODE";
/// `OPENSHELL_CONTAINER_ENV_COUNT` — number of container env entries.
pub(crate) const CONTAINER_ENV_COUNT: &str = "OPENSHELL_CONTAINER_ENV_COUNT";
/// Prefix for `OPENSHELL_CONTAINER_ENV_<i>=KEY=VALUE` entries.
pub(crate) const CONTAINER_ENV_PREFIX: &str = "OPENSHELL_CONTAINER_ENV_";

/// Default search PATH for the child when none was supplied by the image.
const DEFAULT_CONTAINER_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Returns `true` when `OPENSHELL_CONTAINER_MODE=1` is set in the supervisor's
/// own environ.
pub(crate) fn is_container_mode() -> bool {
    std::env::var(CONTAINER_MODE_ENV).is_ok_and(|v| v == "1")
}

/// Read container env entries packed as `OPENSHELL_CONTAINER_ENV_<i>=KEY=VAL`
/// and return them as an ordered `(key, value)` list. Later entries win if the
/// same key is repeated, matching the merge order produced by the host.
///
/// Unparseable entries are skipped; they should have been validated upstream.
pub(crate) fn read_container_env() -> Vec<(String, String)> {
    let count: usize = std::env::var(CONTAINER_ENV_COUNT)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let Ok(raw) = std::env::var(format!("{CONTAINER_ENV_PREFIX}{i}")) else {
            continue;
        };
        let Some((key, value)) = raw.split_once('=') else {
            continue;
        };
        if !key.is_empty() {
            out.push((key.to_string(), value.to_string()));
        }
    }
    out
}

/// Clear the command's inherited environ and apply a clean baseline suitable
/// for container-mode execution.
///
/// Adds (in this order so later values win on conflict):
/// 1. Minimal shell defaults (`HOME=/sandbox`, `PATH=<default>`, `TERM=xterm`).
/// 2. Entries from [`read_container_env`] (the OCI image env + template/spec
///    overrides).
/// 3. `OPENSHELL_SANDBOX=1` marker (always set, even if the image tried to
///    override it).
///
/// Callers layer provider env, proxy env, and TLS env *after* this call; that
/// order matches the pre-existing non-container flow.
pub(crate) fn apply_clean_container_baseline(cmd: &mut Command) {
    cmd.env_clear();
    cmd.env("HOME", "/sandbox");
    cmd.env("PATH", DEFAULT_CONTAINER_PATH);
    cmd.env("TERM", "xterm");
    for (key, value) in read_container_env() {
        cmd.env(key, value);
    }
    // OPENSHELL_SANDBOX is a documented marker for programs inside the
    // sandbox. Apply after container env so images cannot disable it.
    cmd.env("OPENSHELL_SANDBOX", "1");
}

/// Parse a `KEY=VALUE` string, or `None` if it is missing an `=`.
#[cfg(test)]
pub(crate) fn parse_kv(raw: &str) -> Option<(String, String)> {
    let (key, value) = raw.split_once('=')?;
    if key.is_empty() {
        return None;
    }
    Some((key.to_string(), value.to_string()))
}

/// Build a `HashMap` of the env vars currently set on `cmd`, for testing.
#[cfg(test)]
pub(crate) fn command_env_snapshot(cmd: &Command) -> HashMap<String, String> {
    cmd.as_std()
        .get_envs()
        .filter_map(|(k, v)| {
            let key = k.to_str()?.to_string();
            let value = v?.to_str()?.to_string();
            Some((key, value))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Tests touch process-wide env vars; serialize them to avoid races.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        keys: Vec<String>,
    }

    impl EnvGuard {
        fn new() -> Self {
            Self { keys: Vec::new() }
        }

        fn set(&mut self, key: &str, value: &str) {
            self.keys.push(key.to_string());
            // SAFETY: guarded by ENV_LOCK.
            #[allow(unsafe_code)]
            unsafe {
                std::env::set_var(key, value);
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            #[allow(unsafe_code)]
            unsafe {
                for key in &self.keys {
                    std::env::remove_var(key);
                }
            }
        }
    }

    #[test]
    fn is_container_mode_matches_only_when_env_is_one() {
        let _lock = ENV_LOCK.lock().unwrap();
        let mut guard = EnvGuard::new();
        assert!(!is_container_mode(), "default should be off");
        guard.set(CONTAINER_MODE_ENV, "0");
        assert!(!is_container_mode());
        guard.set(CONTAINER_MODE_ENV, "1");
        assert!(is_container_mode());
    }

    #[test]
    fn read_container_env_decodes_ordered_pairs() {
        let _lock = ENV_LOCK.lock().unwrap();
        let mut guard = EnvGuard::new();
        guard.set(CONTAINER_ENV_COUNT, "3");
        guard.set(&format!("{CONTAINER_ENV_PREFIX}0"), "A=1");
        guard.set(&format!("{CONTAINER_ENV_PREFIX}1"), "B=2");
        guard.set(&format!("{CONTAINER_ENV_PREFIX}2"), "PATH=/custom/bin");

        let entries = read_container_env();
        assert_eq!(
            entries,
            vec![
                ("A".to_string(), "1".to_string()),
                ("B".to_string(), "2".to_string()),
                ("PATH".to_string(), "/custom/bin".to_string()),
            ]
        );
    }

    #[test]
    fn read_container_env_skips_malformed_or_missing_entries() {
        let _lock = ENV_LOCK.lock().unwrap();
        let mut guard = EnvGuard::new();
        guard.set(CONTAINER_ENV_COUNT, "3");
        guard.set(&format!("{CONTAINER_ENV_PREFIX}0"), "A=1");
        // index 1 is missing
        guard.set(&format!("{CONTAINER_ENV_PREFIX}2"), "no-equals-sign");

        let entries = read_container_env();
        assert_eq!(entries, vec![("A".to_string(), "1".to_string())]);
    }

    #[tokio::test]
    async fn apply_clean_baseline_clears_existing_env_and_seeds_defaults() {
        let _lock = ENV_LOCK.lock().unwrap();
        let mut guard = EnvGuard::new();
        guard.set(CONTAINER_ENV_COUNT, "1");
        guard.set(&format!("{CONTAINER_ENV_PREFIX}0"), "FROM_IMAGE=yes");

        let mut cmd = Command::new("/usr/bin/true");
        cmd.env("LEAKED_FROM_PARENT", "should-be-cleared");
        cmd.env("OPENSHELL_CONTROL_SECRET", "must-not-leak");
        apply_clean_container_baseline(&mut cmd);

        let env = command_env_snapshot(&cmd);
        assert_eq!(env.get("HOME"), Some(&"/sandbox".to_string()));
        assert_eq!(env.get("TERM"), Some(&"xterm".to_string()));
        assert_eq!(env.get("FROM_IMAGE"), Some(&"yes".to_string()));
        assert_eq!(env.get("OPENSHELL_SANDBOX"), Some(&"1".to_string()));
        assert!(
            !env.contains_key("LEAKED_FROM_PARENT"),
            "pre-existing env must be cleared before baseline"
        );
        assert!(
            !env.contains_key("OPENSHELL_CONTROL_SECRET"),
            "control-plane env must not leak"
        );
    }

    #[tokio::test]
    async fn container_env_cannot_override_openshell_sandbox_marker() {
        let _lock = ENV_LOCK.lock().unwrap();
        let mut guard = EnvGuard::new();
        guard.set(CONTAINER_ENV_COUNT, "1");
        guard.set(
            &format!("{CONTAINER_ENV_PREFIX}0"),
            "OPENSHELL_SANDBOX=hijacked",
        );

        let mut cmd = Command::new("/usr/bin/true");
        apply_clean_container_baseline(&mut cmd);

        let env = command_env_snapshot(&cmd);
        assert_eq!(env.get("OPENSHELL_SANDBOX"), Some(&"1".to_string()));
    }

    #[test]
    fn parse_kv_splits_on_first_equals() {
        assert_eq!(
            parse_kv("A=hello=world"),
            Some(("A".to_string(), "hello=world".to_string()))
        );
        assert_eq!(parse_kv("A="), Some(("A".to_string(), String::new())));
        assert!(parse_kv("no-equals").is_none());
        assert!(parse_kv("=value").is_none());
    }
}
