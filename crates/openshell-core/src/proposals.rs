// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-wide flag controlling agent-driven policy proposals.
//!
//! Initialised once during sandbox start from the `agent_policy_proposals_enabled`
//! setting and updated by the policy poll loop when the setting changes. Read
//! by the `policy.local` route handler and by the skills installer to gate the
//! agent-controlled mutation surface. Tests use [`test_helpers::ProposalsFlagGuard`]
//! to flip the flag through a serialized guard.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// Process-wide handle to the agent-proposals flag.
///
/// Set once by `run_sandbox()` during start; subsequent attempts to set it are
/// ignored. The contained `AtomicBool` is updated by the policy poll loop.
pub static AGENT_PROPOSALS_ENABLED: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// Read the current value of the agent proposals feature flag.
///
/// Returns `false` if the flag has not been initialized (e.g. during unit
/// tests), matching the documented default for the setting.
pub fn agent_proposals_enabled() -> bool {
    AGENT_PROPOSALS_ENABLED
        .get()
        .is_some_and(|flag| flag.load(Ordering::Relaxed))
}

/// Test-only helpers shared across crates' test modules.
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use std::sync::Arc;
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::MutexGuard;

    static PROPOSALS_FLAG_LOCK: LazyLock<tokio::sync::Mutex<()>> =
        LazyLock::new(|| tokio::sync::Mutex::new(()));

    /// Guard for tests that toggle the process-wide flag.
    ///
    /// Acquires a process-wide async mutex, swaps in the requested value, and
    /// restores the previous value on drop. Hold the guard for the duration of
    /// any code that reads `agent_proposals_enabled()`.
    pub struct ProposalsFlagGuard {
        prev: bool,
        flag: Arc<AtomicBool>,
        _lock: MutexGuard<'static, ()>,
    }

    impl ProposalsFlagGuard {
        pub async fn set(enabled: bool) -> Self {
            let lock = PROPOSALS_FLAG_LOCK.lock().await;
            Self::with_lock(enabled, lock)
        }

        pub fn set_blocking(enabled: bool) -> Self {
            let lock = PROPOSALS_FLAG_LOCK.blocking_lock();
            Self::with_lock(enabled, lock)
        }

        fn with_lock(enabled: bool, lock: MutexGuard<'static, ()>) -> Self {
            let flag = super::AGENT_PROPOSALS_ENABLED
                .get_or_init(|| Arc::new(AtomicBool::new(false)))
                .clone();
            let prev = flag.swap(enabled, Ordering::Relaxed);
            Self {
                prev,
                flag,
                _lock: lock,
            }
        }
    }

    impl Drop for ProposalsFlagGuard {
        fn drop(&mut self) {
            self.flag.store(self.prev, Ordering::Relaxed);
        }
    }
}
