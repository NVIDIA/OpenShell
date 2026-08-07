// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-sandbox bound on extension credential minting.
//!
//! Minting resolves the sandbox's effective policy to decide which extension
//! registrations the caller may hold credentials for. That resolution reads
//! policy history, settings, and the provider profile catalog, so an
//! unbounded caller inside a sandbox could impose real gateway cost by
//! requesting credentials in a loop.
//!
//! A well-behaved supervisor rotates at roughly 80% of the credential
//! lifetime — about once every twelve minutes for the fifteen-minute default —
//! plus a small burst at startup and on retry. The default bound leaves ample
//! headroom for that while capping what a compromised sandbox can drive.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEFAULT_WINDOW: Duration = Duration::from_secs(60);
const DEFAULT_MAX_PER_WINDOW: u32 = 10;

/// Number of tracked sandboxes above which expired windows are pruned.
const PRUNE_THRESHOLD: usize = 1_024;

struct Window {
    started: Instant,
    count: u32,
}

pub struct ExtensionMintLimiter {
    window: Duration,
    max_per_window: u32,
    windows: Mutex<HashMap<String, Window>>,
}

impl Default for ExtensionMintLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW, DEFAULT_MAX_PER_WINDOW)
    }
}

impl std::fmt::Debug for ExtensionMintLimiter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExtensionMintLimiter")
            .field("window", &self.window)
            .field("max_per_window", &self.max_per_window)
            .finish_non_exhaustive()
    }
}

impl ExtensionMintLimiter {
    #[must_use]
    pub fn new(window: Duration, max_per_window: u32) -> Self {
        Self {
            window,
            max_per_window,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Record one minting request, returning `false` when the sandbox has
    /// exhausted its window.
    pub fn try_acquire(&self, sandbox_id: &str) -> bool {
        self.try_acquire_at(sandbox_id, Instant::now())
    }

    fn try_acquire_at(&self, sandbox_id: &str, now: Instant) -> bool {
        if self.max_per_window == 0 {
            return true;
        }
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if windows.len() >= PRUNE_THRESHOLD {
            windows.retain(|_, window| now.duration_since(window.started) < self.window);
        }

        let window = windows.entry(sandbox_id.to_string()).or_insert(Window {
            started: now,
            count: 0,
        });
        if now.duration_since(window.started) >= self.window {
            window.started = now;
            window.count = 0;
        }
        if window.count >= self.max_per_window {
            return false;
        }
        window.count += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_a_burst_then_refuses_within_the_window() {
        let limiter = ExtensionMintLimiter::new(Duration::from_secs(60), 3);
        let start = Instant::now();

        for _ in 0..3 {
            assert!(limiter.try_acquire_at("sandbox-a", start));
        }
        assert!(!limiter.try_acquire_at("sandbox-a", start));
    }

    #[test]
    fn window_rollover_restores_capacity() {
        let limiter = ExtensionMintLimiter::new(Duration::from_secs(60), 1);
        let start = Instant::now();

        assert!(limiter.try_acquire_at("sandbox-a", start));
        assert!(!limiter.try_acquire_at("sandbox-a", start + Duration::from_secs(59)));
        assert!(limiter.try_acquire_at("sandbox-a", start + Duration::from_secs(60)));
    }

    #[test]
    fn sandboxes_are_limited_independently() {
        let limiter = ExtensionMintLimiter::new(Duration::from_secs(60), 1);
        let start = Instant::now();

        assert!(limiter.try_acquire_at("sandbox-a", start));
        assert!(!limiter.try_acquire_at("sandbox-a", start));
        // One noisy sandbox must not deny credentials to any other.
        assert!(limiter.try_acquire_at("sandbox-b", start));
    }

    #[test]
    fn legitimate_rotation_cadence_stays_well_inside_the_default_bound() {
        let limiter = ExtensionMintLimiter::default();
        let start = Instant::now();

        // Startup acquires once, then the poll loop rotates at ~80% of a
        // 15-minute credential. Even compressed into a single window that is
        // far below the bound.
        for minute in 0..12 {
            assert!(limiter.try_acquire_at("sandbox-a", start + Duration::from_secs(minute * 60)));
        }
    }

    #[test]
    fn a_zero_bound_disables_limiting() {
        let limiter = ExtensionMintLimiter::new(Duration::from_secs(60), 0);
        let start = Instant::now();
        for _ in 0..1_000 {
            assert!(limiter.try_acquire_at("sandbox-a", start));
        }
    }
}
