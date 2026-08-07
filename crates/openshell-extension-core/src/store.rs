// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use crate::auth::{BearerTokenSlot, TokenSlotError};

/// Fraction of a credential's remaining lifetime to consume before rotating.
/// Matches the gateway-token renewal policy so both credentials refresh well
/// before expiry rather than at it.
const REFRESH_AT_FRACTION: (i64, i64) = (4, 5);

/// Shortest interval a caller is asked to wait before retrying a rotation.
const MIN_REFRESH_DELAY_MS: i64 = 1_000;

#[derive(Clone)]
struct Entry {
    slot: BearerTokenSlot,
    /// Wall-clock point after which this credential should be rotated. Derived
    /// once at install time because a slot records only its expiry, not the
    /// lifetime it was issued with.
    refresh_after_ms: i64,
}

/// Per-service extension credentials held by one supervisor.
///
/// Cloning shares the underlying map, so the registry's middleware clients and
/// the polling loop that rotates them observe the same slots. Ownership is
/// explicit rather than process-global: tests construct independent stores and
/// cannot interfere with each other.
#[derive(Clone, Default)]
pub struct ExtensionCredentialStore {
    inner: Arc<RwLock<HashMap<String, Entry>>>,
}

impl ExtensionCredentialStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, Entry>> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, Entry>> {
        self.inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Install or rotate one credential, returning the shared slot.
    ///
    /// An existing slot is updated in place so clients already holding a clone
    /// pick up the new token without rebuilding their channel.
    pub fn install(
        &self,
        name: &str,
        token: &str,
        expires_at_ms: i64,
        now_ms: i64,
    ) -> Result<BearerTokenSlot, TokenSlotError> {
        let refresh_after_ms = refresh_deadline_ms(expires_at_ms, now_ms);
        let mut slots = self.write();
        if let Some(entry) = slots.get_mut(name) {
            entry.slot.update(token, expires_at_ms)?;
            entry.refresh_after_ms = refresh_after_ms;
            return Ok(entry.slot.clone());
        }
        let slot = BearerTokenSlot::new(token, expires_at_ms)?;
        slots.insert(
            name.to_string(),
            Entry {
                slot: slot.clone(),
                refresh_after_ms,
            },
        );
        Ok(slot)
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<BearerTokenSlot> {
        self.read().get(name).map(|entry| entry.slot.clone())
    }

    /// Snapshot the slots for `names`, or `None` if any is absent.
    #[must_use]
    pub fn slots_for(&self, names: &[String]) -> Option<HashMap<String, BearerTokenSlot>> {
        let slots = self.read();
        names
            .iter()
            .map(|name| {
                slots
                    .get(name)
                    .map(|entry| (name.clone(), entry.slot.clone()))
            })
            .collect()
    }

    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.read().keys().cloned().collect()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.read().is_empty()
    }

    /// True when any requested credential is missing or due for rotation.
    ///
    /// Callers use this to avoid rotating on every configuration poll: a
    /// 15-minute credential polled every 10 seconds would otherwise mint and
    /// re-authorize roughly ninety times per useful rotation.
    #[must_use]
    pub fn needs_refresh(&self, names: &[String], now_ms: i64) -> bool {
        let slots = self.read();
        names.iter().any(|name| {
            slots
                .get(name)
                .is_none_or(|entry| entry.refresh_after_ms <= now_ms)
        })
    }

    /// Bound `fallback` by the soonest rotation deadline so a caller's sleep
    /// never overshoots a credential that must be rotated sooner.
    #[must_use]
    pub fn next_refresh_delay(
        &self,
        fallback: std::time::Duration,
        now_ms: i64,
    ) -> std::time::Duration {
        let Some(earliest) = self
            .read()
            .values()
            .map(|entry| entry.refresh_after_ms)
            .min()
        else {
            return fallback;
        };
        let remaining_ms = earliest.saturating_sub(now_ms).max(MIN_REFRESH_DELAY_MS);
        fallback.min(std::time::Duration::from_millis(
            u64::try_from(remaining_ms).unwrap_or(u64::MAX),
        ))
    }

    /// Drop credentials for services no longer in the installed registry.
    ///
    /// Detached slots are cleared before removal so any client still holding a
    /// clone fails closed instead of continuing with a valid token.
    pub fn retain(&self, names: &HashSet<&str>) {
        self.write().retain(|name, entry| {
            let keep = names.contains(name.as_str());
            if !keep {
                entry.slot.clear();
            }
            keep
        });
    }
}

impl std::fmt::Debug for ExtensionCredentialStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExtensionCredentialStore")
            .field("services", &self.names())
            .finish_non_exhaustive()
    }
}

fn refresh_deadline_ms(expires_at_ms: i64, now_ms: i64) -> i64 {
    let remaining_ms = expires_at_ms.saturating_sub(now_ms);
    if remaining_ms <= 0 {
        return now_ms;
    }
    let consumed = remaining_ms
        .saturating_mul(REFRESH_AT_FRACTION.0)
        .checked_div(REFRESH_AT_FRACTION.1)
        .unwrap_or(remaining_ms);
    now_ms.saturating_add(consumed.max(MIN_REFRESH_DELAY_MS))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tonic::service::Interceptor;

    use super::*;

    const NOW: i64 = 1_000_000;

    /// Interceptor assertions compare against the real clock, so tests that
    /// exercise a live slot need an expiry in the actual future rather than
    /// the synthetic `NOW` used for deterministic scheduling arithmetic.
    const FAR_FUTURE_MS: i64 = 4_102_444_800_000;

    #[test]
    fn rotation_updates_existing_slots_in_place() {
        let store = ExtensionCredentialStore::new();
        let first = store
            .install("guard", "first-secret", FAR_FUTURE_MS, NOW)
            .unwrap();
        let mut interceptor = first.interceptor();

        store
            .install("guard", "second-secret", FAR_FUTURE_MS, NOW)
            .unwrap();

        // The registry's client holds a clone from the first install; rotation
        // must reach it without rebuilding the channel.
        assert_eq!(
            interceptor
                .call(tonic::Request::new(()))
                .unwrap()
                .metadata()
                .get("authorization")
                .unwrap(),
            "Bearer second-secret"
        );
    }

    #[test]
    fn refresh_is_due_only_after_four_fifths_of_the_lifetime() {
        let store = ExtensionCredentialStore::new();
        let names = vec!["guard".to_string()];
        store
            .install("guard", "secret", NOW + 900_000, NOW)
            .unwrap();

        assert!(!store.needs_refresh(&names, NOW));
        assert!(!store.needs_refresh(&names, NOW + 719_000));
        assert!(store.needs_refresh(&names, NOW + 720_001));

        // An unknown service always forces a refresh so newly attached
        // middleware acquires a credential before it is used.
        assert!(store.needs_refresh(&["other".to_string()], NOW));
    }

    #[test]
    fn poll_delay_is_bounded_by_the_soonest_rotation() {
        let store = ExtensionCredentialStore::new();
        let fallback = Duration::from_secs(10);
        assert_eq!(store.next_refresh_delay(fallback, NOW), fallback);

        // 15-minute credential: rotation is due long after the poll interval,
        // so polling cadence is unchanged.
        store
            .install("guard", "secret", NOW + 900_000, NOW)
            .unwrap();
        assert_eq!(store.next_refresh_delay(fallback, NOW), fallback);

        // Short-lived credential: the caller must wake before it is stale.
        store.install("brief", "secret", NOW + 5_000, NOW).unwrap();
        assert_eq!(
            store.next_refresh_delay(fallback, NOW),
            Duration::from_secs(4)
        );
    }

    #[test]
    fn detached_credentials_are_cleared_before_removal() {
        let store = ExtensionCredentialStore::new();
        let slot = store
            .install("detached", "secret", FAR_FUTURE_MS, NOW)
            .unwrap();
        store.install("kept", "secret", FAR_FUTURE_MS, NOW).unwrap();

        store.retain(&HashSet::from(["kept"]));

        assert_eq!(store.names(), vec!["kept".to_string()]);
        // A client still holding the detached slot must fail closed rather
        // than keep using a token that is technically still valid.
        assert_eq!(
            slot.interceptor()
                .call(tonic::Request::new(()))
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
    }

    #[test]
    fn slots_for_requires_every_requested_service() {
        let store = ExtensionCredentialStore::new();
        store
            .install("guard", "secret", NOW + 900_000, NOW)
            .unwrap();

        assert!(store.slots_for(&["guard".to_string()]).is_some());
        assert!(
            store
                .slots_for(&["guard".to_string(), "missing".to_string()])
                .is_none()
        );
    }

    #[test]
    fn already_expired_credentials_are_immediately_due() {
        let store = ExtensionCredentialStore::new();
        store.install("guard", "secret", NOW - 1, NOW).unwrap();
        assert!(store.needs_refresh(&["guard".to_string()], NOW));
    }

    #[test]
    fn stores_are_independent() {
        let first = ExtensionCredentialStore::new();
        let second = ExtensionCredentialStore::new();
        first
            .install("guard", "secret", NOW + 900_000, NOW)
            .unwrap();
        assert!(second.is_empty());
    }
}
