// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-replica observation of assignments with pending dedicated registrations.
//! Notifications are hints: delivery always revalidates the durable assignment.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;
use tonic::Status;
use uuid::Uuid;

use super::{ASSIGNMENT_OBJECT_TYPE, lock};
use crate::persistence::{ObjectStamp, PersistenceError, Store};

const POLL_INTERVAL: Duration = Duration::from_secs(1);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(10);
const MAX_REGISTRATIONS: usize = 4096;

#[derive(Default)]
pub struct RegistrationWatch {
    entries: Mutex<HashMap<String, Entry>>,
}

struct Entry {
    subscription: Uuid,
    changed: watch::Sender<()>,
    observed: Observation,
}

#[derive(Debug, PartialEq, Eq)]
enum Observation {
    Unknown,
    Current(Option<ObjectStamp>),
}

/// The stream owns its subscription, including cleanup on disconnect.
pub struct Registration {
    watcher: Arc<RegistrationWatch>,
    route: String,
    subscription: Uuid,
    changed: watch::Receiver<()>,
}

impl RegistrationWatch {
    pub(crate) fn subscribe(self: &Arc<Self>, route: &str) -> Result<Registration, Status> {
        let mut entries = lock(&self.entries);
        if entries.len() >= MAX_REGISTRATIONS && !entries.contains_key(route) {
            return Err(Status::resource_exhausted(
                "too many pending supervisor registrations",
            ));
        }
        let subscription = Uuid::new_v4();
        let (changed, receiver) = watch::channel(());
        // Dropping the old sender cancels a superseded local stream. The driver
        // has already authenticated this route's physical identity.
        entries.insert(
            route.to_string(),
            Entry {
                subscription,
                changed,
                observed: Observation::Unknown,
            },
        );
        Ok(Registration {
            watcher: self.clone(),
            route: route.to_string(),
            subscription,
            changed: receiver,
        })
    }

    pub(crate) fn notify(&self, route: &str) {
        if let Some(entry) = lock(&self.entries).get(route) {
            entry.changed.send_replace(());
        }
    }

    pub(crate) fn start(self: &Arc<Self>, store: Arc<Store>, mut shutdown: watch::Receiver<bool>) {
        let watcher = self.clone();
        tokio::spawn(async move {
            let mut delay = POLL_INTERVAL;
            loop {
                if *shutdown.borrow() {
                    break;
                }
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => break,
                    () = tokio::time::sleep(delay) => {}
                }
                let result = tokio::select! {
                    biased;
                    _ = shutdown.changed() => break,
                    result = watcher.observe(&store) => result,
                };
                match result {
                    Ok(()) => delay = POLL_INTERVAL,
                    Err(error) => {
                        tracing::warn!(%error, "warm supervisor registration observation failed; retrying");
                        delay = (delay * 2).min(MAX_RETRY_DELAY);
                    }
                }
            }
            lock(&watcher.entries).clear();
        });
    }

    pub(super) async fn observe(&self, store: &Store) -> Result<(), PersistenceError> {
        let subscriptions: Vec<_> = lock(&self.entries)
            .iter()
            .map(|(route, entry)| (route.clone(), entry.subscription))
            .collect();
        if subscriptions.is_empty() {
            return Ok(());
        }
        let routes: Vec<_> = subscriptions
            .iter()
            .map(|(route, _)| route.clone())
            .collect();
        let mut stamps = store
            .object_stamps(ASSIGNMENT_OBJECT_TYPE, "", &routes)
            .await?;
        let mut entries = lock(&self.entries);
        for (route, subscription) in subscriptions {
            let Some(entry) = entries
                .get_mut(&route)
                .filter(|entry| entry.subscription == subscription)
            else {
                continue;
            };
            let current = Observation::Current(stamps.remove(&route));
            if entry.observed != current {
                entry.observed = current;
                entry.changed.send_replace(());
            }
        }
        Ok(())
    }
}

impl Registration {
    pub(crate) fn cancelled(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut changed = self.changed.clone();
        async move { while changed.changed().await.is_ok() {} }
    }

    /// Seed the observation from initial validation, without overwriting an
    /// observation that raced that validation. Any queued notification remains.
    pub(crate) fn baseline(&self, stamp: ObjectStamp) {
        if let Some(entry) = lock(&self.watcher.entries)
            .get_mut(&self.route)
            .filter(|entry| entry.subscription == self.subscription)
            && entry.observed == Observation::Unknown
        {
            entry.observed = Observation::Current(Some(stamp));
        }
    }

    pub(crate) async fn changed(&mut self) -> Result<(), Status> {
        self.changed.changed().await.map_err(|_| {
            Status::unavailable("supervisor registration replaced or gateway is shutting down")
        })
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut entries = lock(&self.watcher.entries);
        if entries
            .get(&self.route)
            .is_some_and(|entry| entry.subscription == self.subscription)
        {
            entries.remove(&self.route);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::test_store;

    async fn put(store: &Store, route: &str, id: &str) {
        // Observation must not decode payloads or resolve credentials.
        store
            .put_if(
                ASSIGNMENT_OBJECT_TYPE,
                id,
                route,
                "",
                b"opaque",
                None,
                crate::persistence::WriteCondition::Unconditional,
            )
            .await
            .unwrap();
    }

    async fn stamp(store: &Store, route: &str) -> ObjectStamp {
        store
            .object_stamps(ASSIGNMENT_OBJECT_TYPE, "", &[route.into()])
            .await
            .unwrap()
            .remove(route)
            .unwrap()
    }

    #[tokio::test]
    async fn unchanged_routes_stay_asleep_and_only_changed_routes_wake() {
        let store = test_store().await;
        let watcher = Arc::new(RegistrationWatch::default());
        put(&store, "a", "id-a").await;
        put(&store, "b", "id-b").await;
        let mut a = watcher.subscribe("a").unwrap();
        let b = watcher.subscribe("b").unwrap();
        a.baseline(stamp(&store, "a").await);
        b.baseline(stamp(&store, "b").await);
        for _ in 0..5 {
            watcher.observe(&store).await.unwrap();
            assert!(!a.changed.has_changed().unwrap());
            assert!(!b.changed.has_changed().unwrap());
        }
        watcher.notify("a");
        a.changed().await.unwrap();
        assert!(!b.changed.has_changed().unwrap());
        // A different replica changes a row without a local notification.
        put(&store, "a", "id-a").await;
        watcher.observe(&store).await.unwrap();
        a.changed().await.unwrap();
        assert!(!b.changed.has_changed().unwrap());
        watcher.observe(&store).await.unwrap();
        assert!(!a.changed.has_changed().unwrap());
    }

    #[tokio::test]
    async fn deletion_and_replacement_are_observed_even_when_versions_repeat() {
        let store = test_store().await;
        let watcher = Arc::new(RegistrationWatch::default());
        put(&store, "a", "original").await;
        let mut registration = watcher.subscribe("a").unwrap();
        registration.baseline(stamp(&store, "a").await);
        store
            .delete(ASSIGNMENT_OBJECT_TYPE, "original")
            .await
            .unwrap();
        put(&store, "a", "replacement").await;
        assert_eq!(stamp(&store, "a").await.resource_version, 1);
        watcher.observe(&store).await.unwrap();
        registration.changed().await.unwrap();
        store
            .delete(ASSIGNMENT_OBJECT_TYPE, "replacement")
            .await
            .unwrap();
        watcher.observe(&store).await.unwrap();
        registration.changed().await.unwrap();
        watcher.observe(&store).await.unwrap();
        assert!(!registration.changed.has_changed().unwrap());
    }

    #[tokio::test]
    async fn observation_failure_preserves_baseline_and_recovers() {
        let store = test_store().await;
        let watcher = Arc::new(RegistrationWatch::default());
        put(&store, "a", "id-a").await;
        let mut registration = watcher.subscribe("a").unwrap();
        let before = stamp(&store, "a").await;
        registration.baseline(before.clone());
        store
            .execute_for_test("ALTER TABLE objects RENAME TO unavailable_objects")
            .await;
        assert!(watcher.observe(&store).await.is_err());
        assert!(!registration.changed.has_changed().unwrap());
        assert_eq!(
            lock(&watcher.entries)["a"].observed,
            Observation::Current(Some(before))
        );
        store
            .execute_for_test("ALTER TABLE unavailable_objects RENAME TO objects")
            .await;
        put(&store, "a", "id-a").await;
        watcher.observe(&store).await.unwrap();
        registration.changed().await.unwrap();
    }

    #[tokio::test]
    async fn subscription_retains_changes_during_initial_validation() {
        let store = test_store().await;
        let watcher = Arc::new(RegistrationWatch::default());
        put(&store, "a", "id-a").await;
        let mut registration = watcher.subscribe("a").unwrap();
        let before = stamp(&store, "a").await;
        put(&store, "a", "id-a").await;
        watcher.observe(&store).await.unwrap();
        // Initial validation finishes after a newer observation.
        registration.baseline(before);
        assert!(registration.changed.has_changed().unwrap());
        registration.changed().await.unwrap();
        watcher.observe(&store).await.unwrap();
        assert!(!registration.changed.has_changed().unwrap());
        watcher.notify("a");
        watcher.notify("a");
        registration.changed().await.unwrap();
        assert!(!registration.changed.has_changed().unwrap());
    }

    #[tokio::test]
    async fn reconnect_cancels_old_stream_and_old_cleanup_preserves_replacement() {
        let watcher = Arc::new(RegistrationWatch::default());
        let old = watcher.subscribe("a").unwrap();
        let cancelled = old.cancelled();
        let mut replacement = watcher.subscribe("a").unwrap();
        tokio::time::timeout(Duration::from_secs(1), cancelled)
            .await
            .unwrap();
        drop(old);
        assert_eq!(lock(&watcher.entries).len(), 1);
        watcher.notify("a");
        replacement.changed().await.unwrap();
        drop(replacement);
        assert!(lock(&watcher.entries).is_empty());
        // An idle watcher does not even query an unavailable store.
        let store = test_store().await;
        store.close_for_test().await;
        watcher.observe(&store).await.unwrap();
        watcher.notify("absent");
        assert!(lock(&watcher.entries).is_empty());
    }

    #[test]
    fn admission_is_bounded_but_reconnects_can_replace_at_capacity() {
        let watcher = Arc::new(RegistrationWatch::default());
        let mut registrations: Vec<_> = (0..MAX_REGISTRATIONS)
            .map(|index| watcher.subscribe(&index.to_string()).unwrap())
            .collect();
        assert_eq!(
            watcher.subscribe("extra").err().unwrap().code(),
            tonic::Code::ResourceExhausted
        );
        let replacement = watcher.subscribe("0").unwrap();
        drop(registrations.remove(0));
        assert_eq!(lock(&watcher.entries).len(), MAX_REGISTRATIONS);
        drop(replacement);
        let _extra = watcher.subscribe("extra").unwrap();
    }

    #[tokio::test]
    async fn background_observer_detects_remote_writes_and_closes_on_shutdown() {
        let store = Arc::new(test_store().await);
        let watcher = Arc::new(RegistrationWatch::default());
        put(&store, "a", "id-a").await;
        let mut registration = watcher.subscribe("a").unwrap();
        registration.baseline(stamp(&store, "a").await);
        let (shutdown, receiver) = watch::channel(false);
        watcher.start(store.clone(), receiver);
        put(&store, "a", "id-a").await;
        tokio::time::timeout(Duration::from_secs(5), registration.changed())
            .await
            .unwrap()
            .unwrap();
        shutdown.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), registration.cancelled())
            .await
            .unwrap();
        assert!(lock(&watcher.entries).is_empty());
    }
}
