// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The cleanup hooks a test registers, run after its body.

use std::any::Any;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures::FutureExt;
use futures::future::BoxFuture;

use crate::error::Result;

/// How long one cleanup hook may take.
pub const CLEANUP_TIMEOUT: Duration = Duration::from_mins(2);

type HookFn = Box<dyn FnOnce() -> BoxFuture<'static, Result> + Send>;

/// What a hook is registered for, so it can be registered once and cancelled.
/// The variants are separate namespaces, so keys of different kinds never
/// collide.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Key {
    /// The hook that deletes the sandbox with this name.
    Sandbox(String),
}

struct Hook {
    /// What the hook does, for reporting a failure.
    name: String,
    /// Registers the hook at most once; see [`Cleanup::push_keyed`].
    key: Option<Key>,
    run: HookFn,
}

impl Hook {
    fn new<F, Fut>(name: String, hook: F) -> Self
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result> + Send + 'static,
    {
        Self {
            name,
            key: None,
            run: Box::new(move || hook().boxed()),
        }
    }

    fn keyed(mut self, key: Key) -> Self {
        self.key = Some(key);
        self
    }
}

/// An ordered list of cleanup hooks, shared by a test's context and the
/// handles that register or cancel hooks.
#[derive(Clone, Default)]
pub(crate) struct Cleanup {
    hooks: Arc<Mutex<Vec<Hook>>>,
}

impl Cleanup {
    /// Add a hook. Hooks run in reverse order of registration.
    pub(crate) fn push<F, Fut>(&self, name: impl Into<String>, hook: F)
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result> + Send + 'static,
    {
        lock(&self.hooks).push(Hook::new(name.into(), hook));
    }

    /// Add a hook unless one with `key` is registered, in which case the
    /// existing hook keeps its place in the order.
    pub(crate) fn push_keyed<F, Fut>(&self, key: Key, name: impl Into<String>, hook: F)
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result> + Send + 'static,
    {
        let mut hooks = lock(&self.hooks);
        if !hooks.iter().any(|hook| hook.key.as_ref() == Some(&key)) {
            hooks.push(Hook::new(name.into(), hook).keyed(key));
        }
    }

    /// Drop the hook registered with `key`, if any, without running it.
    pub(crate) fn remove(&self, key: &Key) {
        lock(&self.hooks).retain(|hook| hook.key.as_ref() != Some(key));
    }

    /// Run every hook, last registered first, each limited to `timeout`. A
    /// hook that fails, panics, or times out doesn't stop the others. Returns
    /// one message per failed hook.
    pub(crate) async fn run(&self, timeout: Duration) -> Vec<String> {
        let mut failures = Vec::new();
        // Pop one at a time rather than draining, so the lock isn't held
        // while a hook runs. A `while let` would hold it through the body.
        loop {
            let Some(hook) = lock(&self.hooks).pop() else {
                break;
            };
            let outcome = match std::panic::catch_unwind(AssertUnwindSafe(hook.run)) {
                Ok(future) => {
                    tokio::time::timeout(timeout, AssertUnwindSafe(future).catch_unwind()).await
                }
                Err(panic) => Ok(Err(panic)),
            };
            let failure = match outcome {
                Ok(Ok(Ok(()))) => continue,
                Ok(Ok(Err(error))) => error.to_string(),
                Ok(Err(panic)) => format!("panicked: {}", panic_message(panic.as_ref())),
                Err(_) => format!("timed out after {timeout:?}"),
            };
            failures.push(format!("{}: {failure}", hook.name));
        }
        failures
    }
}

fn lock(hooks: &Mutex<Vec<Hook>>) -> std::sync::MutexGuard<'_, Vec<Hook>> {
    hooks.lock().unwrap_or_else(PoisonError::into_inner)
}

fn panic_message(panic: &(dyn Any + Send)) -> &str {
    panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload")
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::{Cleanup, Key};

    fn sandbox(name: &str) -> Key {
        Key::Sandbox(name.to_string())
    }
    use crate::error::Error;

    const TIMEOUT: Duration = Duration::from_secs(5);

    type Log = Arc<Mutex<Vec<&'static str>>>;

    /// Register a hook, keyed if `key` is set, that records `name` in `log`
    /// when it runs.
    fn record(cleanup: &Cleanup, key: Option<Key>, log: &Log, name: &'static str) {
        let log = Arc::clone(log);
        let hook = async move || {
            log.lock().unwrap().push(name);
            Ok(())
        };
        match key {
            Some(key) => cleanup.push_keyed(key, name, hook),
            None => cleanup.push(name, hook),
        }
    }

    #[tokio::test]
    async fn runs_hooks_last_registered_first() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let cleanup = Cleanup::default();
        for name in ["first", "second", "third"] {
            record(&cleanup, None, &log, name);
        }
        assert!(cleanup.run(TIMEOUT).await.is_empty());
        assert_eq!(*log.lock().unwrap(), ["third", "second", "first"]);
        // Each hook runs once.
        assert!(cleanup.run(TIMEOUT).await.is_empty());
        assert_eq!(log.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn keyed_hook_is_registered_once_and_can_be_removed() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let cleanup = Cleanup::default();
        record(&cleanup, Some(sandbox("a")), &log, "a");
        record(&cleanup, None, &log, "b");
        // Already registered: keeps its place before "b".
        record(&cleanup, Some(sandbox("a")), &log, "a again");
        record(&cleanup, Some(sandbox("c")), &log, "c");
        cleanup.remove(&sandbox("c"));
        assert!(cleanup.run(TIMEOUT).await.is_empty());
        assert_eq!(*log.lock().unwrap(), ["b", "a"]);
    }

    #[tokio::test]
    async fn a_running_hook_can_change_the_remaining_hooks() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let cleanup = Cleanup::default();
        record(&cleanup, Some(sandbox("removed")), &log, "removed");
        let handle = cleanup.clone();
        cleanup.push("remove", async move || {
            handle.remove(&sandbox("removed"));
            Ok(())
        });
        assert!(cleanup.run(TIMEOUT).await.is_empty());
        assert!(log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn failing_panicking_and_slow_hooks_are_reported_and_the_rest_still_run() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let cleanup = Cleanup::default();
        record(&cleanup, None, &log, "ok first");
        cleanup.push("slow", async || {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(())
        });
        cleanup.push("panics", async || -> crate::Result { panic!("hook panic") });
        cleanup.push(
            "panics before its future",
            || -> std::future::Ready<crate::Result> { panic!("closure panic") },
        );
        cleanup.push("fails", async || Err(Error::msg("hook error")));
        record(&cleanup, None, &log, "ok last");

        let failures = cleanup.run(Duration::from_millis(100)).await;
        assert_eq!(
            failures,
            [
                "fails: hook error",
                "panics before its future: panicked: closure panic",
                "panics: panicked: hook panic",
                "slow: timed out after 100ms",
            ]
        );
        assert_eq!(*log.lock().unwrap(), ["ok last", "ok first"]);
    }
}
