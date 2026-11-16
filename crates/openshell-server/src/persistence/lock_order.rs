// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Debug-build check of the mutation lock ordering rules 1, 4, and 5 in
//! [`super::mutation_lock`].
//!
//! Each held mutation guard, process-local key set, and SSH identity lock is
//! registered with the owner that acquired it: the current Tokio task, or the
//! current thread outside a task (a `block_on` root such as a
//! `#[tokio::test]` body), refined by [`branch`]. An acquisition that breaks a
//! rule panics before it waits, so a nested acquisition fails the test that
//! reaches it instead of deadlocking under contention. Release builds compile
//! the check out.
//!
//! A guard moved to another task stays registered with the owner that
//! acquired it, and nesting through a spawned task that the holder awaits is
//! not detected.

use std::future::Future;

/// A lock whose acquisition the ordering rules restrict.
#[derive(Clone, Copy, Debug)]
pub enum Lock {
    /// A mutation guard or a process-local key set (rule 4).
    Mutation,
    /// A lifecycle gate taken by waiting for it (rule 1).
    LifecycleGate,
    /// The SSH identity lock, a leaf (rule 5).
    SshIdentity,
}

/// Panics, in debug builds, when the current owner may not wait for `lock`.
pub fn check(lock: Lock) {
    #[cfg(debug_assertions)]
    imp::check(lock);
    #[cfg(not(debug_assertions))]
    let _ = lock;
}

/// Registers `lock` as held by the current owner until the result drops.
pub fn hold(lock: Lock) -> Held {
    #[cfg(debug_assertions)]
    {
        let owner = imp::owner();
        imp::hold(owner, lock);
        Held { owner, lock }
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = lock;
        Held {}
    }
}

/// Registration of one held lock. Zero-sized in release builds.
#[must_use = "dropping the registration forgets the held lock"]
pub struct Held {
    #[cfg(debug_assertions)]
    owner: imp::Owner,
    #[cfg(debug_assertions)]
    lock: Lock,
}

#[cfg(debug_assertions)]
impl Drop for Held {
    fn drop(&mut self) {
        imp::release(self.owner, self.lock);
    }
}

/// Runs `future` as its own lock owner inside the current task.
///
/// For futures that run concurrently in one task, such as the branches of
/// `join!` or `try_for_each_concurrent`, when each holds at most its own
/// guard and never waits on a sibling. Release builds return `future`.
pub fn branch<F: Future>(future: F) -> impl Future<Output = F::Output> {
    #[cfg(debug_assertions)]
    {
        imp::branch(future)
    }
    #[cfg(not(debug_assertions))]
    {
        future
    }
}

#[cfg(debug_assertions)]
mod imp {
    use super::Lock;
    use std::collections::HashMap;
    use std::future::Future;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{LazyLock, Mutex, PoisonError};

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    enum Base {
        Task(tokio::task::Id),
        Thread(std::thread::ThreadId),
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub(super) struct Owner {
        base: Base,
        branch: Option<u64>,
    }

    #[derive(Default)]
    struct Counts {
        mutation: usize,
        ssh_identity: usize,
    }

    tokio::task_local! {
        static BRANCH: u64;
    }

    static NEXT_BRANCH: AtomicU64 = AtomicU64::new(1);
    static HELD: LazyLock<Mutex<HashMap<Owner, Counts>>> = LazyLock::new(Mutex::default);

    pub(super) fn owner() -> Owner {
        let base = tokio::task::try_id()
            .map_or_else(|| Base::Thread(std::thread::current().id()), Base::Task);
        Owner {
            base,
            branch: BRANCH.try_with(|branch| *branch).ok(),
        }
    }

    pub(super) fn branch<F: Future>(future: F) -> impl Future<Output = F::Output> {
        BRANCH.scope(NEXT_BRANCH.fetch_add(1, Ordering::Relaxed), future)
    }

    pub(super) fn check(lock: Lock) {
        let owner = owner();
        let (mutation, ssh_identity) = HELD
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&owner)
            .map_or((0, 0), |counts| (counts.mutation, counts.ssh_identity));
        let allowed = match lock {
            Lock::Mutation | Lock::LifecycleGate => mutation == 0 && ssh_identity == 0,
            Lock::SshIdentity => ssh_identity == 0,
        };
        assert!(
            allowed,
            "mutation lock ordering violated: waiting for {lock:?} while holding {mutation} \
             mutation and {ssh_identity} SSH identity locks (see persistence::mutation_lock)"
        );
    }

    pub(super) fn hold(owner: Owner, lock: Lock) {
        let mut held = HELD.lock().unwrap_or_else(PoisonError::into_inner);
        let counts = held.entry(owner).or_default();
        match lock {
            Lock::Mutation => counts.mutation += 1,
            Lock::SshIdentity => counts.ssh_identity += 1,
            Lock::LifecycleGate => unreachable!("lifecycle gates are checked, not held"),
        }
    }

    pub(super) fn release(owner: Owner, lock: Lock) {
        let mut held = HELD.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(counts) = held.get_mut(&owner) else {
            return;
        };
        match lock {
            Lock::Mutation => counts.mutation -= 1,
            Lock::SshIdentity => counts.ssh_identity -= 1,
            Lock::LifecycleGate => {}
        }
        if counts.mutation == 0 && counts.ssh_identity == 0 {
            held.remove(&owner);
        }
    }
}
