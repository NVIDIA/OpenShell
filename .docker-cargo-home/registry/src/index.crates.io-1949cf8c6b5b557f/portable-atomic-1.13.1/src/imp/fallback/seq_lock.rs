// SPDX-License-Identifier: Apache-2.0 OR MIT

// Adapted from https://github.com/crossbeam-rs/crossbeam/blob/crossbeam-utils-0.8.21/crossbeam-utils/src/atomic/seq_lock_wide.rs.

use core::{
    mem::ManuallyDrop,
    sync::atomic::{self, AtomicU64, Ordering},
};

use super::utils::{Backoff, sc_fence};
#[cfg(portable_atomic_unsafe_assume_privileged)]
use crate::imp::interrupt::arch as interrupt;
use crate::utils::unlikely;

pub(super) type State = u64;

const LOCKED: State = 1;

/// A simple stamped lock.
pub(super) struct SeqLock {
    /// The current state of the lock.
    ///
    /// All bits except the least significant one hold the current stamp. When locked, the state
    /// equals 1 and doesn't contain a valid stamp.
    state: AtomicU64,
}

impl SeqLock {
    #[inline]
    pub(super) const fn new() -> Self {
        Self { state: AtomicU64::new(0) }
    }

    /// If not locked, returns the current stamp.
    ///
    /// This method should be called before optimistic reads.
    #[inline]
    pub(super) fn optimistic_read(&self, order: Ordering) -> Option<State> {
        if unlikely(order == Ordering::SeqCst) {
            sc_fence();
        }
        let state = self.state.load(Ordering::Acquire);
        if state == LOCKED { None } else { Some(state) }
    }

    /// Returns `true` if the current stamp is equal to `stamp`.
    ///
    /// This method should be called after optimistic reads to check whether they are valid. The
    /// argument `stamp` should correspond to the one returned by method `optimistic_read`.
    #[inline]
    pub(super) fn validate_read(&self, stamp: State, order: Ordering) -> bool {
        atomic::fence(Ordering::Acquire);
        let result = self.state.load(Ordering::Relaxed) == stamp;
        if unlikely(order == Ordering::SeqCst) && result {
            sc_fence();
        }
        result
    }

    /// Grabs the lock for writing.
    #[inline]
    pub(super) fn write(&self, order: Ordering) -> SeqLockWriteGuard<'_> {
        let emit_sc_fence = order == Ordering::SeqCst;
        if unlikely(emit_sc_fence) {
            sc_fence();
        }

        // Get current interrupt state and disable interrupts when the user
        // explicitly declares that privileged instructions are available.
        #[cfg(portable_atomic_unsafe_assume_privileged)]
        let interrupt_state = interrupt::disable();

        let mut backoff = Backoff::new();
        loop {
            let previous = self.state.swap(LOCKED, Ordering::Acquire);

            if previous != LOCKED {
                atomic::fence(Ordering::Release);

                return SeqLockWriteGuard {
                    lock: self,
                    state: previous,
                    #[cfg(portable_atomic_unsafe_assume_privileged)]
                    interrupt_state,
                    emit_sc_fence,
                };
            }

            while self.state.load(Ordering::Relaxed) == LOCKED {
                backoff.snooze();
            }
        }
    }
}

/// An RAII guard that releases the lock and increments the stamp when dropped.
#[must_use]
pub(super) struct SeqLockWriteGuard<'a> {
    /// The parent lock.
    lock: &'a SeqLock,

    /// The stamp before locking.
    state: State,

    /// The interrupt state before disabling.
    #[cfg(portable_atomic_unsafe_assume_privileged)]
    interrupt_state: interrupt::State,

    emit_sc_fence: bool,
}

impl SeqLockWriteGuard<'_> {
    /// Releases the lock without incrementing the stamp.
    #[inline]
    pub(super) fn abort(self) {
        // We specifically don't want to call drop(), since that's
        // what increments the stamp.
        let this = ManuallyDrop::new(self);

        // Restore the stamp.
        //
        // Release ordering for synchronizing with `optimistic_read`.
        this.lock.state.store(this.state, Ordering::Release);

        // Restore interrupt state.
        // SAFETY: the state was retrieved by the previous `disable`.
        #[cfg(portable_atomic_unsafe_assume_privileged)]
        unsafe {
            interrupt::restore(this.interrupt_state);
        }

        if unlikely(this.emit_sc_fence) {
            sc_fence();
        }
    }
}

impl Drop for SeqLockWriteGuard<'_> {
    #[inline]
    fn drop(&mut self) {
        // Release the lock and increment the stamp.
        //
        // Release ordering for synchronizing with `optimistic_read`.
        self.lock.state.store(self.state.wrapping_add(2), Ordering::Release);

        // Restore interrupt state.
        // SAFETY: the state was retrieved by the previous `disable`.
        #[cfg(portable_atomic_unsafe_assume_privileged)]
        unsafe {
            interrupt::restore(self.interrupt_state);
        }

        if unlikely(self.emit_sc_fence) {
            sc_fence();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Ordering, SeqLock};

    #[test]
    fn smoke() {
        for &order in &[Ordering::AcqRel, Ordering::SeqCst] {
            let lock = SeqLock::new();
            let before = lock.optimistic_read(order).unwrap();
            assert!(lock.validate_read(before, order));
            {
                let _guard = lock.write(order);
            }
            assert!(!lock.validate_read(before, order));
            let after = lock.optimistic_read(order).unwrap();
            assert_ne!(before, after);
        }
    }

    #[test]
    fn test_abort() {
        for &order in &[Ordering::AcqRel, Ordering::SeqCst] {
            let lock = SeqLock::new();
            let before = lock.optimistic_read(order).unwrap();
            {
                let guard = lock.write(order);
                guard.abort();
            }
            let after = lock.optimistic_read(order).unwrap();
            assert_eq!(before, after, "aborted write does not update the stamp");
        }
    }
}
