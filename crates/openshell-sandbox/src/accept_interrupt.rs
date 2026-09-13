// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cancellation for broker-owned blocking accepts without changing workload OFDs.
//!
//! SIGUSR2 is reserved by the sandbox binary. Its process-global disposition is
//! necessarily kernel state, not a global application context. All registration,
//! cancellation and thread ownership state belongs to one broker instance.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::io;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

const INTERRUPT_SIGNAL: libc::c_int = libc::SIGUSR2;
const INTERRUPT_INTERVAL: Duration = Duration::from_millis(10);

extern "C" fn interrupt_accept(_: libc::c_int) {}

fn reserve_signal() -> io::Result<()> {
    // SAFETY: both actions are initialized storage. The no-op handler is
    // async-signal-safe and deliberately omits SA_RESTART so accept returns EINTR.
    unsafe {
        let mut previous: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(INTERRUPT_SIGNAL, std::ptr::null(), &raw mut previous) < 0 {
            return Err(io::Error::last_os_error());
        }
        if previous.sa_sigaction != libc::SIG_DFL
            && previous.sa_sigaction != interrupt_accept as *const () as usize
        {
            return Err(io::Error::other(
                "sandbox SIGUSR2 is already reserved by another handler",
            ));
        }
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = interrupt_accept as *const () as usize;
        libc::sigemptyset(&raw mut action.sa_mask);
        if libc::sigaction(INTERRUPT_SIGNAL, &raw const action, std::ptr::null_mut()) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[derive(Default)]
struct State {
    workers: Mutex<HashMap<u64, RegisteredThread>>,
    changed: Condvar,
    stopped: AtomicBool,
}

// musl represents pthread_t as an opaque pointer, unlike glibc's integer. It
// is only passed back to pthread_kill, never dereferenced by this module.
struct RegisteredThread(libc::pthread_t);

// SAFETY: POSIX permits signaling a live pthread from another thread. The
// handle is accessed only under State::workers, and the owning worker removes
// its registration under that same mutex before returning. AcceptRegistration
// cannot move to another thread, so its Drop cannot outlive the owning worker.
unsafe impl Send for RegisteredThread {}

pub struct AcceptMonitor {
    state: Arc<State>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl AcceptMonitor {
    pub(crate) fn start(valid: impl Fn(u64) -> bool + Send + 'static) -> io::Result<Self> {
        reserve_signal()?;
        let state = Arc::new(State::default());
        let worker_state = state.clone();
        let thread = std::thread::Builder::new()
            .name("openshell-accept-cancellation".into())
            .spawn(move || monitor(&worker_state, valid))?;
        Ok(Self {
            state,
            thread: Some(thread),
        })
    }

    pub(crate) fn registrar(&self) -> AcceptRegistrar {
        AcceptRegistrar(self.state.clone())
    }
}

impl Drop for AcceptMonitor {
    fn drop(&mut self) {
        let workers = lock(&self.state.workers);
        self.state.stopped.store(true, Ordering::Release);
        self.state.changed.notify_all();
        drop(workers);
        // The monitor keeps interrupting registered workers during shutdown.
        // Registrations are removed before their threads can exit/reuse IDs.
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Clone)]
pub struct AcceptRegistrar(Arc<State>);

impl AcceptRegistrar {
    pub(crate) fn register(&self, notification_id: u64) -> io::Result<AcceptRegistration> {
        // SAFETY: this changes only the current broker worker's signal mask.
        // Workload launchers do not inherit this mask; exec resets the handler.
        let thread = unsafe {
            let mut mask: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&raw mut mask);
            libc::sigaddset(&raw mut mask, INTERRUPT_SIGNAL);
            let error =
                libc::pthread_sigmask(libc::SIG_UNBLOCK, &raw const mask, std::ptr::null_mut());
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error));
            }
            libc::pthread_self()
        };
        let mut workers = lock(&self.0.workers);
        if self.0.stopped.load(Ordering::Acquire) {
            return Err(io::Error::from_raw_os_error(libc::ECANCELED));
        }
        if workers.contains_key(&notification_id) {
            return Err(io::Error::other(
                "duplicate accept notification registration",
            ));
        }
        workers.insert(notification_id, RegisteredThread(thread));
        self.0.changed.notify_one();
        Ok(AcceptRegistration {
            state: self.0.clone(),
            notification_id,
            owning_thread: PhantomData,
        })
    }
}

pub struct AcceptRegistration {
    state: Arc<State>,
    notification_id: u64,
    // Drop must run on the registering thread before its pthread_t can expire.
    // No Rc is allocated; this marker makes the guard neither Send nor Sync.
    owning_thread: PhantomData<Rc<()>>,
}

impl AcceptRegistration {
    pub(crate) fn ensure_running(&self) -> io::Result<()> {
        if self.state.stopped.load(Ordering::Acquire) {
            Err(io::Error::from_raw_os_error(libc::ECANCELED))
        } else {
            Ok(())
        }
    }
}

impl Drop for AcceptRegistration {
    fn drop(&mut self) {
        lock(&self.state.workers).remove(&self.notification_id);
        self.state.changed.notify_one();
    }
}

fn monitor(state: &State, valid: impl Fn(u64) -> bool) {
    let mut workers = lock(&state.workers);
    loop {
        let stopped = state.stopped.load(Ordering::Acquire);
        if stopped && workers.is_empty() {
            return;
        }
        for (&notification_id, thread) in &*workers {
            if stopped || !valid(notification_id) {
                // SAFETY: the registration lock pins this live pthread_t.
                // Repeated interrupts close the check-to-accept race: a signal
                // received before accept cannot leave a later accept stranded.
                let _ = unsafe { libc::pthread_kill(thread.0, INTERRUPT_SIGNAL) };
            }
        }
        workers = if workers.is_empty() {
            state
                .changed
                .wait(workers)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        } else {
            state
                .changed
                .wait_timeout(workers, INTERRUPT_INTERVAL)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0
        };
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;

    #[test]
    fn registrar_crosses_threads_but_registration_ends_before_worker_exit() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AcceptRegistrar>();

        let monitor = AcceptMonitor::start(|_| true).unwrap();
        let registrar = monitor.registrar();
        std::thread::spawn(move || {
            let registration = registrar.register(3).unwrap();
            assert!(registrar.register(3).is_err());
            assert!(lock(&registrar.0.workers).contains_key(&3));
            drop(registration);
            assert!(lock(&registrar.0.workers).is_empty());
        })
        .join()
        .unwrap();
        assert!(lock(&monitor.state.workers).is_empty());
    }

    #[test]
    fn cancellation_interrupts_competing_accept_after_readiness_was_consumed() {
        let valid = Arc::new(AtomicBool::new(true));
        let monitored = valid.clone();
        let monitor = AcceptMonitor::start(move |_| monitored.load(Ordering::Acquire)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        // Both contenders could observe this same readable listener. Consume
        // its only connection before the second contender actually accepts.
        let accepted = listener.accept().unwrap();
        let registrar = monitor.registrar();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let registration = registrar.register(1).unwrap();
            ready_tx.send(()).unwrap();
            // SAFETY: the listener is live and null address outputs are valid.
            // Use the syscall directly: std::net retries EINTR internally.
            let result = unsafe {
                libc::accept4(
                    listener.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            assert_eq!(result, -1);
            let error = io::Error::last_os_error();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            drop(registration);
            done_tx.send(()).unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        valid.store(false, Ordering::Release);
        done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        worker.join().unwrap();
        drop((accepted, client, monitor));
    }

    #[test]
    fn shutdown_interrupts_registered_accepts_and_reclaims_the_monitor() {
        let monitor = AcceptMonitor::start(|_| true).unwrap();
        let registrar = monitor.registrar();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let registration = registrar.register(2).unwrap();
            ready_tx.send(()).unwrap();
            // SAFETY: owned listener and optional null address outputs.
            let result = unsafe {
                libc::accept4(
                    listener.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            assert_eq!(result, -1);
            assert!(registration.ensure_running().is_err());
            drop(registration);
            done_tx.send(()).unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let shutdown = std::thread::spawn(move || drop(monitor));
        done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        worker.join().unwrap();
        shutdown.join().unwrap();
    }
}
