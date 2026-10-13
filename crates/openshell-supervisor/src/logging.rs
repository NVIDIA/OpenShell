// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor console and optional file destinations.

use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

use openshell_ocsf::{OcsfJsonlLayer, OcsfShorthandLayer};
use tracing::Subscriber;
use tracing_appender::non_blocking::{NonBlockingBuilder, WorkerGuard};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{EnvFilter, Layer, filter::LevelFilter, registry::LookupSpan};

const CONSOLE_QUEUE_LINES: usize = 1024;

/// Install console output even when the optional file sinks cannot open.
/// All console formatters share one bounded queue and submit whole records.
pub fn layers<S, W>(
    console: W,
    directory: &Path,
    console_filter: EnvFilter,
    enabled: Arc<AtomicBool>,
    schema_version: Arc<Mutex<String>>,
) -> (impl Layer<S>, Vec<WorkerGuard>, bool)
where
    S: Subscriber + for<'a> LookupSpan<'a> + 'static,
    W: Write + Send + 'static,
{
    let (console, console_guard) = NonBlockingBuilder::default()
        .buffered_lines_limit(CONSOLE_QUEUE_LINES)
        .lossy(true)
        .thread_name("openshell-console")
        .finish(console);
    let mut guards = vec![console_guard];
    let shorthand_file = file_writer(directory, "openshell", &mut guards);
    let file_available = shorthand_file.is_some();
    // Preserve the existing file-sink behavior while making stderr independent.
    let json_file = if file_available {
        file_writer(directory, "openshell-ocsf", &mut guards)
    } else {
        None
    };
    let shorthand_file = shorthand_file
        .map(|writer| OcsfShorthandLayer::new(writer).with_filter(EnvFilter::new("info")));
    let json_file = json_file.map(|writer| {
        OcsfJsonlLayer::new(writer)
            .with_enabled_flag(enabled.clone())
            .with_target_version(schema_version.clone())
            .with_filter(LevelFilter::INFO)
    });
    // Keep per-destination filters independent: a diagnostic filter must not
    // veto an explicitly enabled JSON record in another destination.
    let layers: Vec<Box<dyn Layer<S> + Send + Sync>> = vec![
        OcsfShorthandLayer::new(console.clone())
            .with_filter(console_filter)
            .boxed(),
        OcsfJsonlLayer::new(console)
            .with_console_format()
            .with_enabled_flag(enabled)
            .with_target_version(schema_version)
            .with_filter(LevelFilter::INFO)
            .boxed(),
        shorthand_file.boxed(),
        json_file.boxed(),
    ];
    (layers, guards, file_available)
}

fn file_writer(
    directory: &Path,
    prefix: &str,
    guards: &mut Vec<WorkerGuard>,
) -> Option<tracing_appender::non_blocking::NonBlocking> {
    let roller = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(prefix)
        .filename_suffix("log")
        .max_log_files(3)
        .build(directory)
        .ok()?;
    let (writer, guard) = tracing_appender::non_blocking(roller);
    guards.push(guard);
    Some(writer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_ocsf::{EventContext, NetworkActivityBuilder, ocsf_emit};
    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn context() -> EventContext {
        EventContext {
            sandbox_id: "sb-console".to_string(),
            sandbox_name: "console-test".to_string(),
            container_image: "test-image".to_string(),
            hostname: "test-host".to_string(),
            product_version: "test".to_string(),
            proxy_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            proxy_port: 3128,
            origin: openshell_ocsf::EventOrigin::Supervisor,
        }
    }

    #[test]
    fn console_json_survives_file_failure_and_disabled_diagnostics() {
        let directory = tempfile::tempdir().unwrap();
        let invalid_directory = directory.path().join("file");
        std::fs::write(&invalid_directory, "not a directory").unwrap();
        let output = Arc::new(Mutex::new(Vec::new()));
        let (layers, guards, file_available) = layers(
            Capture(output.clone()),
            &invalid_directory,
            EnvFilter::new("off"),
            Arc::new(AtomicBool::new(true)),
            Arc::new(Mutex::new(String::new())),
        );
        assert!(!file_available);
        let subscriber = tracing_subscriber::registry().with(layers);
        let event = NetworkActivityBuilder::new(&context())
            .dst_endpoint(openshell_ocsf::Endpoint::from_domain("example.com", 443))
            .message("console without a file sink")
            .build();
        let expected = event.to_json().unwrap();
        tracing::subscriber::with_default(subscriber, || ocsf_emit!(event));
        drop(guards);
        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), 1);
        let (_, json) = lines[0].split_once(" OCSF-JSON ").unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(json).unwrap(),
            expected
        );
    }

    #[test]
    fn console_and_file_json_preserve_the_same_event() {
        let directory = tempfile::tempdir().unwrap();
        let output = Arc::new(Mutex::new(Vec::new()));
        let (layers, guards, file_available) = layers(
            Capture(output.clone()),
            directory.path(),
            EnvFilter::new("info"),
            Arc::new(AtomicBool::new(true)),
            Arc::new(Mutex::new(String::new())),
        );
        assert!(file_available);
        let subscriber = tracing_subscriber::registry().with(layers);
        let event = NetworkActivityBuilder::new(&context())
            .dst_endpoint(openshell_ocsf::Endpoint::from_domain("example.com", 443))
            .build();
        let expected = event.to_json().unwrap();
        tracing::subscriber::with_default(subscriber, || ocsf_emit!(event));
        drop(guards);
        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(output.lines().any(|line| line.contains(" OCSF ")));
        let (_, json) = output
            .lines()
            .find_map(|line| line.split_once(" OCSF-JSON "))
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(json).unwrap(),
            expected
        );
        let path = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("openshell-ocsf.")
            })
            .unwrap();
        let file = std::fs::read_to_string(path).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(file.trim()).unwrap(),
            expected
        );
    }
    #[test]
    fn slow_console_drops_lines_without_blocking_producers() {
        use std::sync::{Condvar, mpsc};
        use std::time::Duration;

        struct SlowConsole {
            gate: Arc<(Mutex<bool>, Condvar)>,
            started: mpsc::SyncSender<()>,
            writes: Arc<std::sync::atomic::AtomicUsize>,
        }

        impl Write for SlowConsole {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let _ = self.started.try_send(());
                let (lock, ready) = &*self.gate;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = ready.wait(released).unwrap();
                }
                self.writes
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let invalid_directory = directory.path().join("file");
        std::fs::write(&invalid_directory, "not a directory").unwrap();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let writes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (layers, guards, _) = layers(
            SlowConsole {
                gate: gate.clone(),
                started: started_tx,
                writes: writes.clone(),
            },
            &invalid_directory,
            EnvFilter::new("info"),
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(String::new())),
        );
        let dispatch = tracing::Dispatch::new(tracing_subscriber::registry().with(layers));
        tracing::dispatcher::with_default(&dispatch, || tracing::info!("occupy writer"));
        let started = started_rx.recv_timeout(Duration::from_secs(3));
        let (done_tx, done_rx) = mpsc::channel();
        let producer = std::thread::spawn(move || {
            tracing::dispatcher::with_default(&dispatch, || {
                for index in 0..CONSOLE_QUEUE_LINES * 2 {
                    tracing::info!("queued line {index}");
                }
            });
            done_tx.send(()).unwrap();
        });
        let completed = done_rx.recv_timeout(Duration::from_secs(3));
        // Release before asserting so failure cannot strand the worker guard.
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        producer.join().unwrap();
        drop(guards);
        assert!(started.is_ok(), "console worker did not start");
        assert!(completed.is_ok(), "producer blocked on stderr backpressure");
        assert_eq!(
            writes.load(std::sync::atomic::Ordering::Relaxed),
            CONSOLE_QUEUE_LINES + 1
        );
    }
}
