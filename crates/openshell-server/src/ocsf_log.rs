// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, NaiveDate, Utc};
use openshell_ocsf::OcsfEvent;
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

use crate::config_file::{OcsfLogConfig, OcsfLogRotation};

const BATCH_SIZE: usize = 100;
const FLUSH_INTERVAL: Duration = Duration::from_millis(500);
const SHUTDOWN_BUDGET: Duration = Duration::from_secs(5);

#[derive(Default)]
struct State {
    queue: VecDeque<Vec<u8>>,
    queued_bytes: usize,
    in_flight: usize,
    closed: bool,
    abandoned: bool,
    written: u64,
    losses: BTreeMap<&'static str, u64>,
}

struct Shared {
    state: Mutex<State>,
    ready: Condvar,
    config: OcsfLogConfig,
}

#[derive(Clone)]
pub struct Collector(Arc<Shared>);

impl Collector {
    fn new(config: OcsfLogConfig) -> Self {
        Self(Arc::new(Shared {
            state: Mutex::new(State::default()),
            ready: Condvar::new(),
            config,
        }))
    }

    pub(crate) fn collect(&self, event: &OcsfEvent) {
        match event.to_json_line() {
            Ok(line) => {
                self.enqueue(line.into_bytes());
            }
            Err(_) => self.record_loss("serialization", 1),
        }
    }

    fn enqueue(&self, line: Vec<u8>) -> bool {
        let mut state = self.0.state.lock().unwrap();
        let reason = if state.closed {
            Some("closed")
        } else if line.len() > self.0.config.queue_max_bytes.get() {
            Some("oversized")
        } else if state.queue.len() >= self.0.config.queue_capacity.get() {
            Some("queue_capacity")
        } else if line.len() > self.0.config.queue_max_bytes.get() - state.queued_bytes {
            Some("queue_bytes")
        } else {
            None
        };
        if let Some(reason) = reason {
            Self::loss(&mut state, reason, 1);
            return false;
        }
        state.queued_bytes += line.len();
        state.queue.push_back(line);
        Self::queue_metrics(&state);
        metrics::counter!("openshell_ocsf_log_queued_total").increment(1);
        self.0.ready.notify_one();
        true
    }

    #[allow(clippy::cast_precision_loss)]
    fn queue_metrics(state: &State) {
        metrics::gauge!("openshell_ocsf_log_queue_records").set(state.queue.len() as f64);
        metrics::gauge!("openshell_ocsf_log_queue_bytes").set(state.queued_bytes as f64);
    }

    fn loss(state: &mut State, reason: &'static str, count: u64) {
        if count > 0 {
            *state.losses.entry(reason).or_default() += count;
            metrics::counter!("openshell_ocsf_log_dropped_total", "reason" => reason)
                .increment(count);
        }
    }

    pub(crate) fn record_loss(&self, reason: &'static str, count: u64) {
        Self::loss(&mut self.0.state.lock().unwrap(), reason, count);
    }

    fn close(&self) {
        self.0.state.lock().unwrap().closed = true;
        self.0.ready.notify_all();
    }

    fn abandon(&self) {
        let mut state = self.0.state.lock().unwrap();
        state.abandoned = true;
        let queued = state.queue.len() as u64;
        let uncertain = state.in_flight as u64;
        state.queue.clear();
        state.queued_bytes = 0;
        state.in_flight = 0;
        Self::loss(&mut state, "shutdown", queued);
        Self::loss(&mut state, "shutdown_uncertain", uncertain);
        Self::queue_metrics(&state);
        self.0.ready.notify_all();
    }

    fn batch(&self) -> Option<Vec<Vec<u8>>> {
        let mut state = self.0.state.lock().unwrap();
        while state.queue.is_empty() && !state.closed {
            state = self.0.ready.wait(state).unwrap();
        }
        let deadline = Instant::now() + FLUSH_INTERVAL;
        while !state.closed && state.queue.len() < BATCH_SIZE && Instant::now() < deadline {
            state = self
                .0
                .ready
                .wait_timeout(state, deadline.saturating_duration_since(Instant::now()))
                .unwrap()
                .0;
        }
        if state.queue.is_empty() || state.abandoned {
            return None;
        }
        let count = BATCH_SIZE.min(state.queue.len());
        let batch: Vec<_> = state.queue.drain(..count).collect();
        state.queued_bytes -= batch.iter().map(Vec::len).sum::<usize>();
        state.in_flight = count;
        Self::queue_metrics(&state);
        Some(batch)
    }

    fn complete(&self, failure: Option<&'static str>) {
        let mut state = self.0.state.lock().unwrap();
        if state.abandoned {
            return;
        }
        state.in_flight -= 1;
        if let Some(reason) = failure {
            Self::loss(&mut state, reason, 1);
        } else {
            state.written += 1;
            metrics::counter!("openshell_ocsf_log_written_total").increment(1);
        }
    }
}

pub struct OcsfLog {
    collector: Collector,
    done: tokio::sync::oneshot::Receiver<()>,
}

impl OcsfLog {
    pub(crate) fn start(config: OcsfLogConfig) -> io::Result<Self> {
        let collector = Collector::new(config);
        let worker = collector.clone();
        let (done_tx, done) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("ocsf-jsonl".into())
            .spawn(move || {
                run_writer(&worker);
                let _ = done_tx.send(());
            })?;
        Ok(Self { collector, done })
    }

    pub(crate) fn collector(&self) -> Collector {
        self.collector.clone()
    }

    pub(crate) fn layer<S: Subscriber>(&self) -> impl Layer<S> + use<S> {
        CaptureLayer(self.collector())
    }

    pub(crate) async fn shutdown(mut self) {
        self.shutdown_with_budget(SHUTDOWN_BUDGET).await;
    }

    async fn shutdown_with_budget(&mut self, budget: Duration) {
        self.collector.close();
        if !matches!(
            tokio::time::timeout(budget, &mut self.done).await,
            Ok(Ok(()))
        ) {
            self.collector.abandon();
            tracing::warn!(
                "OCSF JSONL shutdown did not finish; queued records lost and outstanding writes uncertain"
            );
        }
    }
}

impl Drop for OcsfLog {
    fn drop(&mut self) {
        self.collector.close();
    }
}

struct CaptureLayer(Collector);

impl<S: Subscriber> Layer<S> for CaptureLayer {
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        if event.metadata().target() == openshell_ocsf::OCSF_TARGET
            && let Some(event) = openshell_ocsf::clone_current_event()
        {
            self.0.collect(&event);
        }
    }
}

fn run_writer(collector: &Collector) {
    let mut writer = FileWriter::new(collector.0.config.clone());
    let mut retry_at = Instant::now();
    let mut backoff = Duration::from_millis(500);
    while let Some(batch) = collector.batch() {
        for line in batch {
            if collector.0.state.lock().unwrap().abandoned {
                return;
            }
            if Instant::now() < retry_at {
                collector.complete(Some("unavailable"));
                continue;
            }
            match writer.append(&line, Utc::now().date_naive()) {
                Ok(()) => {
                    backoff = Duration::from_millis(500);
                    collector.complete(None);
                }
                Err(error) => {
                    writer.file = None;
                    metrics::counter!("openshell_ocsf_log_writer_errors_total").increment(1);
                    tracing::warn!(%error, "OCSF JSONL write failed; record may be incomplete, later records discarded until reopen");
                    collector.complete(Some("write_uncertain"));
                    retry_at = Instant::now() + backoff;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    }
}

struct FileWriter {
    config: OcsfLogConfig,
    file: Option<File>,
    day: Option<NaiveDate>,
}

impl FileWriter {
    fn new(config: OcsfLogConfig) -> Self {
        Self {
            config,
            file: None,
            day: None,
        }
    }

    fn open(&mut self) -> io::Result<()> {
        if let Some(parent) = self
            .config
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        if let Ok(metadata) = std::fs::metadata(&self.config.path)
            && !metadata.is_file()
        {
            return Err(io::Error::other(
                "OCSF log destination must be a regular file",
            ));
        }
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&self.config.path)?;
        self.day = Some(DateTime::<Utc>::from(file.metadata()?.modified()?).date_naive());
        let discarded = recover_tail(&mut file)?;
        if discarded > 0 {
            metrics::counter!("openshell_ocsf_log_recovery_discarded_bytes_total")
                .increment(discarded);
            tracing::warn!(
                discarded_bytes = discarded,
                "OCSF JSONL incomplete tail removed; number of lost records unknown"
            );
        }
        self.file = Some(file);
        Ok(())
    }

    fn append(&mut self, line: &[u8], today: NaiveDate) -> io::Result<()> {
        if self.file.is_none() {
            self.open()?;
        }
        if self.config.rotation == OcsfLogRotation::Daily && self.day != Some(today) {
            self.file = None;
            rotate(&self.config.path, self.day.unwrap())?;
            prune_rotated(&self.config.path, self.config.max_files.unwrap().get())?;
            self.open()?;
        }
        self.day = Some(today);
        append_record(self.file.as_mut().unwrap(), line)
    }
}

trait RecordFile: Write + Seek {
    fn truncate(&mut self, length: u64) -> io::Result<()>;
}

impl RecordFile for File {
    fn truncate(&mut self, length: u64) -> io::Result<()> {
        self.set_len(length)
    }
}

fn append_record(file: &mut impl RecordFile, line: &[u8]) -> io::Result<()> {
    let boundary = file.stream_position()?;
    if let Err(error) = file.write_all(line).and_then(|()| file.flush()) {
        file.truncate(boundary)?;
        file.seek(SeekFrom::Start(boundary))?;
        return Err(error);
    }
    Ok(())
}

fn recover_tail(file: &mut File) -> io::Result<u64> {
    let length = file.metadata()?.len();
    let mut end = length;
    let mut buffer = [0u8; 8192];
    while end > 0 {
        let start = end.saturating_sub(buffer.len() as u64);
        let count = usize::try_from(end - start).unwrap();
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut buffer[..count])?;
        if let Some(index) = buffer[..count].iter().rposition(|byte| *byte == b'\n') {
            let boundary = start + index as u64 + 1;
            file.set_len(boundary)?;
            file.seek(SeekFrom::Start(boundary))?;
            return Ok(length - boundary);
        }
        end = start;
    }
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(length)
}

fn rotate(path: &Path, day: NaiveDate) -> io::Result<()> {
    loop {
        let mut name = path.as_os_str().to_os_string();
        name.push(format!(".{day}.{}", uuid::Uuid::new_v4()));
        let archive = std::path::PathBuf::from(name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&archive)
        {
            Ok(reservation) => {
                drop(reservation);
                if let Err(error) = std::fs::rename(path, &archive) {
                    let _ = std::fs::remove_file(&archive);
                    return Err(error);
                }
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
}

fn prune_rotated(path: &Path, max_files: usize) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let Some(stem) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(());
    };
    let prefix = format!("{stem}.");
    let mut rotated = Vec::new();
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(suffix) = name.to_str().and_then(|name| name.strip_prefix(&prefix)) else {
            continue;
        };
        let Some((day, unique)) = suffix.split_once('.') else {
            continue;
        };
        if let Ok(day) = NaiveDate::parse_from_str(day, "%Y-%m-%d")
            && uuid::Uuid::parse_str(unique).is_ok()
            && entry.file_type()?.is_file()
        {
            rotated.push((day, entry.metadata()?.modified()?, entry.path()));
        }
    }
    rotated.sort();
    let excess = rotated.len().saturating_sub(max_files);
    for (_, _, stale) in rotated.into_iter().take(excess) {
        std::fs::remove_file(stale)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_ocsf::{ConfigStateChangeBuilder, ocsf_emit};
    use tracing_subscriber::prelude::*;

    fn config(path: &Path) -> OcsfLogConfig {
        toml::from_str(&format!(
            "path = {:?}\nrotation = 'never'\n",
            path.display().to_string()
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn gateway_native_events_are_written_with_console_off() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("events.jsonl");
        let log = OcsfLog::start(config(&path)).unwrap();
        let event = ConfigStateChangeBuilder::new(&crate::gateway_ocsf::context("", ""))
            .message("Gateway TLS configuration changed")
            .build();
        let expected: serde_json::Value =
            serde_json::from_str(&event.to_json_line().unwrap()).unwrap();
        let subscriber = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_filter(tracing_subscriber::EnvFilter::new("off")),
            )
            .with(log.layer());
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("ordinary diagnostics must not enter the file");
            ocsf_emit!(event);
        });
        log.shutdown().await;
        let contents = std::fs::read_to_string(path).unwrap();
        assert_eq!(contents.lines().count(), 1);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&contents).unwrap(),
            expected
        );
    }

    #[tokio::test]
    async fn gateway_certificate_reload_reaches_jsonl_without_a_sandbox() {
        let directory = tempfile::tempdir().unwrap();
        crate::tls_test_utils::generate_test_certs_with_ca(directory.path());
        let acceptor = crate::tls::TlsAcceptor::from_files(
            &directory.path().join("server-cert.pem"),
            &directory.path().join("server-key.pem"),
            None,
            false,
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        let path = directory.path().join("events.jsonl");
        let log = OcsfLog::start(config(&path)).unwrap();
        let subscriber = tracing_subscriber::registry().with(log.layer());
        tracing::subscriber::with_default(subscriber, || acceptor.reload().unwrap());
        log.shutdown().await;
        let contents = std::fs::read_to_string(path).unwrap();
        let event: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(
            event["message"],
            "TLS certificate config reloaded successfully"
        );
        assert_eq!(event["metadata"]["product"]["name"], "OpenShell Gateway");
        assert!(event.get("container").is_none());
    }

    #[test]
    fn queue_limits_drop_incoming_records_without_evicting_history() {
        let mut config = config(Path::new("unused"));
        config.queue_capacity = std::num::NonZeroUsize::new(2).unwrap();
        config.queue_max_bytes = std::num::NonZeroUsize::new(8).unwrap();
        let collector = Collector::new(config);
        assert!(collector.enqueue(b"1234\n".to_vec()));
        assert!(!collector.enqueue(b"5678\n".to_vec()));
        assert!(!collector.enqueue(b"oversized\n".to_vec()));
        assert!(collector.enqueue(b"0\n".to_vec()));
        assert!(!collector.enqueue(b"\n".to_vec()));
        collector.close();
        assert!(!collector.enqueue(b"\n".to_vec()));
        let state = collector.0.state.lock().unwrap();
        assert_eq!(state.queued_bytes, 7);
        assert_eq!(state.queue.front().unwrap(), b"1234\n");
        for reason in ["queue_bytes", "oversized", "queue_capacity", "closed"] {
            assert_eq!(state.losses[reason], 1);
        }
    }

    #[test]
    fn reopening_removes_only_the_incomplete_tail() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("events.jsonl");
        for prefix in [Vec::new(), b"{}\n".to_vec()] {
            let mut damaged = prefix.clone();
            damaged.extend(vec![b'x'; 20_000]);
            std::fs::write(&path, &damaged).unwrap();
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            assert_eq!(recover_tail(&mut file).unwrap(), 20_000);
            append_record(&mut file, b"{\"new\":true}\n").unwrap();
            let mut expected = prefix;
            expected.extend(b"{\"new\":true}\n");
            assert_eq!(std::fs::read(&path).unwrap(), expected);
        }
    }

    struct FailingFile {
        bytes: io::Cursor<Vec<u8>>,
        remaining: usize,
        fail_truncate: bool,
        fail_flush: bool,
    }

    impl Write for FailingFile {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::other("disk full"));
            }
            let count = bytes.len().min(self.remaining);
            self.remaining -= count;
            self.bytes.write(&bytes[..count])
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                Err(io::Error::other("flush failed"))
            } else {
                Ok(())
            }
        }
    }

    impl Seek for FailingFile {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.bytes.seek(position)
        }
    }

    impl RecordFile for FailingFile {
        fn truncate(&mut self, length: u64) -> io::Result<()> {
            if self.fail_truncate {
                return Err(io::Error::other("truncate failed"));
            }
            self.bytes
                .get_mut()
                .truncate(usize::try_from(length).unwrap());
            Ok(())
        }
    }

    #[test]
    fn partial_writes_do_not_replay_completed_records() {
        let mut file = FailingFile {
            bytes: io::Cursor::new(Vec::new()),
            remaining: 6,
            fail_truncate: false,
            fail_flush: false,
        };
        append_record(&mut file, b"{}\n").unwrap();
        assert!(append_record(&mut file, b"{\"partial\":true}\n").is_err());
        assert_eq!(file.bytes.get_ref(), b"{}\n");
        file.remaining = 100;
        append_record(&mut file, b"{\"later\":true}\n").unwrap();
        assert_eq!(file.bytes.get_ref(), b"{}\n{\"later\":true}\n");
        file.fail_flush = true;
        assert!(append_record(&mut file, b"{}\n").is_err());
        assert_eq!(file.bytes.get_ref(), b"{}\n{\"later\":true}\n");
        file.fail_truncate = true;
        assert!(append_record(&mut file, b"{}\n").is_err());
    }

    #[test]
    fn same_day_archives_never_overwrite_and_pruning_ignores_unrelated_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("events.jsonl");
        let today = Utc::now().date_naive();
        for contents in ["first\n", "second\n", "third\n"] {
            std::fs::write(&path, contents).unwrap();
            rotate(&path, today).unwrap();
        }
        let mut contents: Vec<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| std::fs::read_to_string(entry.unwrap().path()).unwrap())
            .collect();
        contents.sort();
        assert_eq!(contents, ["first\n", "second\n", "third\n"]);
        let unrelated = directory.path().join("events.jsonl.notes");
        std::fs::write(&unrelated, "keep").unwrap();
        prune_rotated(&path, 1).unwrap();
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
        assert_eq!(std::fs::read_to_string(unrelated).unwrap(), "keep");
    }

    #[test]
    fn daily_rotation_keeps_previous_day_records_out_of_the_active_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("events.jsonl");
        let mut settings = config(&path);
        settings.rotation = OcsfLogRotation::Daily;
        settings.max_files = std::num::NonZeroUsize::new(1);
        let mut writer = FileWriter::new(settings);
        let today = Utc::now().date_naive();
        writer.append(b"{}\n", today).unwrap();
        writer
            .append(b"{\"next\":true}\n", today.succ_opt().unwrap())
            .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"next\":true}\n");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[tokio::test]
    async fn invalid_destination_is_visible_outside_the_output_file() {
        let directory = tempfile::tempdir().unwrap();
        let log = OcsfLog::start(config(directory.path())).unwrap();
        let collector = log.collector();
        collector.enqueue(b"{}\n".to_vec());
        log.shutdown().await;
        let state = collector.0.state.lock().unwrap();
        assert_eq!(state.written, 0);
        assert_eq!(state.losses["write_uncertain"], 1);
    }

    #[tokio::test]
    async fn shutdown_budget_accounts_queued_and_uncertain_records() {
        let collector = Collector::new(config(Path::new("unused")));
        collector.enqueue(b"{}\n".to_vec());
        collector.0.state.lock().unwrap().in_flight = 2;
        let (_sender, done) = tokio::sync::oneshot::channel();
        let mut log = OcsfLog {
            collector: collector.clone(),
            done,
        };
        log.shutdown_with_budget(Duration::from_millis(1)).await;
        collector.complete(None);
        let state = collector.0.state.lock().unwrap();
        assert!(state.queue.is_empty());
        assert_eq!(state.losses["shutdown"], 1);
        assert_eq!(state.losses["shutdown_uncertain"], 2);
        assert_eq!(state.written, 0);
    }
}
