// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Export of OCSF events as OTLP log records.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use openshell_ocsf::format::downgrade::downgrade_event;
use openshell_ocsf::{OCSF_TARGET, OcsfEvent, OcsfSchemaVersion, SeverityId, clone_current_event};
use opentelemetry::InstrumentationScope;
use opentelemetry::logs::{AnyValue, LogRecord as _, Logger as _, LoggerProvider as _, Severity};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::logs::{LogBatch, LogExporter, SdkLogRecord, SdkLogger, SdkLoggerProvider};
use tokio::sync::{mpsc, watch};
use tracing::{Event, Subscriber, warn};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

const SCOPE: &str = "openshell.ocsf";
const QUEUE_CAPACITY: usize = 10_000;
/// Bytes held by queued and in-flight records.
const QUEUE_MAX_BYTES: usize = 16 * 1024 * 1024;
const BATCH_SIZE: usize = 100;
/// Bytes per export request, well under the 4 MiB gRPC message limit that
/// collectors commonly apply. A record larger than this is never exported.
const BATCH_MAX_BYTES: usize = 1024 * 1024;
/// Allowance for a record's attributes, timestamps, and framing beyond its body.
const RECORD_OVERHEAD_BYTES: usize = 512;
const FLUSH_INTERVAL: Duration = Duration::from_millis(500);
const SHUTDOWN_BUDGET: Duration = Duration::from_secs(5);
const MAX_EXPORT_ATTEMPTS: usize = 4;
const INITIAL_BACKOFF: Duration = Duration::from_millis(250);
const MAX_BACKOFF: Duration = Duration::from_secs(2);
const GAP_EVENT: &str = "openshell.ocsf.gap";

/// Exports OCSF events to an OTLP collector as log records.
pub struct OcsfOtlp {
    layer: OcsfOtlpLayer,
    stop: watch::Sender<bool>,
    worker: tokio::task::JoinHandle<()>,
}

impl OcsfOtlp {
    /// Start exporting through `exporter`.
    pub fn start<E>(
        mut exporter: E,
        resource: Resource,
        schema_version: Option<OcsfSchemaVersion>,
    ) -> Self
    where
        E: LogExporter + 'static,
    {
        exporter.set_resource(&resource);
        let (sender, records) = mpsc::channel(QUEUE_CAPACITY);
        let (stop, stopped) = watch::channel(false);
        let logger = logger();
        let gap = Arc::new(Gap::default());
        let pending_bytes = Arc::new(AtomicUsize::new(0));
        let worker = ExportWorker {
            exporter,
            scope: InstrumentationScope::builder(SCOPE).build(),
            logger: logger.clone(),
            gap: Arc::clone(&gap),
            pending_bytes: Arc::clone(&pending_bytes),
        };
        let worker = tokio::spawn(worker.run(records, stopped));
        Self {
            layer: OcsfOtlpLayer {
                sender,
                logger,
                schema_version,
                gap,
                pending_bytes,
            },
            stop,
            worker,
        }
    }

    /// The `tracing` layer that queues OCSF events for export.
    pub fn layer(&self) -> OcsfOtlpLayer {
        self.layer.clone()
    }

    /// Stop accepting events and export what is queued within the shutdown budget.
    pub async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        if tokio::time::timeout(SHUTDOWN_BUDGET, &mut self.worker)
            .await
            .is_err()
        {
            self.worker.abort();
            let _ = self.worker.await;
            warn!(
                "OCSF OTLP export did not finish within the shutdown budget; remaining records dropped"
            );
        }
    }
}

/// Queues OCSF events for [`OcsfOtlp`].
///
/// Events are mapped on the emitting thread and queued without blocking. When
/// the queue is full, by record count or bytes, the event is dropped and
/// counted rather than delaying the emitter.
#[derive(Clone)]
pub struct OcsfOtlpLayer {
    sender: mpsc::Sender<Queued>,
    logger: SdkLogger,
    schema_version: Option<OcsfSchemaVersion>,
    gap: Arc<Gap>,
    pending_bytes: Arc<AtomicUsize>,
}

impl<S: Subscriber> Layer<S> for OcsfOtlpLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != OCSF_TARGET {
            return;
        }
        let Some(event) = clone_current_event() else {
            return;
        };
        let Ok(record) = log_record(&self.logger, &event, self.schema_version, SystemTime::now())
        else {
            self.gap.record_loss("serialization", 1);
            return;
        };
        let bytes = record_bytes(&record);
        if bytes > BATCH_MAX_BYTES {
            self.gap.record_loss("oversized", 1);
            return;
        }
        if self.pending_bytes.fetch_add(bytes, Ordering::SeqCst) + bytes > QUEUE_MAX_BYTES {
            self.pending_bytes.fetch_sub(bytes, Ordering::SeqCst);
            self.gap.record_loss("queue_bytes", 1);
            return;
        }
        let loss = match self.sender.try_send(Queued { record, bytes }) {
            Ok(()) => {
                metrics::counter!("openshell_ocsf_otlp_queued_total").increment(1);
                return;
            }
            Err(mpsc::error::TrySendError::Full(_)) => "queue_capacity",
            Err(mpsc::error::TrySendError::Closed(_)) => "closed",
        };
        self.pending_bytes.fetch_sub(bytes, Ordering::SeqCst);
        self.gap.record_loss(loss, 1);
    }
}

/// A queued record and the bytes it counts against the queue and its batch.
struct Queued {
    record: SdkLogRecord,
    bytes: usize,
}

/// An estimate of a record's size in an export request: its body plus an
/// allowance for everything else.
fn record_bytes(record: &SdkLogRecord) -> usize {
    let body = match record.body() {
        Some(AnyValue::String(body)) => body.as_str().len(),
        _ => 0,
    };
    body + RECORD_OVERHEAD_BYTES
}

/// Records to export together, bounded by [`BATCH_SIZE`] and [`BATCH_MAX_BYTES`].
struct Batch {
    records: Vec<SdkLogRecord>,
    bytes: usize,
}

impl Batch {
    fn new(first: Queued) -> Self {
        let mut records = Vec::with_capacity(BATCH_SIZE);
        records.push(first.record);
        Self {
            records,
            bytes: first.bytes,
        }
    }

    fn is_full(&self) -> bool {
        self.records.len() >= BATCH_SIZE
    }

    fn admits(&self, queued: &Queued) -> bool {
        self.bytes + queued.bytes <= BATCH_MAX_BYTES
    }

    fn push(&mut self, queued: Queued) {
        self.bytes += queued.bytes;
        self.records.push(queued.record);
    }

    /// Add queued records until the batch is full or the queue is empty. A
    /// record that would exceed the byte limit is left in `next`.
    async fn fill(&mut self, records: &mut mpsc::Receiver<Queued>, next: &mut Option<Queued>) {
        while !self.is_full() {
            let Some(queued) = records.recv().await else {
                return;
            };
            if !self.admits(&queued) {
                *next = Some(queued);
                return;
            }
            self.push(queued);
        }
    }
}

/// Records dropped since the last gap report, as `(dropped, since_unix_ms)`.
#[derive(Default)]
struct Gap(Mutex<Option<(u64, u64)>>);

impl Gap {
    fn record_loss(&self, reason: &'static str, records: u64) {
        metrics::counter!("openshell_ocsf_otlp_dropped_total", "reason" => reason)
            .increment(records);
        self.add(records, unix_ms(SystemTime::now()));
    }

    fn add(&self, records: u64, since_unix_ms: u64) {
        if records == 0 {
            return;
        }
        let mut gap = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        *gap = Some(match *gap {
            None => (records, since_unix_ms),
            Some((dropped, since)) => (dropped.saturating_add(records), since.min(since_unix_ms)),
        });
    }

    fn take(&self) -> Option<(u64, u64)> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).take()
    }
}

fn unix_ms(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

struct ExportWorker<E> {
    exporter: E,
    scope: InstrumentationScope,
    logger: SdkLogger,
    gap: Arc<Gap>,
    pending_bytes: Arc<AtomicUsize>,
}

impl<E: LogExporter> ExportWorker<E> {
    /// Export queued records in batches bounded by [`BATCH_SIZE`] and
    /// [`BATCH_MAX_BYTES`], waiting at most [`FLUSH_INTERVAL`] for a batch to
    /// fill. Once stopped, each remaining batch is attempted once so shutdown
    /// fits its budget.
    async fn run(self, mut records: mpsc::Receiver<Queued>, mut stopped: watch::Receiver<bool>) {
        let mut next = None;
        while !*stopped.borrow() {
            let first = if let Some(queued) = next.take() {
                queued
            } else {
                let received = tokio::select! {
                    _ = stopped.wait_for(|stopped| *stopped) => break,
                    received = records.recv() => received,
                };
                let Some(queued) = received else { break };
                queued
            };
            let mut batch = Batch::new(first);
            let _ = tokio::time::timeout(FLUSH_INTERVAL, batch.fill(&mut records, &mut next)).await;
            self.export(batch, MAX_EXPORT_ATTEMPTS).await;
        }

        records.close();
        loop {
            let first = if let Some(queued) = next.take() {
                queued
            } else {
                let Some(queued) = records.recv().await else {
                    break;
                };
                queued
            };
            let mut batch = Batch::new(first);
            batch.fill(&mut records, &mut next).await;
            self.export(batch, 1).await;
        }
        let _ = self.exporter.shutdown();
    }

    /// Export one batch, appending a gap record when records were dropped. If
    /// the batch fails, its records are counted as dropped and the gap is kept
    /// for the next batch.
    async fn export(&self, mut batch: Batch, attempts: usize) {
        let records = batch.records.len() as u64;
        let gap = self.gap.take();
        if let Some((dropped, since_unix_ms)) = gap {
            batch
                .records
                .push(gap_record(&self.logger, dropped, since_unix_ms));
        }
        let result = self.export_with_retry(&batch.records, attempts).await;
        self.pending_bytes.fetch_sub(batch.bytes, Ordering::SeqCst);
        match result {
            Ok(()) => {
                metrics::counter!("openshell_ocsf_otlp_exported_total").increment(records);
            }
            Err(error) => {
                warn!(%error, records, "OCSF OTLP export failed; dropping the batch");
                if let Some((dropped, since_unix_ms)) = gap {
                    self.gap.add(dropped, since_unix_ms);
                }
                self.gap.record_loss("export_failed", records);
            }
        }
    }

    /// A retry can resend records the collector already accepted, so delivery
    /// is at least once.
    async fn export_with_retry(&self, batch: &[SdkLogRecord], attempts: usize) -> OTelSdkResult {
        let entries: Vec<_> = batch.iter().map(|record| (record, &self.scope)).collect();
        let mut backoff = INITIAL_BACKOFF;
        let mut attempt = 1;
        loop {
            // The SDK documents `LogBatch::new` as reserved for its own
            // processors. Submitting batches directly keeps queueing, retries,
            // and loss accounting here instead of in the SDK's batch processor.
            match self.exporter.export(LogBatch::new(&entries)).await {
                Ok(()) => return Ok(()),
                Err(error) => {
                    metrics::counter!("openshell_ocsf_otlp_export_errors_total").increment(1);
                    if attempt >= attempts {
                        return Err(error);
                    }
                }
            }
            metrics::counter!("openshell_ocsf_otlp_retries_total").increment(1);
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
            attempt += 1;
        }
    }
}

/// A warning record reporting OCSF records dropped before export.
fn gap_record(logger: &SdkLogger, dropped: u64, since_unix_ms: u64) -> SdkLogRecord {
    let now = SystemTime::now();
    let mut record = logger.create_log_record();
    record.set_event_name(GAP_EVENT);
    record.set_timestamp(now);
    record.set_observed_timestamp(now);
    record.set_severity_number(Severity::Warn);
    record.set_severity_text("WARN");
    record.set_body(AnyValue::String(
        format!("OCSF log records dropped before export: {dropped}").into(),
    ));
    record.add_attribute(
        "openshell.ocsf.gap.dropped",
        i64::try_from(dropped).unwrap_or(i64::MAX),
    );
    record.add_attribute(
        "openshell.ocsf.gap.since_unix_ms",
        i64::try_from(since_unix_ms).unwrap_or(i64::MAX),
    );
    record
}

fn logger() -> SdkLogger {
    SdkLoggerProvider::builder().build().logger(SCOPE)
}

/// Map one OCSF event onto an OTLP log record.
///
/// The body is the OCSF JSON record, downgraded when a schema version is
/// configured. Attributes come from the event itself, so identifiers that a
/// downgrade strips, such as the sandbox container, remain available for
/// routing.
fn log_record(
    logger: &SdkLogger,
    event: &OcsfEvent,
    schema_version: Option<OcsfSchemaVersion>,
    observed: SystemTime,
) -> Result<SdkLogRecord, serde_json::Error> {
    let base = event.base();
    let mut record = logger.create_log_record();
    if let Ok(time_ms) = u64::try_from(base.time) {
        record.set_timestamp(SystemTime::UNIX_EPOCH + Duration::from_millis(time_ms));
    }
    record.set_observed_timestamp(observed);
    record.set_severity_number(severity(base.severity));
    record.set_severity_text(base.severity.label());
    record.add_attribute("ocsf.class_uid", i64::from(base.class_uid));
    record.add_attribute("ocsf.activity_id", i64::from(base.activity_id));
    record.add_attribute("ocsf.severity_id", i64::from(base.severity.as_u8()));
    if let Some(uid) = &base.metadata.uid {
        record.add_attribute("ocsf.metadata.uid", uid.clone());
    }
    if let Some(sandbox_id) = base
        .container
        .as_ref()
        .and_then(|container| container.uid.clone())
        .filter(|id| !id.is_empty())
    {
        record.add_attribute("openshell.sandbox.id", sandbox_id);
    }

    let body = match schema_version {
        None => serde_json::to_string(event)?,
        Some(schema_version) => {
            let mut body = serde_json::to_value(event)?;
            downgrade_event(&mut body, schema_version.as_str());
            serde_json::to_string(&body)?
        }
    };
    record.set_body(AnyValue::String(body.into()));
    Ok(record)
}

/// Map an OCSF severity onto an OTLP severity.
///
/// OCSF ranks more levels than OTLP has bands. Low and Medium share the WARN
/// band and High and Critical the ERROR band, using the second slot for the
/// higher level so OCSF ordering survives.
fn severity(severity: SeverityId) -> Severity {
    match severity {
        SeverityId::Unknown | SeverityId::Informational | SeverityId::Other => Severity::Info,
        SeverityId::Low => Severity::Warn,
        SeverityId::Medium => Severity::Warn2,
        SeverityId::High => Severity::Error,
        SeverityId::Critical => Severity::Error2,
        SeverityId::Fatal => Severity::Fatal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_ocsf::{ConfigStateChangeBuilder, EventContext, EventOrigin, ocsf_emit};
    use opentelemetry::Key;
    use opentelemetry::logs::{AnyValue, Severity};
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::prelude::*;

    fn event(sandbox_id: &str, severity: SeverityId) -> OcsfEvent {
        ConfigStateChangeBuilder::new(&event_context(sandbox_id))
            .severity(severity)
            .message("policy approved")
            .build()
    }

    fn event_context(sandbox_id: &str) -> EventContext {
        EventContext {
            sandbox_id: sandbox_id.to_string(),
            sandbox_name: "sandbox-name".to_string(),
            container_image: String::new(),
            hostname: "host".to_string(),
            product_version: "0.0.0".to_string(),
            proxy_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            proxy_port: 0,
            origin: EventOrigin::Gateway {
                name: "test-gateway".to_string(),
            },
        }
    }

    fn native(event: &OcsfEvent) -> serde_json::Value {
        serde_json::to_value(event).unwrap()
    }

    fn body(record: &SdkLogRecord) -> serde_json::Value {
        let Some(AnyValue::String(body)) = record.body() else {
            panic!("expected a string body, got {:?}", record.body());
        };
        serde_json::from_str(body.as_str()).unwrap()
    }

    fn attribute(record: &SdkLogRecord, key: &'static str) -> Option<AnyValue> {
        record
            .attributes_iter()
            .find(|(name, _)| *name == Key::from_static_str(key))
            .map(|(_, value)| value.clone())
    }

    fn record(event: &OcsfEvent, schema_version: Option<OcsfSchemaVersion>) -> SdkLogRecord {
        log_record(&logger(), event, schema_version, SystemTime::UNIX_EPOCH).unwrap()
    }

    #[test]
    fn body_is_the_native_ocsf_json_record() {
        let event = event("sandbox-1", SeverityId::Informational);
        assert_eq!(body(&record(&event, None)), native(&event));
    }

    #[test]
    fn body_follows_the_configured_schema_version() {
        let event = event("sandbox-1", SeverityId::Informational);
        let body = body(&record(&event, Some(OcsfSchemaVersion::V1_3)));
        assert_eq!(body["metadata"]["version"], "1.3");
        assert!(body.get("container").is_none());
    }

    #[test]
    fn timestamps_are_event_time_and_observed_time() {
        let event = event("sandbox-1", SeverityId::Informational);
        let observed = SystemTime::UNIX_EPOCH + Duration::from_secs(42);
        let record = log_record(&logger(), &event, None, observed).unwrap();
        let time_ms = native(&event)["time"].as_u64().unwrap();
        assert_eq!(
            record.timestamp(),
            Some(SystemTime::UNIX_EPOCH + Duration::from_millis(time_ms))
        );
        assert_eq!(record.observed_timestamp(), Some(observed));
    }

    #[test]
    fn ocsf_severity_keeps_its_order_in_otlp_bands() {
        for (severity, number) in [
            (SeverityId::Unknown, Severity::Info),
            (SeverityId::Informational, Severity::Info),
            (SeverityId::Low, Severity::Warn),
            (SeverityId::Medium, Severity::Warn2),
            (SeverityId::High, Severity::Error),
            (SeverityId::Critical, Severity::Error2),
            (SeverityId::Fatal, Severity::Fatal),
            (SeverityId::Other, Severity::Info),
        ] {
            let record = record(&event("", severity), None);
            assert_eq!(record.severity_number(), Some(number), "{severity:?}");
            assert_eq!(record.severity_text(), Some(severity.label()));
        }
    }

    #[test]
    fn attributes_identify_the_event_and_its_sandbox() {
        let event = event("sandbox-1", SeverityId::Medium);
        let native = native(&event);
        // The sandbox identity survives a downgrade that strips `container`.
        let record = record(&event, Some(OcsfSchemaVersion::V1_1));
        let int = |key| match attribute(&record, key) {
            Some(AnyValue::Int(value)) => value,
            other => panic!("{key}: {other:?}"),
        };
        assert_eq!(int("ocsf.class_uid"), native["class_uid"].as_i64().unwrap());
        assert_eq!(
            int("ocsf.activity_id"),
            native["activity_id"].as_i64().unwrap()
        );
        assert_eq!(int("ocsf.severity_id"), 3);
        assert_eq!(
            attribute(&record, "ocsf.metadata.uid"),
            Some(AnyValue::String(
                native["metadata"]["uid"]
                    .as_str()
                    .unwrap()
                    .to_string()
                    .into()
            ))
        );
        assert_eq!(
            attribute(&record, "openshell.sandbox.id"),
            Some(AnyValue::String("sandbox-1".into()))
        );
    }

    #[test]
    fn events_without_a_sandbox_carry_no_sandbox_attribute() {
        let record = record(&event("", SeverityId::Informational), None);
        assert!(attribute(&record, "openshell.sandbox.id").is_none());
    }

    #[test]
    fn gap_sums_losses_from_the_earliest_and_resets_when_taken() {
        let gap = Gap::default();
        assert_eq!(gap.take(), None);
        gap.add(2, 200);
        gap.add(3, 100);
        gap.add(0, 50);
        assert_eq!(gap.take(), Some((5, 100)));
        assert_eq!(gap.take(), None);
    }

    /// One exported record with its instrumentation scope name.
    #[derive(Debug)]
    struct Exported {
        record: SdkLogRecord,
        scope: String,
    }

    /// Records every exported batch and the resource the worker assigns.
    ///
    /// The first `failures` export attempts fail as if the collector were down.
    #[derive(Debug, Clone, Default)]
    struct RecordingExporter {
        exported: Arc<Mutex<Vec<Exported>>>,
        resource: Arc<Mutex<Option<Resource>>>,
        failures: Arc<AtomicUsize>,
        attempts: Arc<AtomicUsize>,
        batch_bytes: Arc<Mutex<Vec<usize>>>,
    }

    impl RecordingExporter {
        fn failing(failures: usize) -> Self {
            let exporter = Self::default();
            exporter.failures.store(failures, Ordering::SeqCst);
            exporter
        }

        fn exported(&self) -> std::sync::MutexGuard<'_, Vec<Exported>> {
            self.exported.lock().unwrap()
        }

        fn attempts(&self) -> usize {
            self.attempts.load(Ordering::SeqCst)
        }

        fn service_name(&self) -> Option<String> {
            self.resource
                .lock()
                .unwrap()
                .as_ref()?
                .get(&Key::from_static_str("service.name"))
                .map(|value| value.to_string())
        }
    }

    impl LogExporter for RecordingExporter {
        fn export(&self, batch: LogBatch<'_>) -> impl Future<Output = OTelSdkResult> + Send {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            if self
                .failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                    left.checked_sub(1)
                })
                .is_ok()
            {
                return std::future::ready(Err(OTelSdkError::InternalFailure(
                    "collector unavailable".to_string(),
                )));
            }
            self.batch_bytes
                .lock()
                .unwrap()
                .push(batch.iter().map(|(record, _)| record_bytes(record)).sum());
            self.exported()
                .extend(batch.iter().map(|(record, scope)| Exported {
                    record: record.clone(),
                    scope: scope.name().to_string(),
                }));
            std::future::ready(Ok(()))
        }

        fn set_resource(&mut self, resource: &Resource) {
            *self.resource.lock().unwrap() = Some(resource.clone());
        }
    }

    fn exporter_resource() -> Resource {
        Resource::builder()
            .with_service_name("openshell-test")
            .build()
    }

    /// Emit events whose messages are `message_bytes` long.
    fn emit_sized(otlp: &OcsfOtlp, events: usize, message_bytes: usize) {
        let subscriber = tracing_subscriber::registry().with(otlp.layer());
        tracing::subscriber::with_default(subscriber, || {
            for _ in 0..events {
                ocsf_emit!(
                    ConfigStateChangeBuilder::new(&event_context(""))
                        .message("x".repeat(message_bytes))
                        .build()
                );
            }
        });
    }

    fn emit(otlp: &OcsfOtlp, events: usize) {
        let subscriber = tracing_subscriber::registry().with(otlp.layer());
        tracing::subscriber::with_default(subscriber, || {
            for _ in 0..events {
                ocsf_emit!(event("", SeverityId::Informational));
            }
        });
    }

    #[tokio::test]
    async fn emitted_ocsf_events_reach_the_exporter_with_its_resource() {
        let exporter = RecordingExporter::default();
        let otlp = OcsfOtlp::start(exporter.clone(), exporter_resource(), None);
        let subscriber = tracing_subscriber::registry().with(otlp.layer());
        let event = event("sandbox-1", SeverityId::Medium);
        let expected = native(&event);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("ordinary diagnostics are not exported");
            ocsf_emit!(event);
        });
        otlp.shutdown().await;

        let records = exporter.exported();
        assert_eq!(records.len(), 1);
        assert_eq!(body(&records[0].record), expected);
        assert_eq!(records[0].scope, SCOPE);
        assert_eq!(exporter.service_name().as_deref(), Some("openshell-test"));
    }

    #[tokio::test]
    async fn shutdown_exports_every_queued_record_in_bounded_batches() {
        let exporter = RecordingExporter::default();
        let otlp = OcsfOtlp::start(exporter.clone(), exporter_resource(), None);
        emit(&otlp, BATCH_SIZE * 2 + 1);
        otlp.shutdown().await;
        assert_eq!(exporter.exported().len(), BATCH_SIZE * 2 + 1);
    }

    /// Let the paused-clock worker export everything queued so far.
    async fn settle() {
        tokio::time::sleep(Duration::from_mins(1)).await;
    }

    fn is_gap(exported: &Exported) -> bool {
        exported.record.event_name() == Some(GAP_EVENT)
    }

    #[tokio::test(start_paused = true)]
    async fn transient_export_failures_are_retried_without_loss() {
        let exporter = RecordingExporter::failing(MAX_EXPORT_ATTEMPTS - 1);
        let otlp = OcsfOtlp::start(exporter.clone(), exporter_resource(), None);
        emit(&otlp, 3);
        settle().await;
        otlp.shutdown().await;

        assert_eq!(exporter.attempts(), MAX_EXPORT_ATTEMPTS);
        let records = exporter.exported();
        assert_eq!(records.len(), 3);
        assert!(!records.iter().any(is_gap));
    }

    #[tokio::test(start_paused = true)]
    async fn exhausted_retries_drop_the_batch_and_report_the_gap_next() {
        let exporter = RecordingExporter::failing(MAX_EXPORT_ATTEMPTS);
        let otlp = OcsfOtlp::start(exporter.clone(), exporter_resource(), None);
        emit(&otlp, 3);
        settle().await;
        emit(&otlp, 1);
        settle().await;
        otlp.shutdown().await;

        let records = exporter.exported();
        assert_eq!(records.len(), 2);
        let gap = records
            .iter()
            .find(|record| is_gap(record))
            .expect("gap record");
        assert_eq!(
            attribute(&gap.record, "openshell.ocsf.gap.dropped"),
            Some(AnyValue::Int(3))
        );
        assert_eq!(gap.record.severity_number(), Some(Severity::Warn));
        assert_eq!(
            records
                .iter()
                .filter(|record| attribute(&record.record, "ocsf.class_uid").is_some())
                .count(),
            1
        );
    }

    #[tokio::test(start_paused = true)]
    async fn batches_stay_within_the_byte_limit() {
        let exporter = RecordingExporter::default();
        let otlp = OcsfOtlp::start(exporter.clone(), exporter_resource(), None);
        emit_sized(&otlp, 5, BATCH_MAX_BYTES * 2 / 5);
        settle().await;
        let pending_bytes = Arc::clone(&otlp.layer.pending_bytes);
        otlp.shutdown().await;

        assert_eq!(pending_bytes.load(Ordering::SeqCst), 0);
        assert_eq!(exporter.exported().len(), 5);
        let batch_bytes = exporter.batch_bytes.lock().unwrap();
        assert!(batch_bytes.len() > 1, "{batch_bytes:?}");
        assert!(
            batch_bytes.iter().all(|bytes| *bytes <= BATCH_MAX_BYTES),
            "{batch_bytes:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn records_larger_than_a_batch_are_dropped_and_reported() {
        let exporter = RecordingExporter::default();
        let otlp = OcsfOtlp::start(exporter.clone(), exporter_resource(), None);
        emit_sized(&otlp, 1, BATCH_MAX_BYTES);
        emit(&otlp, 1);
        settle().await;
        otlp.shutdown().await;

        let records = exporter.exported();
        assert_eq!(records.len(), 2);
        let gap = records.iter().find(|record| is_gap(record)).expect("gap");
        assert_eq!(
            attribute(&gap.record, "openshell.ocsf.gap.dropped"),
            Some(AnyValue::Int(1))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_queue_rejects_records_beyond_its_byte_limit() {
        let otlp = OcsfOtlp::start(HangingExporter::default(), exporter_resource(), None);
        let events = QUEUE_MAX_BYTES / (BATCH_MAX_BYTES / 2) + 4;
        emit_sized(&otlp, events, BATCH_MAX_BYTES / 2);

        assert!(otlp.layer.pending_bytes.load(Ordering::SeqCst) <= QUEUE_MAX_BYTES);
        let (dropped, _) = otlp.layer.gap.take().expect("dropped records");
        assert!(dropped >= 4, "dropped {dropped} of {events}");
        otlp.shutdown().await;
    }

    /// An exporter whose exports never finish, like a collector that accepts
    /// connections but never responds.
    #[derive(Debug, Default)]
    struct HangingExporter {
        alive: Arc<()>,
    }

    impl LogExporter for HangingExporter {
        fn export(&self, _batch: LogBatch<'_>) -> impl Future<Output = OTelSdkResult> + Send {
            std::future::pending()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_stops_a_worker_that_outlasts_the_budget() {
        let exporter = HangingExporter::default();
        let alive = Arc::clone(&exporter.alive);
        let otlp = OcsfOtlp::start(exporter, exporter_resource(), None);
        emit(&otlp, 1);
        settle().await;
        otlp.shutdown().await;
        assert_eq!(
            Arc::strong_count(&alive),
            1,
            "worker still owns the exporter"
        );
    }
}
