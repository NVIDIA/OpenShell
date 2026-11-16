// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! JSON console log format for the gateway.
//!
//! Each event becomes one line holding one JSON object. The top-level keys
//! follow the structured-logging conventions that log agents such as the
//! Google Cloud Logging agent map to entry metadata:
//!
//! - `timestamp`: RFC 3339 time in UTC.
//! - `severity`: `DEBUG`, `INFO`, `WARNING`, `ERROR`, or for OCSF events the
//!   mapped OCSF severity.
//! - `message`: the event message, or the OCSF shorthand for OCSF events.
//! - `target`: the tracing target.
//!
//! Event fields and the fields of every enclosing span are flattened next to
//! those keys, innermost value winning. An event field whose name collides
//! with a top-level key is kept under `field.<name>`. OCSF events also carry
//! the full OCSF record under `ocsf`.
//!
//! Span fields are read from the [`JsonFields`] storage that the console
//! layer must be configured with, so span values keep their JSON types.

use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing_subscriber::fmt::format::{JsonFields, Writer};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormattedFields};
use tracing_subscriber::registry::LookupSpan;

/// Keys this format writes itself. Event and span fields never replace them.
const RESERVED_KEYS: [&str; 7] = [
    "timestamp",
    "severity",
    "message",
    "target",
    "spans",
    "ocsf",
    "field",
];

/// Prefix of the fields `tracing-log` attaches to events bridged from `log`.
const LOG_FIELD_PREFIX: &str = "log.";

/// Formats gateway console events as single-line JSON objects.
pub struct JsonEventFormat;

impl<S> FormatEvent<S, JsonFields> for JsonEventFormat
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn format_event(
        &self,
        context: &FmtContext<'_, S, JsonFields>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let mut record = OrderedRecord::default();
        record.push(
            "timestamp",
            chrono::Utc::now()
                .to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
                .into(),
        );

        let metadata = event.metadata();
        let mut fields = FieldCollector::default();
        event.record(&mut fields);

        let ocsf = (metadata.target() == openshell_ocsf::OCSF_TARGET)
            .then(openshell_ocsf::clone_current_event)
            .flatten();
        let (severity, message) = match &ocsf {
            Some(ocsf) => (
                ocsf_severity(ocsf.base().severity)
                    .unwrap_or_else(|| level_severity(*metadata.level())),
                Some(Value::String(ocsf.format_shorthand())),
            ),
            None => (level_severity(*metadata.level()), fields.message.take()),
        };
        record.push("severity", severity.into());
        if let Some(message) = message {
            record.push("message", message);
        }
        let target = fields
            .log_target
            .take()
            .unwrap_or_else(|| metadata.target().to_owned());
        record.push("target", target.into());

        let mut spans = Vec::new();
        let mut flattened = Map::new();
        if let Some(scope) = context.event_scope() {
            for span in scope.from_root() {
                spans.push(Value::String(span.name().to_owned()));
                let extensions = span.extensions();
                if let Some(stored) = extensions.get::<FormattedFields<JsonFields>>()
                    && let Ok(Value::Object(span_fields)) =
                        serde_json::from_str::<Value>(stored.as_str())
                {
                    flattened.extend(span_fields);
                }
            }
        }
        // OCSF events carry their details in `ocsf`; the bridge's own tracing
        // fields are an implementation detail.
        if ocsf.is_none() {
            flattened.extend(fields.values);
        }
        if !spans.is_empty() {
            record.push("spans", Value::Array(spans));
        }
        for (key, value) in flattened {
            if RESERVED_KEYS.contains(&key.as_str()) {
                record.push(format!("field.{key}"), value);
            } else {
                record.push(key, value);
            }
        }

        if let Some(ocsf) = &ocsf
            && let Ok(json) = ocsf.to_json()
        {
            record.push("ocsf", json);
        }

        let line = serde_json::to_string(&record).map_err(|_| std::fmt::Error)?;
        writeln!(writer, "{line}")
    }
}

/// JSON object whose keys keep insertion order, so every line starts with
/// `timestamp`, `severity`, `message`, and `target`. Callers never push a key
/// twice: flattened fields are unique and reserved names are renamed.
#[derive(Default)]
struct OrderedRecord(Vec<(String, Value)>);

impl OrderedRecord {
    fn push(&mut self, key: impl Into<String>, value: Value) {
        self.0.push((key.into(), value));
    }
}

impl serde::Serialize for OrderedRecord {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

/// Cloud Logging severity name for a tracing level.
fn level_severity(level: tracing::Level) -> &'static str {
    match level {
        tracing::Level::TRACE | tracing::Level::DEBUG => "DEBUG",
        tracing::Level::INFO => "INFO",
        tracing::Level::WARN => "WARNING",
        tracing::Level::ERROR => "ERROR",
    }
}

/// Cloud Logging severity name for an OCSF severity. `None` means the OCSF
/// value carries no ordering, so the tracing level applies.
fn ocsf_severity(severity: openshell_ocsf::SeverityId) -> Option<&'static str> {
    use openshell_ocsf::SeverityId;
    match severity {
        SeverityId::Informational => Some("INFO"),
        SeverityId::Low => Some("NOTICE"),
        SeverityId::Medium => Some("WARNING"),
        SeverityId::High => Some("ERROR"),
        SeverityId::Critical => Some("CRITICAL"),
        SeverityId::Fatal => Some("ALERT"),
        SeverityId::Unknown | SeverityId::Other => None,
    }
}

/// Collects an event's fields as typed JSON values.
#[derive(Default)]
struct FieldCollector {
    message: Option<Value>,
    log_target: Option<String>,
    values: Map<String, Value>,
}

impl FieldCollector {
    fn insert(&mut self, field: &Field, value: Value) {
        match field.name() {
            "message" => self.message = Some(value),
            "log.target" => {
                if let Value::String(target) = value {
                    self.log_target = Some(target);
                }
            }
            name if name.starts_with(LOG_FIELD_PREFIX) => {}
            name => {
                self.values.insert(name.to_owned(), value);
            }
        }
    }
}

impl Visit for FieldCollector {
    fn record_f64(&mut self, field: &Field, value: f64) {
        let value = serde_json::Number::from_f64(value)
            .map_or_else(|| Value::String(value.to_string()), Value::Number);
        self.insert(field, value);
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field, value.into());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field, value.into());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field, value.into());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert(field, value.into());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.insert(field, value.to_string().into());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.insert(field, format!("{value:?}").into());
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use serde_json::Value;
    use tracing_subscriber::fmt::format::JsonFields;
    use tracing_subscriber::prelude::*;

    use super::JsonEventFormat;

    #[derive(Clone, Default)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Run `emit` under a JSON console layer and return the raw output.
    fn capture(emit: impl FnOnce()) -> String {
        let output = SharedWriter::default();
        let writer = output.clone();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .fmt_fields(JsonFields::new())
                .event_format(JsonEventFormat)
                .with_ansi(true)
                .with_writer(move || writer.clone())
                .with_filter(tracing_subscriber::EnvFilter::new("trace")),
        );
        tracing::subscriber::with_default(subscriber, emit);
        String::from_utf8(output.0.lock().unwrap().clone()).unwrap()
    }

    fn records(output: &str) -> Vec<Value> {
        output
            .lines()
            .map(|line| serde_json::from_str(line).expect("each line is one JSON object"))
            .collect()
    }

    #[test]
    fn maps_levels_to_cloud_logging_severity() {
        let output = capture(|| {
            tracing::trace!("t");
            tracing::debug!("d");
            tracing::info!("i");
            tracing::warn!("w");
            tracing::error!("e");
        });
        let severities: Vec<_> = records(&output)
            .iter()
            .map(|record| record["severity"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(severities, ["DEBUG", "DEBUG", "INFO", "WARNING", "ERROR"]);
    }

    #[test]
    fn writes_message_target_timestamp_and_flattened_fields() {
        let output = capture(|| {
            let outer = tracing::info_span!("request", sandbox = "sbx-1", attempt = 1_u64);
            let _outer = outer.enter();
            let inner = tracing::info_span!("handler", attempt = 2_u64);
            let _inner = inner.enter();
            tracing::info!(
                target: "openshell_server::test",
                count = 3_i64,
                ok = true,
                ratio = 0.5_f64,
                error = %"boom",
                "sandbox ready"
            );
        });
        let records = records(&output);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record["message"], "sandbox ready");
        assert_eq!(record["target"], "openshell_server::test");
        assert_eq!(record["severity"], "INFO");
        assert_eq!(record["count"], 3);
        assert_eq!(record["ok"], true);
        assert_eq!(record["ratio"], 0.5);
        assert_eq!(record["error"], "boom");
        assert_eq!(record["sandbox"], "sbx-1");
        assert_eq!(record["attempt"], 2, "innermost span value wins");
        assert_eq!(record["spans"], serde_json::json!(["request", "handler"]));
        assert!(record.get("fields").is_none(), "fields are flattened");
        let timestamp = record["timestamp"].as_str().unwrap();
        assert!(
            chrono::DateTime::parse_from_rfc3339(timestamp).is_ok(),
            "timestamp is RFC 3339: {timestamp}"
        );
    }

    #[test]
    fn leads_every_line_with_the_fixed_keys() {
        let output = capture(|| tracing::info!(alpha = 1_u64, "ordered"));
        let line = output.lines().next().unwrap();
        let positions: Vec<_> = [
            "\"timestamp\"",
            "\"severity\"",
            "\"message\"",
            "\"target\"",
            "\"alpha\"",
        ]
        .iter()
        .map(|key| {
            line.find(key)
                .unwrap_or_else(|| panic!("{key} missing: {line}"))
        })
        .collect();
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]), "{line}");
        assert!(line.starts_with("{\"timestamp\":"), "{line}");
    }

    #[test]
    fn keeps_colliding_fields_without_replacing_reserved_keys() {
        let output = capture(|| {
            tracing::warn!(severity = "low", target_name = "x", "collision");
        });
        let record = &records(&output)[0];
        assert_eq!(record["severity"], "WARNING");
        assert_eq!(record["field.severity"], "low");
        assert_eq!(record["target_name"], "x");
    }

    #[test]
    fn output_is_one_line_without_ansi_escapes() {
        let output = capture(|| {
            tracing::error!(
                detail = "line one\nline two",
                "multi\nline \u{1b}[31mred\u{1b}[0m"
            );
        });
        assert_eq!(output.lines().count(), 1, "one event is one line: {output}");
        assert!(
            !output.contains('\u{1b}'),
            "no raw escape bytes even with ANSI requested: {output:?}"
        );
        let record = &records(&output)[0];
        assert_eq!(record["message"], "multi\nline \u{1b}[31mred\u{1b}[0m");
        assert_eq!(record["detail"], "line one\nline two");
    }

    #[test]
    fn ocsf_events_carry_shorthand_and_full_record() {
        let event =
            openshell_ocsf::NetworkActivityBuilder::new(&crate::gateway_ocsf::context("", ""))
                .activity(openshell_ocsf::ActivityId::Open)
                .action(openshell_ocsf::ActionId::Denied)
                .disposition(openshell_ocsf::DispositionId::Blocked)
                .severity(openshell_ocsf::SeverityId::Medium)
                .dst_endpoint(openshell_ocsf::Endpoint::from_domain("example.com", 443))
                .message("CONNECT denied example.com:443")
                .build();
        let shorthand = event.format_shorthand();
        let expected = event.to_json().unwrap();
        let output = capture(|| openshell_ocsf::ocsf_emit!(event));

        let records = records(&output);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record["message"], shorthand);
        assert_eq!(record["severity"], "WARNING", "OCSF Medium maps to WARNING");
        assert_eq!(record["target"], openshell_ocsf::OCSF_TARGET);
        assert_eq!(record["ocsf"]["class_uid"], expected["class_uid"]);
        assert_eq!(record["ocsf"]["message"], "CONNECT denied example.com:443");
        assert_eq!(record["ocsf"]["severity_id"], 3);
    }

    #[test]
    fn informational_ocsf_events_are_info() {
        let event =
            openshell_ocsf::ConfigStateChangeBuilder::new(&crate::gateway_ocsf::context("", ""))
                .message("TLS certificate config reloaded successfully")
                .build();
        let output = capture(|| openshell_ocsf::ocsf_emit!(event));
        let record = &records(&output)[0];
        assert_eq!(record["severity"], "INFO");
        assert!(record["ocsf"].is_object());
    }
}
