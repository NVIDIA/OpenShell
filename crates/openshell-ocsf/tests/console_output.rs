// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Collector framing, live settings, and whole-line console writes.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use openshell_ocsf::{
    EventContext, NetworkActivityBuilder, OcsfJsonlLayer, OcsfShorthandLayer, ocsf_emit,
};
use tracing_subscriber::layer::SubscriberExt;

/// Capture individual writes to verify queue entries are whole lines.
#[derive(Clone, Default)]
struct Records(Arc<Mutex<Vec<Vec<u8>>>>);

impl Write for Records {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().push(bytes.to_vec());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn payload(record: &[u8]) -> serde_json::Value {
    let line = std::str::from_utf8(record).unwrap();
    assert_eq!(line.lines().count(), 1);
    assert!(line.ends_with('\n'));
    assert!(!line.contains('\x1b'));
    let (timestamp, json) = line.trim_end().split_once(" OCSF-JSON ").unwrap();
    chrono::DateTime::parse_from_rfc3339(timestamp).unwrap();
    serde_json::from_str(json).unwrap()
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
fn console_json_toggles_and_downgrades_without_changing_event_identity() {
    let records = Records::default();
    let enabled = Arc::new(AtomicBool::new(false));
    let version = Arc::new(Mutex::new(String::new()));
    let subscriber = tracing_subscriber::registry().with(
        OcsfJsonlLayer::new(records.clone())
            .with_console_format()
            .with_enabled_flag(enabled.clone())
            .with_target_version(version.clone()),
    );
    let event = NetworkActivityBuilder::new(&context())
        .dst_endpoint(openshell_ocsf::Endpoint::from_domain("example.com", 443))
        .message("first line\nsecond line")
        .build();
    let expected = event.to_json().unwrap();
    tracing::subscriber::with_default(subscriber, || {
        ocsf_emit!(event.clone());
        tracing::warn!("diagnostics are not JSON audit events");
        enabled.store(true, Ordering::Relaxed);
        ocsf_emit!(event.clone());
        *version.lock().unwrap() = "1.3".to_string();
        ocsf_emit!(event.clone());
        enabled.store(false, Ordering::Relaxed);
        ocsf_emit!(event);
    });
    let records = records.0.lock().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(payload(&records[0]), expected);
    let downgraded = payload(&records[1]);
    assert_eq!(downgraded["metadata"]["version"], "1.3");
    assert_eq!(downgraded["metadata"]["uid"], expected["metadata"]["uid"]);
    assert_eq!(downgraded["message"], expected["message"]);
}

#[test]
fn concurrent_console_formats_submit_complete_records() {
    let records = Records::default();
    let subscriber = tracing_subscriber::registry()
        .with(OcsfShorthandLayer::new(records.clone()))
        .with(OcsfJsonlLayer::new(records.clone()).with_console_format());
    let dispatch = tracing::Dispatch::new(subscriber);
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let dispatch = dispatch.clone();
            scope.spawn(move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    for index in 0..50 {
                        tracing::info!("diagnostic {worker}:{index}");
                        ocsf_emit!(
                            NetworkActivityBuilder::new(&context())
                                .dst_endpoint(openshell_ocsf::Endpoint::from_domain(
                                    "example.com",
                                    443
                                ))
                                .message(format!("connection {worker}:{index}"))
                                .build()
                        );
                    }
                });
            });
        }
    });
    let records = records.0.lock().unwrap();
    assert_eq!(records.len(), 8 * 50 * 3);
    let mut json_count = 0;
    for record in records.iter() {
        let line = std::str::from_utf8(record).unwrap();
        assert_eq!(line.lines().count(), 1);
        assert!(line.ends_with('\n'));
        if line.contains(" OCSF-JSON ") {
            payload(record);
            json_count += 1;
        } else {
            assert!(line.contains(" OCSF ") || line.contains(" INFO "));
        }
    }
    assert_eq!(json_count, 8 * 50);
}

#[test]
fn non_json_console_records_preserve_physical_line_boundaries() {
    let records = Records::default();
    let subscriber = tracing_subscriber::registry()
        .with(OcsfShorthandLayer::new(records.clone()))
        .with(OcsfJsonlLayer::new(records.clone()).with_console_format());
    let message = "first\r\nsecond\nthird\rfourth";
    let event = openshell_ocsf::ConfigStateChangeBuilder::new(&context())
        .message(message)
        .build();
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(target: "console\r\ncontinued", message = message);
        ocsf_emit!(event);
    });
    let records = records.0.lock().unwrap();
    assert_eq!(records.len(), 3);
    for record in records.iter() {
        assert_eq!(
            record.iter().position(|byte| *byte == b'\n'),
            Some(record.len() - 1)
        );
        assert!(!record.contains(&b'\r'));
        assert_eq!(record.last(), Some(&b'\n'));
        let line = std::str::from_utf8(record).unwrap();
        if line.contains(" OCSF-JSON ") {
            assert_eq!(payload(record)["message"], message);
        } else {
            assert!(line.contains("first\\r\\nsecond\\nthird\\rfourth"));
        }
    }
}
