// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The legacy driver-contract documents against golden JSON examples.
//!
//! The examples in `tests/legacy_contract/examples` are the bytes that existing
//! drivers write and existing readers accept. Each must decode and re-encode to
//! the same JSON, so a change to a type that alters its encoding fails here.

#![cfg(feature = "legacy-contract")]

use openshell_driver_sdk::jwt::{SandboxLaunchAuthentication, SupervisorAuthBundle};
use openshell_driver_sdk::legacy_contract::{BoundaryConfig, SandboxRuntimeDescriptor};
use serde_json::{Value, json};

macro_rules! example {
    ($name:literal) => {
        (
            $name,
            include_str!(concat!("legacy_contract/examples/", $name)),
        )
    };
}

const EXAMPLES: &[(&str, &str)] = &[
    example!("BoundaryConfig.runtime-initiated-unix.json"),
    example!("BoundaryConfig.runtime-initiated-routed-tcp.json"),
    example!("SandboxRuntimeDescriptor.runtime-initiated-unix.json"),
    example!("SandboxRuntimeDescriptor.runtime-initiated-routed.json"),
    example!("SandboxRuntimeDescriptor.tcp.json"),
    example!("SandboxRuntimeDescriptor.vsock.json"),
    example!("SupervisorAuthBundle.minimal.json"),
    example!("SupervisorAuthBundle.full.json"),
    example!("SandboxLaunchAuthentication.json"),
];

fn document_type(file: &str) -> &str {
    file.split('.').next().expect("example file name")
}

fn example(file: &str) -> Value {
    let (_, text) = EXAMPLES
        .iter()
        .find(|(name, _)| *name == file)
        .unwrap_or_else(|| panic!("no example {file}"));
    serde_json::from_str(text).expect("example is JSON")
}

/// Decode `document` as the named type and encode it again.
fn round_trip(document_type: &str, document: &Value) -> Result<Value, String> {
    fn through<T>(document: &Value) -> Result<Value, String>
    where
        T: serde::de::DeserializeOwned + serde::Serialize,
    {
        let value: T = serde_json::from_value(document.clone()).map_err(|e| e.to_string())?;
        serde_json::to_value(&value).map_err(|e| e.to_string())
    }
    match document_type {
        "BoundaryConfig" => through::<BoundaryConfig>(document),
        "SandboxRuntimeDescriptor" => through::<SandboxRuntimeDescriptor>(document),
        "SupervisorAuthBundle" => through::<SupervisorAuthBundle>(document),
        "SandboxLaunchAuthentication" => through::<SandboxLaunchAuthentication>(document),
        other => panic!("no type registered for {other}"),
    }
}

#[test]
fn examples_round_trip_unchanged() {
    for (file, text) in EXAMPLES {
        let document: Value = serde_json::from_str(text).expect("example is JSON");
        let written = round_trip(document_type(file), &document)
            .unwrap_or_else(|error| panic!("{file} rejected: {error}"));
        assert_eq!(written, document, "{file} changed when re-encoded");
    }
}

/// Apply `mutate` to an example and require the reader to reject the result.
fn assert_rejected(file: &str, mutate: impl FnOnce(&mut Value)) {
    let mut document = example(file);
    mutate(&mut document);
    assert!(
        round_trip(document_type(file), &document).is_err(),
        "{file}: the reader accepted an invalid document"
    );
}

#[test]
fn readers_reject_unknown_top_level_fields() {
    for file in [
        "BoundaryConfig.runtime-initiated-unix.json",
        "SandboxRuntimeDescriptor.tcp.json",
        "SupervisorAuthBundle.minimal.json",
        "SandboxLaunchAuthentication.json",
    ] {
        assert_rejected(file, |document| {
            document["unexpected"] = json!(true);
        });
    }
}

#[test]
fn readers_reject_missing_required_fields() {
    assert_rejected("BoundaryConfig.runtime-initiated-unix.json", |document| {
        document.as_object_mut().unwrap().remove("auth_epoch");
    });
    assert_rejected("SandboxRuntimeDescriptor.tcp.json", |document| {
        document.as_object_mut().unwrap().remove("tls");
    });
}

#[test]
fn readers_reject_unknown_listener_and_transport_kinds() {
    assert_rejected("BoundaryConfig.runtime-initiated-unix.json", |document| {
        document["listener"]["kind"] = json!("carrier-pigeon");
    });
    assert_rejected("SandboxRuntimeDescriptor.tcp.json", |document| {
        document["transport"]["kind"] = json!("carrier-pigeon");
    });
}

#[test]
fn readers_reject_nil_and_noncanonical_session_ids() {
    for invalid in [
        "00000000-0000-0000-0000-000000000000",
        "7D3F0A52-9C1E-4B6A-8F21-3A5E6C9D0B14",
        "7d3f0a529c1e4b6a8f213a5e6c9d0b14",
    ] {
        assert_rejected("BoundaryConfig.runtime-initiated-unix.json", |document| {
            document["session_id"] = json!(invalid);
        });
    }
}

#[test]
fn readers_reject_a_workload_identity_that_uses_root() {
    assert_rejected("BoundaryConfig.runtime-initiated-unix.json", |document| {
        document["workload_identity"]["uid"] = json!(0);
    });
}

#[test]
fn readers_reject_a_malformed_evidence_digest() {
    assert_rejected("BoundaryConfig.runtime-initiated-unix.json", |document| {
        document["provisioning_evidence"]["evidence_digest"] = json!("not-hex");
    });
}

/// Rules that serde decoding does not apply and a later validator does.
#[test]
fn some_rules_are_enforced_after_decoding() {
    let mut document = example("SandboxRuntimeDescriptor.runtime-initiated-routed.json");
    document["transport"]["route"] = json!("short");
    let descriptor: SandboxRuntimeDescriptor = serde_json::from_value(document).unwrap();
    assert!(descriptor.transport.validate().is_err());

    let mut document = example("SupervisorAuthBundle.full.json");
    document["traces_otlp_tls"] = json!(9);
    let bundle: SupervisorAuthBundle = serde_json::from_value(document).unwrap();
    assert!(bundle.validate().is_err());
}
