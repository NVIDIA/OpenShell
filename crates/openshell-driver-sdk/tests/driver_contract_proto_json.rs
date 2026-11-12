// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The documents of `sandbox_runtime.proto` as protobuf JSON, checked against
//! the legacy documents.
//!
//! For each legacy example, the document built from the legacy Rust type must
//! equal the protobuf JSON example, and reading the protobuf JSON example must
//! give back the legacy document. The protobuf JSON examples are the
//! reference for a driver in any language that writes the new format.
//!
//! Run with `UPDATE_EXAMPLES=1` to rewrite the protobuf JSON examples from the
//! legacy ones, then review the diff.

#![cfg(feature = "legacy-contract")]

use std::path::Path;

use openshell_driver_sdk::legacy_contract::{BoundaryConfig, SandboxRuntimeDescriptor};
use openshell_driver_sdk::proto::FILE_DESCRIPTOR_SET;
use openshell_driver_sdk::proto::sandbox_runtime::v1 as pb;
use prost_reflect::{DescriptorPool, DeserializeOptions, DynamicMessage};
use serde_json::{Value, json};

const PACKAGE: &str = "openshell.sandbox.runtime.v1";

macro_rules! example {
    ($name:literal) => {
        (
            $name,
            include_str!(concat!("legacy_contract/examples/", $name)),
            include_str!(concat!("legacy_contract/proto_json/", $name)),
        )
    };
}

/// File name, legacy example, protobuf JSON example.
const EXAMPLES: &[(&str, &str, &str)] = &[
    example!("BoundaryConfig.runtime-initiated-unix.json"),
    example!("BoundaryConfig.runtime-initiated-routed-tcp.json"),
    example!("SandboxRuntimeDescriptor.runtime-initiated-unix.json"),
    example!("SandboxRuntimeDescriptor.runtime-initiated-routed.json"),
    example!("SandboxRuntimeDescriptor.tcp.json"),
    example!("SandboxRuntimeDescriptor.vsock.json"),
];

fn document_type(file: &str) -> &str {
    file.split('.').next().expect("example file name")
}

fn pool() -> DescriptorPool {
    DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("descriptor set decodes")
}

/// The protobuf JSON of the legacy document `legacy`, built through the Rust
/// conversion.
fn to_proto_json(document_type: &str, legacy: &Value) -> Value {
    fn through<L, M>(legacy: &Value) -> Vec<u8>
    where
        L: serde::de::DeserializeOwned,
        for<'a> M: From<&'a L> + prost::Message,
    {
        let legacy: L = serde_json::from_value(legacy.clone()).expect("legacy document decodes");
        M::from(&legacy).encode_to_vec()
    }
    let bytes = match document_type {
        "BoundaryConfig" => through::<BoundaryConfig, pb::BoundaryConfig>(legacy),
        "SandboxRuntimeDescriptor" => {
            through::<SandboxRuntimeDescriptor, pb::SandboxRuntimeDescriptor>(legacy)
        }
        other => panic!("no type registered for {other}"),
    };
    let descriptor = pool()
        .get_message_by_name(&format!("{PACKAGE}.{document_type}"))
        .expect("message exists");
    let message = DynamicMessage::decode(descriptor, bytes.as_slice()).expect("message decodes");
    serde_json::to_value(&message).expect("message serializes as protobuf JSON")
}

/// Read protobuf JSON as the named document and write it as the legacy
/// document.
fn to_legacy(document_type: &str, text: &str) -> Result<Value, String> {
    fn back<L, M>(message: &DynamicMessage) -> Result<Value, String>
    where
        L: TryFrom<M> + serde::Serialize,
        <L as TryFrom<M>>::Error: std::fmt::Display,
        M: prost::Message + Default,
    {
        let typed: M = message.transcode_to().map_err(|error| error.to_string())?;
        let legacy = L::try_from(typed).map_err(|error| error.to_string())?;
        serde_json::to_value(&legacy).map_err(|error| error.to_string())
    }
    let descriptor = pool()
        .get_message_by_name(&format!("{PACKAGE}.{document_type}"))
        .expect("message exists");
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let message = DynamicMessage::deserialize_with_options(
        descriptor,
        &mut deserializer,
        &DeserializeOptions::new().deny_unknown_fields(true),
    )
    .map_err(|error| error.to_string())?;
    deserializer.end().map_err(|error| error.to_string())?;
    match document_type {
        "BoundaryConfig" => back::<BoundaryConfig, pb::BoundaryConfig>(&message),
        "SandboxRuntimeDescriptor" => {
            back::<SandboxRuntimeDescriptor, pb::SandboxRuntimeDescriptor>(&message)
        }
        other => panic!("no type registered for {other}"),
    }
}

#[test]
fn update_examples_when_requested() {
    if std::env::var_os("UPDATE_EXAMPLES").is_none() {
        return;
    }
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/legacy_contract/proto_json");
    std::fs::create_dir_all(&directory).unwrap();
    for (file, legacy, _) in EXAMPLES {
        let legacy: Value = serde_json::from_str(legacy).unwrap();
        let written = to_proto_json(document_type(file), &legacy);
        std::fs::write(
            directory.join(file),
            serde_json::to_string_pretty(&written).unwrap() + "\n",
        )
        .unwrap();
    }
}

#[test]
fn the_rust_conversion_writes_the_protobuf_json_examples() {
    for (file, legacy, expected) in EXAMPLES {
        let legacy: Value = serde_json::from_str(legacy).unwrap();
        let expected: Value = serde_json::from_str(expected).unwrap();
        assert_eq!(
            to_proto_json(document_type(file), &legacy),
            expected,
            "{file}: the protobuf JSON differs from the example"
        );
    }
}

#[test]
fn reading_the_protobuf_json_examples_gives_back_the_legacy_documents() {
    for (file, legacy, proto_json) in EXAMPLES {
        let legacy: Value = serde_json::from_str(legacy).unwrap();
        let read = to_legacy(document_type(file), proto_json)
            .unwrap_or_else(|error| panic!("{file} was rejected: {error}"));
        assert_eq!(read, legacy, "{file}: reading the example changed it");
    }
}

fn example(file: &str) -> Value {
    let (_, _, text) = EXAMPLES
        .iter()
        .find(|(name, _, _)| *name == file)
        .unwrap_or_else(|| panic!("no example {file}"));
    serde_json::from_str(text).unwrap()
}

/// Apply `mutate` to a protobuf JSON example and require the reader to reject
/// the result.
fn assert_rejected(file: &str, mutate: impl FnOnce(&mut Value)) {
    let mut document = example(file);
    mutate(&mut document);
    assert!(
        to_legacy(document_type(file), &document.to_string()).is_err(),
        "{file}: the reader accepted an invalid document"
    );
}

#[test]
fn readers_reject_unknown_fields() {
    for file in [
        "BoundaryConfig.runtime-initiated-unix.json",
        "SandboxRuntimeDescriptor.tcp.json",
    ] {
        assert_rejected(file, |document| {
            document["unexpected"] = json!(true);
        });
    }
}

#[test]
fn readers_reject_a_missing_or_unsupported_version() {
    for file in [
        "BoundaryConfig.runtime-initiated-unix.json",
        "SandboxRuntimeDescriptor.tcp.json",
    ] {
        assert_rejected(file, |document| {
            document.as_object_mut().unwrap().remove("contractVersion");
        });
        for version in ["2.0", "1.1", "1"] {
            assert_rejected(file, |document| {
                document["contractVersion"] = json!(version);
            });
        }
    }
}

#[test]
fn readers_accept_the_original_field_names() {
    let mut document = example("BoundaryConfig.runtime-initiated-unix.json");
    let object = document.as_object_mut().unwrap();
    let value = object.remove("boundaryId").unwrap();
    object.insert("boundary_id".to_string(), value);
    assert!(to_legacy("BoundaryConfig", &document.to_string()).is_ok());
}

#[test]
fn readers_reject_zero_epoch_and_rotation() {
    for field in ["authEpoch", "sessionRotation"] {
        assert_rejected("BoundaryConfig.runtime-initiated-unix.json", |document| {
            document["trust"][field] = json!("0");
        });
    }
}

#[test]
fn readers_reject_an_invalid_initiator_and_endpoint_pairing() {
    assert_rejected("SandboxRuntimeDescriptor.tcp.json", |document| {
        document["transport"]["initiator"] = json!("CONNECTION_INITIATOR_UNSPECIFIED");
    });
    assert_rejected(
        "SandboxRuntimeDescriptor.runtime-initiated-routed.json",
        |document| {
            document["transport"]["endpoint"]["tcp"]["addresses"] = json!(["10.0.0.5:8443"]);
        },
    );
    assert_rejected("SandboxRuntimeDescriptor.vsock.json", |document| {
        document["transport"]["endpoint"]["vsock"]
            .as_object_mut()
            .unwrap()
            .remove("cid");
    });
}

#[test]
fn readers_reject_a_workload_identity_that_uses_root() {
    assert_rejected("BoundaryConfig.runtime-initiated-unix.json", |document| {
        document["workloadIdentity"]["uid"] = json!(0);
    });
}

#[test]
fn readers_reject_a_malformed_digest_and_session_id() {
    assert_rejected("BoundaryConfig.runtime-initiated-unix.json", |document| {
        document["fenceEvidence"]["evidenceDigest"] = json!("not-hex");
    });
    assert_rejected("BoundaryConfig.runtime-initiated-unix.json", |document| {
        document["sessionId"] = json!("00000000-0000-0000-0000-000000000000");
    });
}
