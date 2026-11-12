// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The launch credentials of `launch_credentials.proto` as protobuf JSON, checked
//! against the legacy documents.
//!
//! For each legacy example, the document built from the legacy Rust type must
//! equal the protobuf JSON example, and reading the protobuf JSON example must
//! give back the legacy document. The protobuf JSON examples are the
//! reference for a driver in any language that writes the new format.
//!
//! Run with `UPDATE_EXAMPLES=1` to rewrite the protobuf JSON examples from the
//! legacy ones, then review the diff.

#![cfg(feature = "jwt")]

use std::path::Path;

use openshell_driver_sdk::jwt::{SandboxLaunchAuthentication, SupervisorAuthBundle};
use openshell_driver_sdk::proto::FILE_DESCRIPTOR_SET;
use openshell_driver_sdk::proto::compute::v1 as compute;
use prost_reflect::{DescriptorPool, DeserializeOptions, DynamicMessage};
use serde_json::{Value, json};

/// The launch credentials live in the compute package, which
/// `compute_driver.proto` carries them in.
const PACKAGE: &str = "openshell.compute.v1";

fn qualified(document_type: &str) -> String {
    // The launch credentials message replaces the legacy launch authentication
    // type, whose name the example files keep.
    match document_type {
        "SandboxLaunchAuthentication" => format!("{PACKAGE}.SandboxLaunchCredentials"),
        _ => format!("{PACKAGE}.{document_type}"),
    }
}

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
    example!("SupervisorAuthBundle.minimal.json"),
    example!("SupervisorAuthBundle.full.json"),
    example!("SandboxLaunchAuthentication.json"),
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
        "SupervisorAuthBundle" => {
            through::<SupervisorAuthBundle, compute::SupervisorAuthBundle>(legacy)
        }
        "SandboxLaunchAuthentication" => {
            through::<SandboxLaunchAuthentication, compute::SandboxLaunchCredentials>(legacy)
        }
        other => panic!("no type registered for {other}"),
    };
    let descriptor = pool()
        .get_message_by_name(&qualified(document_type))
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
        .get_message_by_name(&qualified(document_type))
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
        "SupervisorAuthBundle" => {
            back::<SupervisorAuthBundle, compute::SupervisorAuthBundle>(&message)
        }
        "SandboxLaunchAuthentication" => {
            back::<SandboxLaunchAuthentication, compute::SandboxLaunchCredentials>(&message)
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
        "SupervisorAuthBundle.minimal.json",
        "SandboxLaunchAuthentication.json",
    ] {
        assert_rejected(file, |document| {
            document["unexpected"] = json!(true);
        });
    }
}

#[test]
fn readers_reject_a_missing_or_unsupported_version() {
    for file in ["SandboxLaunchAuthentication.json"] {
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
fn readers_reject_an_out_of_range_collector_tls_index() {
    assert_rejected("SupervisorAuthBundle.full.json", |document| {
        document["tracesOtlpTls"] = json!(9);
    });
}
