// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reading and writing the contract documents as files, preferring the
//! protobuf JSON file that sits beside the legacy one.

#![cfg(feature = "legacy-contract")]

use std::path::Path;

use openshell_driver_sdk::legacy_contract::{
    BUILTIN_BACKEND_NAME, BoundaryConfig, ContractDocument, SandboxRuntimeDescriptor,
    protobuf_json_file_name, protobuf_json_path, read_descriptor_payload, read_document,
};
use serde_json::{Value, json};

const LEGACY: &str =
    include_str!("legacy_contract/examples/BoundaryConfig.runtime-initiated-unix.json");
const PROTOBUF: &str =
    include_str!("legacy_contract/proto_json/BoundaryConfig.runtime-initiated-unix.json");

fn config() -> BoundaryConfig {
    serde_json::from_str(LEGACY).unwrap()
}

#[test]
fn the_new_file_is_named_beside_the_legacy_one() {
    for (legacy, expected) in [
        (
            "/.openshell/channel/sandbox/bootstrap.json",
            "/.openshell/channel/sandbox/bootstrap.pb.json",
        ),
        ("/run/descriptor", "/run/descriptor.pb.json"),
    ] {
        assert_eq!(protobuf_json_path(Path::new(legacy)), Path::new(expected));
    }
}

#[test]
fn encoding_matches_the_protobuf_json_example() {
    let written: Value = serde_json::from_slice(&config().to_protobuf_json().unwrap()).unwrap();
    assert_eq!(written, serde_json::from_str::<Value>(PROTOBUF).unwrap());
}

#[test]
fn the_legacy_encoding_is_unchanged() {
    let written: Value = serde_json::from_slice(&config().to_legacy_json().unwrap()).unwrap();
    assert_eq!(written, serde_json::from_str::<Value>(LEGACY).unwrap());
}

#[test]
fn decoding_gives_back_the_document() {
    let decoded = BoundaryConfig::from_protobuf_json(PROTOBUF.as_bytes()).unwrap();
    assert_eq!(
        serde_json::to_value(&decoded).unwrap(),
        serde_json::from_str::<Value>(LEGACY).unwrap()
    );
}

#[test]
fn the_descriptor_round_trips_through_protobuf_json() {
    let descriptor: SandboxRuntimeDescriptor = serde_json::from_str(include_str!(
        "legacy_contract/examples/SandboxRuntimeDescriptor.runtime-initiated-routed.json"
    ))
    .unwrap();
    let again =
        SandboxRuntimeDescriptor::from_protobuf_json(&descriptor.to_protobuf_json().unwrap())
            .unwrap();
    assert_eq!(
        serde_json::to_value(&descriptor).unwrap(),
        serde_json::to_value(&again).unwrap()
    );
}

#[test]
fn a_reader_prefers_the_new_file() {
    let directory = tempfile::tempdir().unwrap();
    let legacy = directory.path().join("bootstrap.json");
    // The legacy file holds a different boundary so the source is visible.
    let mut other = serde_json::to_value(config()).unwrap();
    other["boundary_id"] = json!("from-the-legacy-file");
    std::fs::write(&legacy, other.to_string()).unwrap();
    std::fs::write(directory.path().join("bootstrap.pb.json"), PROTOBUF).unwrap();
    let read: BoundaryConfig = read_document(&legacy).unwrap();
    assert_eq!(read.boundary_id, "sbx-0001");
}

#[test]
fn a_reader_falls_back_to_the_legacy_file() {
    let directory = tempfile::tempdir().unwrap();
    let legacy = directory.path().join("bootstrap.json");
    std::fs::write(&legacy, LEGACY).unwrap();
    let read: BoundaryConfig = read_document(&legacy).unwrap();
    assert_eq!(read.boundary_id, "sbx-0001");
}

#[test]
fn an_invalid_new_file_is_an_error_not_a_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let legacy = directory.path().join("bootstrap.json");
    std::fs::write(&legacy, LEGACY).unwrap();
    let mut invalid: Value = serde_json::from_str(PROTOBUF).unwrap();
    invalid["unexpected"] = json!(true);
    std::fs::write(
        directory.path().join("bootstrap.pb.json"),
        invalid.to_string(),
    )
    .unwrap();
    assert!(read_document::<BoundaryConfig>(&legacy).is_err());
}

#[test]
fn a_missing_pair_of_files_is_an_error() {
    let directory = tempfile::tempdir().unwrap();
    assert!(read_document::<BoundaryConfig>(&directory.path().join("bootstrap.json")).is_err());
}

#[test]
fn the_file_name_rule_matches_the_path_rule() {
    assert_eq!(
        protobuf_json_file_name("bootstrap.json"),
        "bootstrap.pb.json"
    );
    assert_eq!(protobuf_json_file_name("descriptor"), "descriptor.pb.json");
}

#[test]
fn both_files_are_encoded_from_one_value() {
    let files = config().to_files("bootstrap.json").unwrap();
    assert_eq!(files.legacy.name, "bootstrap.json");
    assert_eq!(files.protobuf.name, "bootstrap.pb.json");
    assert_eq!(files.legacy.contents, config().to_legacy_json().unwrap());
    assert_eq!(
        files.protobuf.contents,
        config().to_protobuf_json().unwrap()
    );
    let names: Vec<_> = files.iter().map(|file| file.name.as_str()).collect();
    assert_eq!(names, ["bootstrap.json", "bootstrap.pb.json"]);
    // Reading either file gives the same document.
    let from_legacy: BoundaryConfig = serde_json::from_slice(&files.legacy.contents).unwrap();
    let from_protobuf = BoundaryConfig::from_protobuf_json(&files.protobuf.contents).unwrap();
    assert_eq!(
        serde_json::to_value(&from_legacy).unwrap(),
        serde_json::to_value(&from_protobuf).unwrap()
    );
}

const LEGACY_DESCRIPTOR: &str =
    include_str!("legacy_contract/examples/SandboxRuntimeDescriptor.tcp.json");
const PROTOBUF_DESCRIPTOR: &str =
    include_str!("legacy_contract/proto_json/SandboxRuntimeDescriptor.tcp.json");

#[test]
fn built_in_descriptor_prefers_the_protobuf_json_file() {
    let directory = tempfile::tempdir().unwrap();
    let legacy = directory.path().join("runtime-descriptor.json");
    // The legacy file names a different boundary, so the source is visible.
    let mut other: Value = serde_json::from_str(LEGACY_DESCRIPTOR).unwrap();
    other["boundary_id"] = json!("from-the-legacy-file");
    std::fs::write(&legacy, other.to_string()).unwrap();
    std::fs::write(
        directory.path().join("runtime-descriptor.pb.json"),
        PROTOBUF_DESCRIPTOR,
    )
    .unwrap();
    let payload = read_descriptor_payload(&legacy, BUILTIN_BACKEND_NAME).unwrap();
    // The payload is the legacy encoding of the protobuf JSON descriptor.
    assert_eq!(
        serde_json::from_slice::<Value>(&payload).unwrap(),
        serde_json::from_str::<Value>(LEGACY_DESCRIPTOR).unwrap()
    );
    let descriptor: SandboxRuntimeDescriptor = serde_json::from_slice(&payload).unwrap();
    assert_eq!(descriptor.boundary_id, "sbx-0003");
}

#[test]
fn built_in_descriptor_falls_back_to_the_legacy_file() {
    let directory = tempfile::tempdir().unwrap();
    let legacy = directory.path().join("runtime-descriptor.json");
    std::fs::write(&legacy, LEGACY_DESCRIPTOR).unwrap();
    let payload = read_descriptor_payload(&legacy, BUILTIN_BACKEND_NAME).unwrap();
    assert_eq!(payload, LEGACY_DESCRIPTOR.as_bytes());
}

#[test]
fn an_invalid_protobuf_json_descriptor_is_an_error_not_a_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let legacy = directory.path().join("runtime-descriptor.json");
    std::fs::write(&legacy, LEGACY_DESCRIPTOR).unwrap();
    std::fs::write(
        directory.path().join("runtime-descriptor.pb.json"),
        r#"{"unexpected":true}"#,
    )
    .unwrap();
    assert!(read_descriptor_payload(&legacy, BUILTIN_BACKEND_NAME).is_err());
}

#[test]
fn an_external_backends_descriptor_is_read_as_it_is() {
    let directory = tempfile::tempdir().unwrap();
    let legacy = directory.path().join("runtime-descriptor.json");
    std::fs::write(&legacy, b"opaque backend payload").unwrap();
    std::fs::write(
        directory.path().join("runtime-descriptor.pb.json"),
        PROTOBUF_DESCRIPTOR,
    )
    .unwrap();
    let payload = read_descriptor_payload(&legacy, "openshell-mxc").unwrap();
    assert_eq!(payload, b"opaque backend payload");
}
