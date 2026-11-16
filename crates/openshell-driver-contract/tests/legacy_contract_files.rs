// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Writing the contract documents as files, and reading them back, preferring
//! the binary protobuf file that sits beside the legacy one.

use openshell_driver_contract::proto::sandbox_runtime::v1 as pb;
use openshell_driver_contract::write::encode;
use openshell_driver_contract::{
    BUILTIN_BACKEND_NAME, BoundaryConfig, SandboxRuntimeDescriptor, read,
};
use prost::Message as _;
use prost_reflect::{DescriptorPool, DynamicMessage};
use serde_json::{Value, json};

/// The binary encoding of the protobuf JSON golden `json`, a document of type
/// `M`. The goldens stay JSON so they can be reviewed; the files a driver writes
/// are binary. A dynamic message writes map entries in no fixed order, so the
/// bytes are taken from the typed message instead.
fn binary<M: prost::Message + Default>(message: &str, json: &str) -> Vec<u8> {
    let pool =
        DescriptorPool::decode(openshell_driver_contract::proto::FILE_DESCRIPTOR_SET).unwrap();
    let descriptor = pool
        .get_message_by_name(&format!("openshell.sandbox.runtime.v1.{message}"))
        .unwrap();
    let mut deserializer = serde_json::Deserializer::from_str(json);
    let dynamic = DynamicMessage::deserialize(descriptor, &mut deserializer).unwrap();
    M::decode(dynamic.encode_to_vec().as_slice())
        .unwrap()
        .encode_to_vec()
}

const LEGACY: &str =
    include_str!("legacy_contract/examples/BoundaryConfig.runtime-initiated-unix.json");
const PROTOBUF: &str =
    include_str!("legacy_contract/proto_json/BoundaryConfig.runtime-initiated-unix.json");

fn config() -> BoundaryConfig {
    serde_json::from_str(LEGACY).unwrap()
}

#[test]
fn encoding_matches_the_protobuf_example() {
    let files = encode(&config()).unwrap();
    assert_eq!(
        files.binary.contents,
        binary::<pb::BoundaryConfig>("BoundaryConfig", PROTOBUF)
    );
}

#[test]
fn the_legacy_encoding_is_unchanged() {
    let files = encode(&config()).unwrap();
    let written: Value = serde_json::from_slice(&files.legacy.contents).unwrap();
    assert_eq!(written, serde_json::from_str::<Value>(LEGACY).unwrap());
}

#[test]
fn the_files_are_named_beside_each_other() {
    let files = encode(&config()).unwrap();
    assert_eq!(files.legacy.name, "boundary-bootstrap.json");
    assert_eq!(files.binary.name, "boundary-bootstrap.pb");
    let names: Vec<_> = files.iter().map(|file| file.name.as_str()).collect();
    assert_eq!(names, ["boundary-bootstrap.pb", "boundary-bootstrap.json"]);
    let files = encode(&descriptor()).unwrap();
    assert_eq!(files.legacy.name, "runtime-descriptor.json");
    assert_eq!(files.binary.name, "runtime-descriptor.pb");
}

#[test]
fn an_invalid_document_is_not_encoded() {
    let mut config = config();
    config.generation = "another-generation".to_string();
    assert!(encode(&config).is_err());
}

fn write(directory: &std::path::Path, files: &openshell_driver_contract::write::DocumentFiles) {
    for file in files.iter() {
        std::fs::write(directory.join(&file.name), &file.contents).unwrap();
    }
}

#[test]
fn the_written_files_read_back_as_the_same_document() {
    let directory = tempfile::tempdir().unwrap();
    write(directory.path(), &encode(&config()).unwrap());
    let path = directory.path().join("boundary-bootstrap.json");
    let read = read::boundary_config(&path).unwrap();
    assert_eq!(
        serde_json::to_value(&read).unwrap(),
        serde_json::from_str::<Value>(LEGACY).unwrap()
    );
    // Either file alone gives the same document.
    std::fs::remove_file(directory.path().join("boundary-bootstrap.pb")).unwrap();
    assert_eq!(
        serde_json::to_value(read::boundary_config(&path).unwrap()).unwrap(),
        serde_json::to_value(&read).unwrap()
    );
}

#[test]
fn the_new_file_is_preferred() {
    let directory = tempfile::tempdir().unwrap();
    let legacy = directory.path().join("bootstrap.json");
    let mut other: Value = serde_json::from_str(LEGACY).unwrap();
    other["boundary_id"] = json!("from-the-legacy-file");
    std::fs::write(&legacy, other.to_string()).unwrap();
    std::fs::write(
        directory.path().join("bootstrap.pb"),
        binary::<pb::BoundaryConfig>("BoundaryConfig", PROTOBUF),
    )
    .unwrap();
    let config = read::boundary_config(&legacy).unwrap();
    assert_ne!(config.boundary_id, "from-the-legacy-file");
}

#[test]
fn the_legacy_file_is_read_when_there_is_no_new_one() {
    let directory = tempfile::tempdir().unwrap();
    let legacy = directory.path().join("bootstrap.json");
    std::fs::write(&legacy, LEGACY).unwrap();
    let config = read::boundary_config(&legacy).unwrap();
    assert_eq!(
        serde_json::to_value(&config).unwrap(),
        serde_json::from_str::<Value>(LEGACY).unwrap()
    );
}

#[test]
fn an_invalid_new_file_is_an_error_not_a_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let legacy = directory.path().join("bootstrap.json");
    std::fs::write(&legacy, LEGACY).unwrap();
    // Not a protobuf message: field 1 claims more bytes than the file holds.
    std::fs::write(directory.path().join("bootstrap.pb"), [0x0a, 0xff]).unwrap();
    assert!(read::boundary_config(&legacy).is_err());
}

#[test]
fn a_missing_pair_of_files_is_an_error() {
    let directory = tempfile::tempdir().unwrap();
    assert!(read::boundary_config(&directory.path().join("bootstrap.json")).is_err());
}

#[test]
fn a_name_without_a_json_ending_gets_the_new_suffix_appended() {
    let directory = tempfile::tempdir().unwrap();
    let legacy = directory.path().join("descriptor");
    std::fs::write(&legacy, b"legacy").unwrap();
    std::fs::write(directory.path().join("descriptor.pb"), b"binary").unwrap();
    read::consume(&legacy).unwrap();
    assert!(!legacy.exists());
    assert!(!directory.path().join("descriptor.pb").exists());
}

#[test]
fn consuming_removes_every_form_and_tolerates_a_missing_one() {
    let directory = tempfile::tempdir().unwrap();
    write(directory.path(), &encode(&config()).unwrap());
    let legacy = directory.path().join("boundary-bootstrap.json");
    read::consume(&legacy).unwrap();
    assert!(!legacy.exists());
    assert!(!directory.path().join("boundary-bootstrap.pb").exists());
    // Nothing left is not an error.
    read::consume(&legacy).unwrap();
}

const LEGACY_DESCRIPTOR: &str =
    include_str!("legacy_contract/examples/SandboxRuntimeDescriptor.tcp.json");
const PROTOBUF_DESCRIPTOR: &str =
    include_str!("legacy_contract/proto_json/SandboxRuntimeDescriptor.tcp.json");

fn descriptor() -> SandboxRuntimeDescriptor {
    serde_json::from_str(LEGACY_DESCRIPTOR).unwrap()
}

#[test]
fn the_descriptor_reads_back() {
    let directory = tempfile::tempdir().unwrap();
    write(directory.path(), &encode(&descriptor()).unwrap());
    let read = read::runtime_descriptor(&directory.path().join("runtime-descriptor.json")).unwrap();
    assert_eq!(read, descriptor());
}

#[test]
fn built_in_descriptor_prefers_the_protobuf_file() {
    let directory = tempfile::tempdir().unwrap();
    let legacy = directory.path().join("runtime-descriptor.json");
    // The legacy file names a different boundary, so the source is visible.
    let mut other: Value = serde_json::from_str(LEGACY_DESCRIPTOR).unwrap();
    other["boundary_id"] = json!("from-the-legacy-file");
    std::fs::write(&legacy, other.to_string()).unwrap();
    std::fs::write(
        directory.path().join("runtime-descriptor.pb"),
        binary::<pb::SandboxRuntimeDescriptor>("SandboxRuntimeDescriptor", PROTOBUF_DESCRIPTOR),
    )
    .unwrap();
    let payload = read::descriptor_payload(&legacy, BUILTIN_BACKEND_NAME).unwrap();
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
    let payload = read::descriptor_payload(&legacy, BUILTIN_BACKEND_NAME).unwrap();
    assert_eq!(payload, LEGACY_DESCRIPTOR.as_bytes());
}

#[test]
fn an_invalid_protobuf_descriptor_is_an_error_not_a_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let legacy = directory.path().join("runtime-descriptor.json");
    std::fs::write(&legacy, LEGACY_DESCRIPTOR).unwrap();
    std::fs::write(directory.path().join("runtime-descriptor.pb"), [0x0a, 0xff]).unwrap();
    assert!(read::descriptor_payload(&legacy, BUILTIN_BACKEND_NAME).is_err());
}

#[test]
fn an_external_backends_descriptor_is_read_as_it_is() {
    let directory = tempfile::tempdir().unwrap();
    let legacy = directory.path().join("runtime-descriptor.json");
    std::fs::write(&legacy, b"opaque backend payload").unwrap();
    std::fs::write(
        directory.path().join("runtime-descriptor.pb"),
        binary::<pb::SandboxRuntimeDescriptor>("SandboxRuntimeDescriptor", PROTOBUF_DESCRIPTOR),
    )
    .unwrap();
    let payload = read::descriptor_payload(&legacy, "openshell-mxc").unwrap();
    assert_eq!(payload, b"opaque backend payload");
}
