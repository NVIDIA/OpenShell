// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Messages that are deliberately defined in more than one proto file must stay
//! identical. `sandbox_runtime.proto` and `sandbox_protocol.proto` do not import
//! `compute_driver.proto`, so they repeat the messages they share with it. The
//! encodings are interchangeable only while the copies agree.

use std::collections::BTreeMap;

use prost::Message;
use prost_types::{DescriptorProto, FileDescriptorSet};

const COMPUTE: &str = "openshell.compute.v1";
const RUNTIME: &str = "openshell.sandbox.runtime.v1";
const PROTOCOL: &str = "openshell.sandbox.protocol.v1";

/// A message's shape: for every field, its number mapped to its name, type, type
/// name, label and, for a map, the shape of its entry message.
fn shape(set: &FileDescriptorSet, package: &str, message: &str) -> Vec<String> {
    let file = set
        .file
        .iter()
        .find(|file| {
            file.package.as_deref() == Some(package)
                && file
                    .message_type
                    .iter()
                    .any(|m| m.name.as_deref() == Some(message))
        })
        .unwrap_or_else(|| panic!("{package}.{message} is not in the descriptor set"));
    let descriptor = file
        .message_type
        .iter()
        .find(|m| m.name.as_deref() == Some(message))
        .expect("message exists");

    let entries: BTreeMap<&str, &DescriptorProto> = descriptor
        .nested_type
        .iter()
        .filter_map(|nested| Some((nested.name.as_deref()?, nested)))
        .collect();
    let mut fields: Vec<_> = descriptor.field.iter().collect();
    fields.sort_by_key(|field| field.number());
    fields
        .into_iter()
        .map(|field| {
            // A message-typed field names its type with the package, which is
            // allowed to differ between copies; compare the bare message name.
            let type_name = field
                .type_name
                .as_deref()
                .map(|name| name.rsplit('.').next().unwrap_or(name).to_string())
                .unwrap_or_default();
            let entry = entries
                .get(type_name.as_str())
                .map(|entry| {
                    let mut inner: Vec<_> = entry.field.iter().collect();
                    inner.sort_by_key(|field| field.number());
                    inner
                        .into_iter()
                        .map(|f| format!("{}:{}:{:?}", f.number(), f.name(), f.r#type()))
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            format!(
                "{} {} {:?} {:?} {} [{}]",
                field.number(),
                field.name(),
                field.r#type(),
                field.label(),
                if entry.is_empty() {
                    type_name
                } else {
                    String::new()
                },
                entry,
            )
        })
        .collect()
}

fn assert_identical(message: &str, reference: &str, copies: &[&str]) {
    let set = FileDescriptorSet::decode(openshell_core::FILE_DESCRIPTOR_SET)
        .expect("descriptor set decodes");
    let expected = shape(&set, reference, message);
    let mut differences = Vec::new();
    for package in copies {
        let actual = shape(&set, package, message);
        if actual != expected {
            differences.push(format!(
                "{package}.{message} differs from {reference}.{message}\n  expected: {expected:#?}\n  actual:   {actual:#?}"
            ));
        }
    }
    assert!(
        differences.is_empty(),
        "duplicated messages have drifted; change every copy together:\n{}",
        differences.join("\n")
    );
}

#[test]
fn resolved_workload_identity_is_identical_in_every_proto_that_defines_it() {
    assert_identical("ResolvedWorkloadIdentity", COMPUTE, &[RUNTIME, PROTOCOL]);
}

#[test]
fn driver_fence_evidence_is_identical_in_every_proto_that_defines_it() {
    assert_identical("DriverFenceEvidence", COMPUTE, &[RUNTIME]);
}

#[test]
fn the_comparison_notices_a_difference() {
    // Two different messages must not compare equal.
    let set = FileDescriptorSet::decode(openshell_core::FILE_DESCRIPTOR_SET).unwrap();
    assert_ne!(
        shape(&set, COMPUTE, "ResolvedWorkloadIdentity"),
        shape(&set, RUNTIME, "BoundaryConfig")
    );
}
