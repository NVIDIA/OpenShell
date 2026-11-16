// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The legacy encoding of the launch authentication documents against golden JSON
//! examples.
//!
//! The examples in `tests/legacy_contract/examples` are the bytes that existing
//! drivers write and existing readers accept. Each must decode and re-encode to
//! the same JSON, so a change to a type that alters its encoding fails here.

#![cfg(feature = "jwt")]

use openshell_driver_sdk::jwt::{SandboxLaunchAuthentication, SupervisorAuthBundle};
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
        "SupervisorAuthBundle.minimal.json",
        "SandboxLaunchAuthentication.json",
    ] {
        assert_rejected(file, |document| {
            document["unexpected"] = json!(true);
        });
    }
}

/// Rules that serde decoding does not apply and a later validator does.
#[test]
fn some_rules_are_enforced_after_decoding() {
    let mut document = example("SupervisorAuthBundle.full.json");
    document["traces_otlp_tls"] = json!(9);
    let bundle: SupervisorAuthBundle = serde_json::from_value(document).unwrap();
    assert!(bundle.validate().is_err());
}
