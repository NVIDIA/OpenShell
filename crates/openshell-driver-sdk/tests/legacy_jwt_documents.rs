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

mod launch_authentication_fields {
    use super::*;
    use openshell_driver_sdk::launch_credentials::{
        launch_credentials_from_bytes, resolve_launch_authentication,
    };

    fn example_bytes() -> Vec<u8> {
        serde_json::to_vec(&example("SandboxLaunchAuthentication.json")).unwrap()
    }

    fn legacy() -> SandboxLaunchAuthentication {
        serde_json::from_slice(&example_bytes()).unwrap()
    }

    #[test]
    fn only_bytes_present_decodes_the_bytes() {
        let resolved = resolve_launch_authentication(None, &example_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_value(&resolved).unwrap(),
            serde_json::to_value(legacy()).unwrap()
        );
    }

    #[test]
    fn typed_present_without_bytes_decodes_the_typed_field() {
        let typed = launch_credentials_from_bytes(&example_bytes())
            .unwrap()
            .unwrap();
        let resolved = resolve_launch_authentication(Some(&typed), &[])
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_value(&resolved).unwrap(),
            serde_json::to_value(legacy()).unwrap()
        );
    }

    #[test]
    fn both_present_prefers_typed_over_bytes() {
        let mut typed = launch_credentials_from_bytes(&example_bytes())
            .unwrap()
            .unwrap();
        typed.gateway_id = "from-the-typed-field".to_string();
        let resolved = resolve_launch_authentication(Some(&typed), &example_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(resolved.gateway_id, "from-the-typed-field");
    }

    #[test]
    fn invalid_typed_field_is_not_bypassed_for_the_bytes() {
        let mut typed = launch_credentials_from_bytes(&example_bytes())
            .unwrap()
            .unwrap();
        typed.supervisor = None;
        assert!(resolve_launch_authentication(Some(&typed), &example_bytes()).is_err());
    }

    #[test]
    fn neither_present_is_none() {
        assert!(resolve_launch_authentication(None, &[]).unwrap().is_none());
        assert!(launch_credentials_from_bytes(&[]).unwrap().is_none());
    }
}
