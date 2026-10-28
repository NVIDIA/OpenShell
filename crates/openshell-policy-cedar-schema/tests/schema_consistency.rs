// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Asserts that every constant in [`entity_types`]/[`actions`] names an
//! entity type or action actually declared in [`SANDBOX_SCHEMA_SRC`], so the
//! hand-written constants cannot silently drift from the schema they
//! describe.

use std::collections::{BTreeSet, HashSet};

use openshell_policy_cedar_schema::{
    SANDBOX_SCHEMA_SRC, actions, context_fields, declared_attributes, endpoint_fields,
    entity_types, load_schema,
};

#[test]
fn entity_type_constants_are_declared_in_the_schema() {
    let schema = load_schema().expect("embedded schema must parse");
    let declared: HashSet<String> = schema.entity_types().map(ToString::to_string).collect();

    for name in [
        entity_types::PROCESS,
        entity_types::USER,
        entity_types::GROUP,
        entity_types::FILESYSTEM_PATH,
        entity_types::NETWORK_ENDPOINT,
        entity_types::HTTP_QUERY,
    ] {
        assert!(
            declared.contains(name),
            "entity_types constant {name:?} is not declared in the schema; declared types: {declared:?}"
        );
    }
}

#[test]
fn action_constants_are_declared_in_the_schema() {
    let schema = load_schema().expect("embedded schema must parse");
    let declared: HashSet<String> = schema.actions().map(ToString::to_string).collect();

    for action in [
        actions::READ_FILE,
        actions::WRITE_FILE,
        actions::NETWORK_CONNECT,
        actions::HTTP_REQUEST,
    ] {
        let uid = format!("{}::\"{action}\"", actions::ACTION_TYPE);
        assert!(
            declared.contains(&uid),
            "action constant {action:?} (as {uid:?}) is not declared in the schema; declared actions: {declared:?}"
        );
    }
}

/// Counts the `context` attribute declarations of `field` in the schema
/// source.
fn context_declarations(field: &str) -> usize {
    SANDBOX_SCHEMA_SRC
        .lines()
        .filter(|line| line.trim_start().starts_with(&format!("{field}:")))
        .count()
}

#[test]
fn binary_identity_context_fields_are_declared_on_both_network_actions() {
    // Both network actions carry the same binary identity fields, so a
    // policy can guard connections and requests with one condition.
    for field in [
        context_fields::BINARY_PATH,
        context_fields::ANCESTORS,
        context_fields::BINARY_ALIASES,
        context_fields::BINARY_GLOBS,
    ] {
        assert_eq!(
            context_declarations(field),
            2,
            "{field} must be declared on NetworkConnect and HttpRequest"
        );
    }
}

#[test]
fn request_context_fields_are_declared_only_on_http_request() {
    // No request has been read at CONNECT time, so NetworkConnect declares
    // none of these; a connection policy that reads one fails validation
    // instead of never matching.
    for field in [
        context_fields::METHOD,
        context_fields::PATH,
        context_fields::COMMAND,
        context_fields::JSONRPC_METHOD,
        context_fields::JSONRPC_RECEIVE_STREAM,
        context_fields::JSONRPC_RESPONSE,
        context_fields::MCP_TOOL,
        context_fields::MCP_METHOD_CLASS,
        context_fields::GRAPHQL_OPERATION_TYPE,
        context_fields::GRAPHQL_OPERATION_NAME,
        context_fields::GRAPHQL_FIELDS,
        context_fields::QUERY,
    ] {
        assert_eq!(
            context_declarations(field),
            1,
            "{field} must be declared on HttpRequest only"
        );
    }
}

#[test]
fn process_carries_only_its_identity() {
    // `Process` once declared an optional `workdir` that nothing populated,
    // so `principal has workdir` was always false. The entity has exactly
    // the attributes the supervisor sets on every request.
    let declared = declared_attributes().expect("embedded schema must convert");
    assert_eq!(
        declared.entity(entity_types::PROCESS),
        &BTreeSet::from(["user".to_string(), "group".to_string()])
    );
}

#[test]
fn declared_attributes_follow_the_schema() {
    let declared = declared_attributes().expect("embedded schema must convert");
    let names = |fields: &[&str]| {
        fields
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(
        declared.context(actions::NETWORK_CONNECT),
        &names(&[
            context_fields::BINARY_PATH,
            context_fields::ANCESTORS,
            context_fields::BINARY_ALIASES,
            context_fields::BINARY_GLOBS,
            context_fields::DESTINATION_IP,
        ])
    );
    let http_request = declared.context(actions::HTTP_REQUEST);
    for field in [
        context_fields::METHOD,
        context_fields::PATH,
        context_fields::COMMAND,
        context_fields::QUERY,
    ] {
        assert!(http_request.contains(field), "{field}");
    }
    assert!(!http_request.contains(context_fields::DESTINATION_IP));
    assert!(declared.context(actions::READ_FILE).is_empty());
    assert_eq!(
        declared.entity(entity_types::NETWORK_ENDPOINT),
        &names(&[
            endpoint_fields::HOST,
            endpoint_fields::PORT,
            endpoint_fields::PROTOCOL,
            endpoint_fields::HOST_PORT,
        ])
    );
    assert!(declared.entity(entity_types::FILESYSTEM_PATH).is_empty());
    assert!(declared.entity("Sandbox::Missing").is_empty());
    assert!(declared.context("Missing").is_empty());
}
