// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Asserts that every constant in [`entity_types`]/[`actions`] names an
//! entity type or action actually declared in [`SANDBOX_SCHEMA_SRC`], so the
//! hand-written constants cannot silently drift from the schema they
//! describe.

use std::collections::HashSet;

use openshell_policy_cedar_schema::{actions, entity_types, load_schema};

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
