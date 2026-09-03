// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-private, versioned protobuf formats for durable storage.

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    unused_imports,
    unused_qualifications,
    rust_2018_idioms
)]

include!(concat!(env!("OUT_DIR"), "/openshell.storage.v1.rs"));

#[cfg(test)]
const STORAGE_FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/storage_descriptor.bin"));

use openshell_core::{
    GetResourceVersion, ObjectId, ObjectLabels, ObjectName, ObjectWorkspace, SetResourceVersion,
};
use std::collections::HashMap;

impl ObjectId for StoredProviderProfile {
    fn object_id(&self) -> &str {
        self.metadata.as_ref().map_or("", |m| m.id.as_str())
    }
}

impl ObjectName for StoredProviderProfile {
    fn object_name(&self) -> &str {
        self.metadata.as_ref().map_or("", |m| m.name.as_str())
    }
}

impl ObjectLabels for StoredProviderProfile {
    fn object_labels(&self) -> Option<HashMap<String, String>> {
        self.metadata.as_ref().map(|m| m.labels.clone())
    }
}

impl SetResourceVersion for StoredProviderProfile {
    fn set_resource_version(&mut self, version: u64) {
        if let Some(meta) = self.metadata.as_mut() {
            meta.resource_version = version;
        }
    }
}

impl GetResourceVersion for StoredProviderProfile {
    fn get_resource_version(&self) -> u64 {
        self.metadata.as_ref().map_or(0, |m| m.resource_version)
    }
}

impl ObjectWorkspace for StoredProviderProfile {
    fn object_workspace(&self) -> &str {
        self.metadata.as_ref().map_or("", |m| m.workspace.as_str())
    }

    fn requires_workspace() -> bool {
        false
    }
}

impl ObjectId for StoredProviderCredentialRefreshState {
    fn object_id(&self) -> &str {
        self.metadata.as_ref().map_or("", |m| m.id.as_str())
    }
}

impl ObjectName for StoredProviderCredentialRefreshState {
    fn object_name(&self) -> &str {
        self.metadata.as_ref().map_or("", |m| m.name.as_str())
    }
}

impl ObjectLabels for StoredProviderCredentialRefreshState {
    fn object_labels(&self) -> Option<HashMap<String, String>> {
        self.metadata.as_ref().map(|m| m.labels.clone())
    }
}

impl SetResourceVersion for StoredProviderCredentialRefreshState {
    fn set_resource_version(&mut self, version: u64) {
        if let Some(meta) = self.metadata.as_mut() {
            meta.resource_version = version;
        }
    }
}

impl GetResourceVersion for StoredProviderCredentialRefreshState {
    fn get_resource_version(&self) -> u64 {
        self.metadata.as_ref().map_or(0, |m| m.resource_version)
    }
}

impl ObjectWorkspace for StoredProviderCredentialRefreshState {
    fn object_workspace(&self) -> &str {
        self.metadata.as_ref().map_or("", |m| m.workspace.as_str())
    }

    fn requires_workspace() -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use prost_types::{DescriptorProto, EnumDescriptorProto, FileDescriptorSet};
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    const STORAGE_V1_SCHEMA_SHA256: &str =
        "79c72615d957fc0653c672f61998bf7d8d21b757bc05d07b3fff92bd70fc8f52";
    const PUBLIC_RPC_SCHEMA_SHA256: &str =
        "88792324febbe48e2b311f21d2541566f100762324dbca45bce3fd18852417ca";
    const DURABLE_SCHEMA_SHA256: &str =
        "29d46ae84cdae41d67a1650bdf2c7691088799283c0b727970782a36f29dc4d2";
    const PUBLIC_DURABLE_OVERLAP_SHA256: &str =
        "05add438ba041defc98d791038ae593d3f09352677cae43f2276d494205ce415";
    // Synthetic payloads generated with the public declarations at v0.0.116,
    // before their relocation into openshell.storage.v1. Values are deliberately
    // non-secret and the ordinary protobuf bytes contain no package names.
    const V0_0_116_REFRESH_STATE: &str = "0a230a096c65676163792d6964120b6c65676163792d6e616d6528073a0764656661756c74120b70726f76696465722d69641a0870726f76696465722205544f4b454e32160a09636c69656e745f6964120973796e7468657469633a0d726566726573685f746f6b656e406448c8015a06616374697665720773636f70652d619a011f0a0d726566726573685f746f6b656e120e0a047465737412066f7061717565a201150a036f6c64120e0a047465737412066f7061717565";
    const V0_0_116_DELETION: &str = "0a036f6c64120e0a047465737412066f7061717565";
    const V0_0_116_PROFILE: &str = "0a230a096c65676163792d6964120b6c65676163792d6e616d6528073a0764656661756c7412110a0770726f66696c6512064c6567616379";
    const V0_0_116_POLICY_PAYLOAD: &str =
        "0a0012067368613235361a046e6f6e6520ac022a110a06736f75726365120766697874757265";
    const V0_0_116_DRAFT_PAYLOAD: &str =
        "0a0472756c651a07666978747572652d0000403f3a0b6578616d706c652e636f6d40bb035002";
    const V0_0_116_POLICY_RECORD: &str = "0a09706f6c6963792d6964120a73616e64626f782d6964180222030102032a0673686132353632066c6f616465643a046e6f6e6540fa0148ac0252110a06736f75726365120766697874757265";
    const V0_0_116_DRAFT_RECORD: &str = "0a086368756e6b2d6964120a73616e64626f782d69641802220770656e64696e672a0472756c65320204053a076669787475726549000000000000e83f50de02589003620b6578616d706c652e636f6d68bb037801";
    const STORAGE_MESSAGE_NAMES: [&str; 7] = [
        "DraftChunkPayload",
        "PolicyRevisionPayload",
        "StoredDraftChunk",
        "StoredPolicyRevision",
        "StoredProviderCredentialRefreshState",
        "StoredProviderProfile",
        "StoredRefreshMaterialDeletion",
    ];
    const DURABLE_ROOTS: [&str; 13] = [
        ".openshell.datamodel.v1.Provider",
        ".openshell.datamodel.v1.Workspace",
        ".openshell.inference.v1.InferenceRoute",
        ".openshell.sandbox.v1.SandboxPolicy",
        ".openshell.storage.v1.DraftChunkPayload",
        ".openshell.storage.v1.PolicyRevisionPayload",
        ".openshell.storage.v1.StoredProviderCredentialRefreshState",
        ".openshell.storage.v1.StoredProviderProfile",
        ".openshell.v1.Sandbox",
        ".openshell.v1.SandboxWorkloadTemplate",
        ".openshell.v1.ServiceEndpoint",
        ".openshell.v1.SshSession",
        ".openshell.v1.WorkspaceMember",
    ];

    #[derive(Default)]
    struct SchemaIndex<'a> {
        messages: BTreeMap<String, &'a DescriptorProto>,
        enums: BTreeMap<String, &'a EnumDescriptorProto>,
    }

    #[derive(Debug)]
    struct SchemaClosure {
        messages: BTreeSet<String>,
        enums: BTreeSet<String>,
    }

    fn qualified_name(prefix: &str, name: &str) -> String {
        if prefix.is_empty() {
            format!(".{name}")
        } else {
            format!("{prefix}.{name}")
        }
    }

    fn index_message<'a>(index: &mut SchemaIndex<'a>, prefix: &str, message: &'a DescriptorProto) {
        let name = qualified_name(prefix, message.name.as_deref().expect("message name"));
        index.messages.insert(name.clone(), message);
        for nested in &message.nested_type {
            index_message(index, &name, nested);
        }
        for nested_enum in &message.enum_type {
            index.enums.insert(
                qualified_name(&name, nested_enum.name.as_deref().expect("enum name")),
                nested_enum,
            );
        }
    }

    fn index_descriptor<'a>(index: &mut SchemaIndex<'a>, descriptor: &'a FileDescriptorSet) {
        for file in &descriptor.file {
            let package = file.package.as_deref().unwrap_or_default();
            let prefix = if package.is_empty() {
                String::new()
            } else {
                format!(".{package}")
            };
            for message in &file.message_type {
                index_message(index, &prefix, message);
            }
            for r#enum in &file.enum_type {
                index.enums.insert(
                    qualified_name(&prefix, r#enum.name.as_deref().expect("enum name")),
                    r#enum,
                );
            }
        }
    }

    fn schema_closure(
        index: &SchemaIndex<'_>,
        roots: impl IntoIterator<Item = String>,
    ) -> SchemaClosure {
        let mut messages = BTreeSet::new();
        let mut enums = BTreeSet::new();
        let mut pending = roots.into_iter().collect::<VecDeque<_>>();
        while let Some(name) = pending.pop_front() {
            if let Some(message) = index.messages.get(&name) {
                if !messages.insert(name) {
                    continue;
                }
                for field in &message.field {
                    let Some(type_name) = field.type_name.as_ref() else {
                        continue;
                    };
                    if index.messages.contains_key(type_name) {
                        pending.push_back(type_name.clone());
                    } else if index.enums.contains_key(type_name) {
                        enums.insert(type_name.clone());
                    }
                }
            } else if index.enums.contains_key(&name) {
                enums.insert(name);
            } else {
                panic!("schema root or dependency {name} is missing from descriptors");
            }
        }
        SchemaClosure { messages, enums }
    }

    fn append_one_message_schema(output: &mut String, full_name: &str, message: &DescriptorProto) {
        output.push_str(&format!(
            "message|{}|{}|{:?}|{:?}|{:?}\n",
            full_name,
            message
                .options
                .as_ref()
                .map(|options| hex::encode(options.encode_to_vec()))
                .unwrap_or_default(),
            message.reserved_range,
            message.reserved_name,
            message.oneof_decl,
        ));
        for field in &message.field {
            output.push_str(&format!(
                "field|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
                full_name,
                field.number.unwrap_or_default(),
                field.name.as_deref().unwrap_or_default(),
                field.label.unwrap_or_default(),
                field.r#type.unwrap_or_default(),
                field.type_name.as_deref().unwrap_or_default(),
                field.oneof_index.unwrap_or(-1),
                field.proto3_optional.unwrap_or(false),
                field
                    .options
                    .as_ref()
                    .map(|options| hex::encode(options.encode_to_vec()))
                    .unwrap_or_default(),
            ));
        }
    }

    fn schema_fingerprint(index: &SchemaIndex<'_>, closure: &SchemaClosure) -> String {
        let mut schema = String::new();
        for name in &closure.messages {
            append_one_message_schema(&mut schema, name, index.messages[name]);
        }
        for name in &closure.enums {
            let r#enum = index.enums[name];
            schema.push_str(&format!(
                "enum|{}|{}|{:?}|{:?}\n",
                name,
                r#enum
                    .options
                    .as_ref()
                    .map(|options| hex::encode(options.encode_to_vec()))
                    .unwrap_or_default(),
                r#enum.reserved_range,
                r#enum.reserved_name,
            ));
            for value in &r#enum.value {
                schema.push_str(&format!(
                    "enum-value|{}|{}|{}|{}\n",
                    name,
                    value.number.unwrap_or_default(),
                    value.name.as_deref().unwrap_or_default(),
                    value
                        .options
                        .as_ref()
                        .map(|options| hex::encode(options.encode_to_vec()))
                        .unwrap_or_default(),
                ));
            }
        }
        format!("{:x}", Sha256::digest(schema.as_bytes()))
    }

    fn append_message_schema(output: &mut String, prefix: &str, message: &DescriptorProto) {
        let name = message.name.as_deref().expect("message name");
        let full_name = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}.{name}")
        };
        output.push_str(&format!(
            "message|{}|{}|{:?}|{:?}\n",
            full_name,
            message
                .options
                .as_ref()
                .map(|options| hex::encode(options.encode_to_vec()))
                .unwrap_or_default(),
            message.reserved_range,
            message.reserved_name,
        ));

        for field in &message.field {
            output.push_str(&format!(
                "field|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
                full_name,
                field.number.unwrap_or_default(),
                field.name.as_deref().unwrap_or_default(),
                field.label.unwrap_or_default(),
                field.r#type.unwrap_or_default(),
                field.type_name.as_deref().unwrap_or_default(),
                field.oneof_index.unwrap_or(-1),
                field.proto3_optional.unwrap_or(false),
                field
                    .options
                    .as_ref()
                    .map(|options| hex::encode(options.encode_to_vec()))
                    .unwrap_or_default(),
            ));
        }
        for nested in &message.nested_type {
            append_message_schema(output, &full_name, nested);
        }
    }

    fn storage_schema() -> (Vec<String>, String) {
        let descriptor = FileDescriptorSet::decode(STORAGE_FILE_DESCRIPTOR_SET)
            .expect("storage descriptor set must decode");
        let file = descriptor
            .file
            .iter()
            .find(|file| file.package.as_deref() == Some("openshell.storage.v1"))
            .expect("storage descriptor must contain openshell.storage.v1");
        let mut names = file
            .message_type
            .iter()
            .map(|message| message.name.clone().expect("message name"))
            .collect::<Vec<_>>();
        names.sort();

        let mut messages = file.message_type.iter().collect::<Vec<_>>();
        messages.sort_by_key(|message| message.name.as_deref().unwrap_or_default());
        let mut schema = String::new();
        for message in messages {
            append_message_schema(&mut schema, "", message);
        }
        (names, schema)
    }

    #[test]
    fn storage_v1_schema_is_frozen() {
        let (names, schema) = storage_schema();
        assert_eq!(names, STORAGE_MESSAGE_NAMES);
        let actual = format!("{:x}", Sha256::digest(schema.as_bytes()));
        assert_eq!(
            actual, STORAGE_V1_SCHEMA_SHA256,
            "openshell.storage.v1 changed; keep v1 decoders intact and introduce a versioned migration path before updating this reviewed fingerprint"
        );
    }

    #[test]
    fn storage_types_are_absent_from_public_descriptor() {
        let public = FileDescriptorSet::decode(openshell_core::FILE_DESCRIPTOR_SET)
            .expect("public descriptor set must decode");
        for file in public.file {
            assert_ne!(file.package.as_deref(), Some("openshell.storage.v1"));
            for message in file.message_type {
                let name = message.name.expect("message name");
                assert!(
                    !STORAGE_MESSAGE_NAMES.contains(&name.as_str()),
                    "storage-only message {name} leaked into the public descriptor"
                );
            }
        }
    }

    #[test]
    fn public_and_durable_schema_inventories_are_complete() {
        let public = FileDescriptorSet::decode(openshell_core::FILE_DESCRIPTOR_SET)
            .expect("public descriptor set must decode");
        let storage = FileDescriptorSet::decode(STORAGE_FILE_DESCRIPTOR_SET)
            .expect("storage descriptor set must decode");
        let mut index = SchemaIndex::default();
        index_descriptor(&mut index, &storage);
        index_descriptor(&mut index, &public);

        let mut methods = Vec::new();
        let mut public_roots = BTreeSet::new();
        let mut compiled_method_count = 0;
        for file in &public.file {
            let package = file.package.as_deref().unwrap_or_default();
            for service in &file.service {
                let service_name = service.name.as_deref().expect("service name");
                compiled_method_count += service.method.len();
                if !matches!(
                    (package, service_name),
                    ("openshell.v1", "OpenShell") | ("openshell.inference.v1", "Inference")
                ) {
                    continue;
                }
                for method in &service.method {
                    let input = method.input_type.as_deref().expect("method input type");
                    let output = method.output_type.as_deref().expect("method output type");
                    public_roots.insert(input.to_string());
                    public_roots.insert(output.to_string());
                    methods.push(format!(
                        "{package}.{service_name}/{}|{}|{}|{}|{}",
                        method.name.as_deref().expect("method name"),
                        input,
                        output,
                        method.client_streaming.unwrap_or(false),
                        method.server_streaming.unwrap_or(false),
                    ));
                }
            }
        }
        methods.sort();
        assert_eq!(compiled_method_count, 102, "classify every compiled RPC");
        assert_eq!(methods.len(), 77, "inventory every public gateway RPC");
        assert_eq!(
            methods
                .iter()
                .filter(|method| method.starts_with("openshell.v1.OpenShell/"))
                .count(),
            73
        );
        assert_eq!(
            methods
                .iter()
                .filter(|method| method.starts_with("openshell.inference.v1.Inference/"))
                .count(),
            4
        );
        assert!(methods.iter().all(|method| !method.contains(".storage.")));

        let public_closure = schema_closure(&index, public_roots);
        let durable_closure = schema_closure(&index, DURABLE_ROOTS.into_iter().map(str::to_string));
        let overlap_messages = public_closure
            .messages
            .intersection(&durable_closure.messages)
            .cloned()
            .collect::<BTreeSet<_>>();
        let overlap_enums = public_closure
            .enums
            .intersection(&durable_closure.enums)
            .cloned()
            .collect::<BTreeSet<_>>();
        let overlap_inventory = overlap_messages
            .iter()
            .map(|name| format!("message|{name}"))
            .chain(overlap_enums.iter().map(|name| format!("enum|{name}")))
            .collect::<Vec<_>>()
            .join("\n");

        let public_schema_hash = schema_fingerprint(&index, &public_closure);
        let public_inventory_hash = format!(
            "{:x}",
            Sha256::digest(format!("{}\n{public_schema_hash}", methods.join("\n")).as_bytes())
        );
        let durable_inventory_hash = schema_fingerprint(&index, &durable_closure);
        let overlap_hash = format!("{:x}", Sha256::digest(overlap_inventory.as_bytes()));

        assert_eq!(
            (public_closure.messages.len(), public_closure.enums.len()),
            (280, 12)
        );
        assert_eq!(
            (durable_closure.messages.len(), durable_closure.enums.len()),
            (83, 8)
        );
        assert_eq!((overlap_messages.len(), overlap_enums.len()), (71, 8));

        assert_eq!(
            public_inventory_hash, PUBLIC_RPC_SCHEMA_SHA256,
            "the public RPC schema closure changed; review API compatibility and update the inventory and architecture/gateway.md"
        );
        assert_eq!(
            durable_inventory_hash, DURABLE_SCHEMA_SHA256,
            "a durable protobuf root or transitive dependency changed; record migration handling and a prior-version fixture before updating this fingerprint"
        );
        assert_eq!(
            overlap_hash, PUBLIC_DURABLE_OVERLAP_SHA256,
            "the public/durable protobuf overlap changed; review both API and storage compatibility before updating this inventory"
        );
    }

    fn legacy_bytes(encoded: &str) -> Vec<u8> {
        hex::decode(encoded).expect("checked-in legacy fixture must be valid hex")
    }

    #[test]
    fn pre_move_storage_payloads_decode_after_package_relocation() {
        let refresh = StoredProviderCredentialRefreshState::decode(
            legacy_bytes(V0_0_116_REFRESH_STATE).as_slice(),
        )
        .expect("legacy refresh state must decode");
        assert_eq!(refresh.provider_id, "provider-id");
        assert_eq!(refresh.provider_name, "provider");
        assert_eq!(refresh.credential_key, "TOKEN");
        assert_eq!(refresh.material["client_id"], "synthetic");
        assert_eq!(refresh.secret_material_keys, ["refresh_token"]);
        assert_eq!(refresh.expires_at_ms, 100);
        assert_eq!(refresh.next_refresh_at_ms, 200);
        assert_eq!(refresh.status, "active");
        assert_eq!(refresh.scopes, ["scope-a"]);
        assert_eq!(
            refresh.secret_material_handles["refresh_token"].driver,
            "test"
        );
        assert_eq!(refresh.pending_secret_deletions[0].material_key, "old");

        let deletion =
            StoredRefreshMaterialDeletion::decode(legacy_bytes(V0_0_116_DELETION).as_slice())
                .expect("legacy deletion must decode");
        assert_eq!(deletion.material_key, "old");
        assert_eq!(deletion.handle.expect("handle").driver, "test");

        let profile = StoredProviderProfile::decode(legacy_bytes(V0_0_116_PROFILE).as_slice())
            .expect("legacy provider profile must decode");
        let profile = profile.profile.expect("profile");
        assert_eq!(profile.id, "profile");
        assert_eq!(profile.display_name, "Legacy");

        let policy_payload =
            PolicyRevisionPayload::decode(legacy_bytes(V0_0_116_POLICY_PAYLOAD).as_slice())
                .expect("legacy policy payload must decode");
        assert!(policy_payload.policy.is_some());
        assert_eq!(policy_payload.hash, "sha256");
        assert_eq!(policy_payload.load_error, "none");
        assert_eq!(policy_payload.loaded_at_ms, 300);
        assert_eq!(policy_payload.provenance["source"], "fixture");

        let draft_payload =
            DraftChunkPayload::decode(legacy_bytes(V0_0_116_DRAFT_PAYLOAD).as_slice())
                .expect("legacy draft payload must decode");
        assert_eq!(draft_payload.rule_name, "rule");
        assert_eq!(draft_payload.rationale, "fixture");
        assert_eq!(draft_payload.confidence, 0.75);
        assert_eq!(draft_payload.host, "example.com");
        assert_eq!(draft_payload.port, 443);
        assert_eq!(draft_payload.draft_version, 2);

        let policy = StoredPolicyRevision::decode(legacy_bytes(V0_0_116_POLICY_RECORD).as_slice())
            .expect("legacy policy record must decode");
        assert_eq!(policy.id, "policy-id");
        assert_eq!(policy.sandbox_id, "sandbox-id");
        assert_eq!(policy.version, 2);
        assert_eq!(policy.policy_payload, [1, 2, 3]);
        assert_eq!(policy.policy_hash, "sha256");
        assert_eq!(policy.status, "loaded");
        assert_eq!(policy.load_error.as_deref(), Some("none"));
        assert_eq!(policy.created_at_ms, 250);
        assert_eq!(policy.loaded_at_ms, Some(300));
        assert_eq!(policy.provenance["source"], "fixture");

        let draft = StoredDraftChunk::decode(legacy_bytes(V0_0_116_DRAFT_RECORD).as_slice())
            .expect("legacy draft record must decode");
        assert_eq!(draft.id, "chunk-id");
        assert_eq!(draft.sandbox_id, "sandbox-id");
        assert_eq!(draft.draft_version, 2);
        assert_eq!(draft.status, "pending");
        assert_eq!(draft.rule_name, "rule");
        assert_eq!(draft.proposed_rule, [4, 5]);
        assert_eq!(draft.rationale, "fixture");
        assert_eq!(draft.confidence, 0.75);
        assert_eq!(draft.created_at_ms, 350);
        assert_eq!(draft.decided_at_ms, Some(400));
        assert_eq!(draft.host, "example.com");
        assert_eq!(draft.port, 443);
        assert_eq!(draft.hit_count, 1);
    }

    #[tokio::test]
    async fn v0_0_116_database_payloads_survive_current_migrations() {
        use crate::persistence::{DRAFT_CHUNK_OBJECT_TYPE, POLICY_OBJECT_TYPE, Store};
        use crate::policy_store::{draft_chunk_record_from_parts, policy_record_from_parts};

        let tempdir = tempfile::tempdir().expect("temporary database directory");
        let database_path = tempdir.path().join("v0.0.116.db");
        let database_url = format!("sqlite://{}", database_path.display());

        // v0.0.116 and this change share migrations 001-006. Populate that
        // historical on-disk shape with bytes emitted by the v0.0.116 schema,
        // then reopen it through the current migration and loader path.
        let old_store = Store::connect(&database_url)
            .await
            .expect("create legacy database");
        let fixtures = [
            (
                "provider_credential_refresh_state",
                "legacy-id",
                "legacy-name",
                "default",
                V0_0_116_REFRESH_STATE,
            ),
            (
                "provider_profile",
                "legacy-profile-id",
                "legacy-profile",
                "",
                V0_0_116_PROFILE,
            ),
            (
                POLICY_OBJECT_TYPE,
                "policy-id",
                "",
                "default",
                V0_0_116_POLICY_PAYLOAD,
            ),
            (
                DRAFT_CHUNK_OBJECT_TYPE,
                "chunk-id",
                "",
                "default",
                V0_0_116_DRAFT_PAYLOAD,
            ),
        ];
        for (object_type, id, name, workspace, payload) in fixtures {
            old_store
                .put(
                    object_type,
                    id,
                    name,
                    workspace,
                    &legacy_bytes(payload),
                    None,
                )
                .await
                .expect("insert v0.0.116 fixture");
        }
        old_store.close().await;

        let current_store = Store::connect(&database_url)
            .await
            .expect("current migrations must accept legacy database");
        for (object_type, id, _, _, payload) in fixtures {
            let record = current_store
                .get(object_type, id)
                .await
                .expect("load fixture row")
                .expect("fixture row must remain present");
            assert_eq!(record.payload, legacy_bytes(payload));
        }

        let refresh = current_store
            .get_message::<StoredProviderCredentialRefreshState>("legacy-id")
            .await
            .expect("decode refresh fixture")
            .expect("refresh fixture must remain present");
        assert_eq!(refresh.provider_id, "provider-id");
        assert_eq!(refresh.get_resource_version(), 1);

        let profile = current_store
            .get_message::<StoredProviderProfile>("legacy-profile-id")
            .await
            .expect("decode profile fixture")
            .expect("profile fixture must remain present");
        assert_eq!(profile.profile.expect("profile").display_name, "Legacy");

        let policy_record = current_store
            .get(POLICY_OBJECT_TYPE, "policy-id")
            .await
            .expect("load policy fixture")
            .expect("policy fixture must remain present");
        let policy = policy_record_from_parts(
            policy_record.id,
            "sandbox-id".to_string(),
            2,
            "loaded".to_string(),
            &policy_record.payload,
            policy_record.created_at_ms,
        )
        .expect("current policy loader must decode v0.0.116 payload");
        assert_eq!(policy.policy_hash, "sha256");
        assert_eq!(policy.provenance["source"], "fixture");

        let draft_record = current_store
            .get(DRAFT_CHUNK_OBJECT_TYPE, "chunk-id")
            .await
            .expect("load draft fixture")
            .expect("draft fixture must remain present");
        let draft = draft_chunk_record_from_parts(
            draft_record.id,
            "sandbox-id".to_string(),
            "pending".to_string(),
            1,
            &draft_record.payload,
            draft_record.created_at_ms,
            draft_record.updated_at_ms,
        )
        .expect("current draft loader must decode v0.0.116 payload");
        assert_eq!(draft.rule_name, "rule");
        assert_eq!(draft.host, "example.com");
        assert_eq!(draft.port, 443);
    }
}
