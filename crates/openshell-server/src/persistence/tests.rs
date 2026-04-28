// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{ObjectType, Store, generate_name};
use crate::policy_store::PolicyStoreExt;
use openshell_core::proto::{ObjectForTest, SandboxPolicy};
use prost::Message;

#[tokio::test]
async fn sqlite_put_get_round_trip() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put("sandbox", "abc", "my-sandbox", b"payload", None)
        .await
        .unwrap();

    let record = store.get("sandbox", "abc").await.unwrap().unwrap();
    assert_eq!(record.object_type, "sandbox");
    assert_eq!(record.id, "abc");
    assert_eq!(record.name, "my-sandbox");
    assert_eq!(record.payload, b"payload");
}

#[tokio::test]
async fn sqlite_connect_runs_embedded_migrations() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    let records = store.list("sandbox", 10, 0).await.unwrap();
    assert!(records.is_empty());
}

#[tokio::test]
async fn sqlite_updates_timestamp() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put("sandbox", "abc", "my-sandbox", b"payload", None)
        .await
        .unwrap();

    let first = store.get("sandbox", "abc").await.unwrap().unwrap();

    store
        .put("sandbox", "abc", "my-sandbox", b"payload2", None)
        .await
        .unwrap();

    let second = store.get("sandbox", "abc").await.unwrap().unwrap();
    assert!(second.updated_at_ms >= first.updated_at_ms);
    assert_eq!(second.payload, b"payload2");
}

#[tokio::test]
async fn sqlite_list_paging() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    for idx in 0..5 {
        let id = format!("id-{idx}");
        let name = format!("name-{idx}");
        let payload = format!("payload-{idx}");
        store
            .put("sandbox", &id, &name, payload.as_bytes(), None)
            .await
            .unwrap();
    }

    let records = store.list("sandbox", 2, 1).await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].name, "name-1");
    assert_eq!(records[1].name, "name-2");
}

#[tokio::test]
async fn sqlite_delete_behavior() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put("sandbox", "abc", "my-sandbox", b"payload", None)
        .await
        .unwrap();

    let deleted = store.delete("sandbox", "abc").await.unwrap();
    assert!(deleted);

    let deleted_again = store.delete("sandbox", "missing").await.unwrap();
    assert!(!deleted_again);
}

#[tokio::test]
async fn sqlite_protobuf_round_trip() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    let object = ObjectForTest {
        id: "abc".to_string(),
        name: "test-object".to_string(),
        count: 42,
    };

    store.put_message(&object).await.unwrap();

    let loaded = store
        .get_message::<ObjectForTest>(&object.id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(loaded.id, object.id);
    assert_eq!(loaded.name, object.name);
    assert_eq!(loaded.count, object.count);
}

#[tokio::test]
async fn sqlite_get_by_name() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put("sandbox", "id-1", "my-sandbox", b"payload", None)
        .await
        .unwrap();

    let record = store
        .get_by_name("sandbox", "my-sandbox")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.id, "id-1");
    assert_eq!(record.name, "my-sandbox");
    assert_eq!(record.payload, b"payload");

    let missing = store.get_by_name("sandbox", "no-such-name").await.unwrap();
    assert!(missing.is_none());
}

#[tokio::test]
async fn sqlite_get_message_by_name() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    let object = ObjectForTest {
        id: "uid-1".to_string(),
        name: "my-test".to_string(),
        count: 7,
    };

    store.put_message(&object).await.unwrap();

    let loaded = store
        .get_message_by_name::<ObjectForTest>("my-test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.id, "uid-1");
    assert_eq!(loaded.name, "my-test");
    assert_eq!(loaded.count, 7);

    let missing = store
        .get_message_by_name::<ObjectForTest>("no-such-name")
        .await
        .unwrap();
    assert!(missing.is_none());
}

#[tokio::test]
async fn sqlite_delete_by_name() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put("sandbox", "id-1", "my-sandbox", b"payload", None)
        .await
        .unwrap();

    let deleted = store.delete_by_name("sandbox", "my-sandbox").await.unwrap();
    assert!(deleted);

    let deleted_again = store.delete_by_name("sandbox", "my-sandbox").await.unwrap();
    assert!(!deleted_again);

    let gone = store.get("sandbox", "id-1").await.unwrap();
    assert!(gone.is_none());
}

#[tokio::test]
async fn sqlite_name_unique_per_object_type() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put("sandbox", "id-1", "shared-name", b"payload1", None)
        .await
        .unwrap();

    // Same name, same object_type, different id -> upsert on name.
    store
        .put("sandbox", "id-2", "shared-name", b"payload2", None)
        .await
        .unwrap();

    let record = store
        .get_by_name("sandbox", "shared-name")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.id, "id-1");
    assert_eq!(record.payload, b"payload2");

    // Same name, different object_type -> should succeed.
    store
        .put("secret", "id-3", "shared-name", b"payload3", None)
        .await
        .unwrap();
}

#[tokio::test]
async fn sqlite_id_globally_unique() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put("sandbox", "same-id", "name-a", b"payload1", None)
        .await
        .unwrap();

    // Same id, different object_type -> should fail because ids remain global
    // primary keys even when writes upsert on name.
    let result = store
        .put("secret", "same-id", "name-b", b"payload2", None)
        .await;
    assert!(result.is_err());

    // Original row is untouched.
    let record = store.get("sandbox", "same-id").await.unwrap().unwrap();
    assert_eq!(record.object_type, "sandbox");
    assert_eq!(record.payload, b"payload1");

    // The secret was not inserted.
    let missing = store.get("secret", "same-id").await.unwrap();
    assert!(missing.is_none());
}

#[test]
fn generate_name_format() {
    for _ in 0..100 {
        let name = generate_name();
        assert_eq!(name.len(), 6);
        assert!(name.chars().all(|c| c.is_ascii_lowercase()));
    }
}

impl ObjectType for ObjectForTest {
    fn object_type() -> &'static str {
        "object_for_test"
    }
}

// ObjectId, ObjectName, ObjectLabels implementations
// for ObjectForTest are in openshell-core::metadata

// ---------------------------------------------------------------------------
// ObjectMeta tests (labels)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn labels_round_trip() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    let labels = r#"{"env":"production","team":"platform"}"#;
    store
        .put(
            "sandbox",
            "id-1",
            "labeled-sandbox",
            b"payload",
            Some(labels),
        )
        .await
        .unwrap();

    let record = store.get("sandbox", "id-1").await.unwrap().unwrap();
    assert_eq!(record.labels.as_deref(), Some(labels));
}

#[tokio::test]
async fn label_selector_single_match() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put("sandbox", "id-1", "s1", b"p1", Some(r#"{"env":"prod"}"#))
        .await
        .unwrap();
    store
        .put("sandbox", "id-2", "s2", b"p2", Some(r#"{"env":"dev"}"#))
        .await
        .unwrap();
    store
        .put(
            "sandbox",
            "id-3",
            "s3",
            b"p3",
            Some(r#"{"env":"prod","team":"platform"}"#),
        )
        .await
        .unwrap();

    let results = store
        .list_with_selector("sandbox", "env=prod", 10, 0)
        .await
        .unwrap();

    assert_eq!(results.len(), 2);
    let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains(&"id-1"));
    assert!(ids.contains(&"id-3"));
}

#[tokio::test]
async fn label_selector_multiple_labels() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put(
            "sandbox",
            "id-1",
            "s1",
            b"p1",
            Some(r#"{"env":"prod","team":"platform"}"#),
        )
        .await
        .unwrap();
    store
        .put(
            "sandbox",
            "id-2",
            "s2",
            b"p2",
            Some(r#"{"env":"prod","team":"data"}"#),
        )
        .await
        .unwrap();
    store
        .put(
            "sandbox",
            "id-3",
            "s3",
            b"p3",
            Some(r#"{"env":"dev","team":"platform"}"#),
        )
        .await
        .unwrap();

    let results = store
        .list_with_selector("sandbox", "env=prod,team=platform", 10, 0)
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "id-1");
}

#[tokio::test]
async fn label_selector_no_match() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put("sandbox", "id-1", "s1", b"p1", Some(r#"{"env":"prod"}"#))
        .await
        .unwrap();

    let results = store
        .list_with_selector("sandbox", "env=staging", 10, 0)
        .await
        .unwrap();

    assert_eq!(results.len(), 0);
}

#[tokio::test]
async fn label_selector_respects_paging() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    for idx in 0..5 {
        let id = format!("id-{idx}");
        let name = format!("name-{idx}");
        store
            .put("sandbox", &id, &name, b"payload", Some(r#"{"env":"prod"}"#))
            .await
            .unwrap();
    }

    let page1 = store
        .list_with_selector("sandbox", "env=prod", 2, 0)
        .await
        .unwrap();
    assert_eq!(page1.len(), 2);

    let page2 = store
        .list_with_selector("sandbox", "env=prod", 2, 2)
        .await
        .unwrap();
    assert_eq!(page2.len(), 2);

    let page3 = store
        .list_with_selector("sandbox", "env=prod", 2, 4)
        .await
        .unwrap();
    assert_eq!(page3.len(), 1);
}

#[tokio::test]
async fn empty_labels_not_matched_by_selector() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put("sandbox", "id-1", "s1", b"p1", None)
        .await
        .unwrap();
    store
        .put("sandbox", "id-2", "s2", b"p2", Some(r#"{"env":"prod"}"#))
        .await
        .unwrap();

    let results = store
        .list_with_selector("sandbox", "env=prod", 10, 0)
        .await
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "id-2");
}

// ---------------------------------------------------------------------------
// Policy revision tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn policy_put_and_get_latest() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    let policy_v1 = SandboxPolicy::default().encode_to_vec();
    store
        .put_policy_revision("p1", "sandbox-1", 1, &policy_v1, "hash1")
        .await
        .unwrap();

    let latest = store.get_latest_policy("sandbox-1").await.unwrap().unwrap();
    assert_eq!(latest.version, 1);
    assert_eq!(latest.policy_hash, "hash1");
    assert_eq!(latest.status, "pending");
    assert_eq!(latest.policy_payload, policy_v1);

    // Add version 2
    let policy_v2 = SandboxPolicy {
        version: 2,
        ..SandboxPolicy::default()
    }
    .encode_to_vec();
    store
        .put_policy_revision("p2", "sandbox-1", 2, &policy_v2, "hash2")
        .await
        .unwrap();

    let latest = store.get_latest_policy("sandbox-1").await.unwrap().unwrap();
    assert_eq!(latest.version, 2);
    assert_eq!(latest.policy_hash, "hash2");
}

#[tokio::test]
async fn policy_get_by_version() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    let policy_v1 = SandboxPolicy::default().encode_to_vec();
    let policy_v2 = SandboxPolicy {
        version: 2,
        ..SandboxPolicy::default()
    }
    .encode_to_vec();
    store
        .put_policy_revision("p1", "sandbox-1", 1, &policy_v1, "h1")
        .await
        .unwrap();
    store
        .put_policy_revision("p2", "sandbox-1", 2, &policy_v2, "h2")
        .await
        .unwrap();

    let v1 = store
        .get_policy_by_version("sandbox-1", 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v1.version, 1);
    assert_eq!(v1.policy_hash, "h1");

    let v2 = store
        .get_policy_by_version("sandbox-1", 2)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v2.version, 2);
    assert_eq!(v2.policy_hash, "h2");

    let none = store.get_policy_by_version("sandbox-1", 99).await.unwrap();
    assert!(none.is_none());
}

#[tokio::test]
async fn policy_update_status_and_get_loaded() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    let payload = SandboxPolicy::default().encode_to_vec();
    store
        .put_policy_revision("p1", "sandbox-1", 1, &payload, "h1")
        .await
        .unwrap();

    // No loaded policy yet.
    let loaded = store.get_latest_loaded_policy("sandbox-1").await.unwrap();
    assert!(loaded.is_none());

    // Mark as loaded.
    let updated = store
        .update_policy_status("sandbox-1", 1, "loaded", None, Some(1000))
        .await
        .unwrap();
    assert!(updated);

    let loaded = store
        .get_latest_loaded_policy("sandbox-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.version, 1);
    assert_eq!(loaded.status, "loaded");
    assert_eq!(loaded.loaded_at_ms, Some(1000));
}

#[tokio::test]
async fn policy_status_failed_with_error() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    let payload = SandboxPolicy::default().encode_to_vec();
    store
        .put_policy_revision("p1", "sandbox-1", 1, &payload, "h1")
        .await
        .unwrap();

    store
        .update_policy_status("sandbox-1", 1, "failed", Some("L7 validation error"), None)
        .await
        .unwrap();

    let record = store
        .get_policy_by_version("sandbox-1", 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.status, "failed");
    assert_eq!(record.load_error.as_deref(), Some("L7 validation error"));
}

#[tokio::test]
async fn policy_supersede_older() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    let payload = SandboxPolicy::default().encode_to_vec();
    store
        .put_policy_revision("p1", "sandbox-1", 1, &payload, "h1")
        .await
        .unwrap();
    store
        .put_policy_revision("p2", "sandbox-1", 2, &payload, "h2")
        .await
        .unwrap();
    store
        .put_policy_revision("p3", "sandbox-1", 3, &payload, "h3")
        .await
        .unwrap();

    // Mark v1 as loaded.
    store
        .update_policy_status("sandbox-1", 1, "loaded", None, Some(1000))
        .await
        .unwrap();

    // Supersede all older revisions (pending + loaded) before v3.
    let count = store
        .supersede_older_policies("sandbox-1", 3)
        .await
        .unwrap();
    assert_eq!(count, 2); // v1 (loaded) + v2 (pending) both < v3

    let v1 = store
        .get_policy_by_version("sandbox-1", 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v1.status, "superseded");

    let v2 = store
        .get_policy_by_version("sandbox-1", 2)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v2.status, "superseded");

    let v3 = store
        .get_policy_by_version("sandbox-1", 3)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v3.status, "pending"); // still pending (not < 3)
}

#[tokio::test]
async fn policy_list_ordered_by_version_desc() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    let payload = SandboxPolicy::default().encode_to_vec();
    store
        .put_policy_revision("p1", "sandbox-1", 1, &payload, "h1")
        .await
        .unwrap();
    store
        .put_policy_revision("p2", "sandbox-1", 2, &payload, "h2")
        .await
        .unwrap();
    store
        .put_policy_revision("p3", "sandbox-1", 3, &payload, "h3")
        .await
        .unwrap();

    let records = store.list_policies("sandbox-1", 10, 0).await.unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].version, 3);
    assert_eq!(records[1].version, 2);
    assert_eq!(records[2].version, 1);

    // Test with limit.
    let records = store.list_policies("sandbox-1", 2, 0).await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].version, 3);
    assert_eq!(records[1].version, 2);
}

#[tokio::test]
async fn policy_isolation_between_sandboxes() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    let policy_s1 = SandboxPolicy::default().encode_to_vec();
    let policy_s2 = SandboxPolicy {
        version: 7,
        ..SandboxPolicy::default()
    }
    .encode_to_vec();
    store
        .put_policy_revision("p1", "sandbox-1", 1, &policy_s1, "h1")
        .await
        .unwrap();
    store
        .put_policy_revision("p2", "sandbox-2", 1, &policy_s2, "h2")
        .await
        .unwrap();

    let s1 = store.get_latest_policy("sandbox-1").await.unwrap().unwrap();
    let s2 = store.get_latest_policy("sandbox-2").await.unwrap().unwrap();

    assert_eq!(s1.policy_payload, policy_s1);
    assert_eq!(s2.policy_payload, policy_s2);
}

// ---- Label selector parsing tests ----

#[test]
fn parse_label_selector_empty_string() {
    let result = super::parse_label_selector("").unwrap();
    assert!(result.is_empty());
}

#[test]
fn parse_label_selector_single_pair() {
    let result = super::parse_label_selector("env=prod").unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result.get("env"), Some(&"prod".to_string()));
}

#[test]
fn parse_label_selector_multiple_pairs() {
    let result = super::parse_label_selector("env=prod,tier=frontend,version=v1").unwrap();
    assert_eq!(result.len(), 3);
    assert_eq!(result.get("env"), Some(&"prod".to_string()));
    assert_eq!(result.get("tier"), Some(&"frontend".to_string()));
    assert_eq!(result.get("version"), Some(&"v1".to_string()));
}

#[test]
fn parse_label_selector_accepts_empty_value() {
    // Kubernetes allows empty label values, so selectors should accept "key=" format
    let result = super::parse_label_selector("env=").unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result.get("env"), Some(&"".to_string()));
}

#[test]
fn parse_label_selector_multiple_with_empty_value() {
    let result = super::parse_label_selector("env=,tier=frontend").unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result.get("env"), Some(&"".to_string()));
    assert_eq!(result.get("tier"), Some(&"frontend".to_string()));
}

#[test]
fn parse_label_selector_rejects_empty_key() {
    let result = super::parse_label_selector("=value");
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("key cannot be empty")
    );
}

#[test]
fn parse_label_selector_rejects_missing_equals() {
    let result = super::parse_label_selector("env");
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("expected 'key=value'")
    );
}

#[test]
fn parse_label_selector_handles_whitespace() {
    let result = super::parse_label_selector("env = prod , tier = frontend").unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result.get("env"), Some(&"prod".to_string()));
    assert_eq!(result.get("tier"), Some(&"frontend".to_string()));
}
