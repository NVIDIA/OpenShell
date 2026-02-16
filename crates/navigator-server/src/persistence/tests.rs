use super::{ObjectId, ObjectName, ObjectType, Store, generate_name};
use navigator_core::proto::ObjectForTest;

#[tokio::test]
async fn sqlite_put_get_round_trip() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put("sandbox", "abc", "my-sandbox", b"payload")
        .await
        .unwrap();

    let record = store.get("sandbox", "abc").await.unwrap().unwrap();
    assert_eq!(record.object_type, "sandbox");
    assert_eq!(record.id, "abc");
    assert_eq!(record.name, "my-sandbox");
    assert_eq!(record.payload, b"payload");
}

#[tokio::test]
async fn sqlite_updates_timestamp() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put("sandbox", "abc", "my-sandbox", b"payload")
        .await
        .unwrap();

    let first = store.get("sandbox", "abc").await.unwrap().unwrap();

    store
        .put("sandbox", "abc", "my-sandbox", b"payload2")
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
            .put("sandbox", &id, &name, payload.as_bytes())
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
        .put("sandbox", "abc", "my-sandbox", b"payload")
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
        .put("sandbox", "id-1", "my-sandbox", b"payload")
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
        .put("sandbox", "id-1", "my-sandbox", b"payload")
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
        .put("sandbox", "id-1", "shared-name", b"payload1")
        .await
        .unwrap();

    // Same name, same object_type, different id -> should fail (unique constraint).
    let result = store
        .put("sandbox", "id-2", "shared-name", b"payload2")
        .await;
    assert!(result.is_err());

    // Same name, different object_type -> should succeed.
    store
        .put("secret", "id-3", "shared-name", b"payload3")
        .await
        .unwrap();
}

#[tokio::test]
async fn sqlite_id_globally_unique() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put("sandbox", "same-id", "name-a", b"payload1")
        .await
        .unwrap();

    // Same id, different object_type -> the upsert is a no-op (WHERE
    // clause prevents updating a row with a different object_type).
    // The original row is preserved unchanged.
    store
        .put("secret", "same-id", "name-b", b"payload2")
        .await
        .unwrap();

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

impl ObjectId for ObjectForTest {
    fn object_id(&self) -> &str {
        &self.id
    }
}

impl ObjectName for ObjectForTest {
    fn object_name(&self) -> &str {
        &self.name
    }
}
