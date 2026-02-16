//! Persistence layer for Navigator Server.

mod postgres;
mod sqlite;

use navigator_core::{Error, Result};
use prost::Message;
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

pub use postgres::PostgresStore;
pub use sqlite::SqliteStore;

/// Stored object record.
#[derive(Debug, Clone)]
pub struct ObjectRecord {
    pub object_type: String,
    pub id: String,
    pub name: String,
    pub payload: Vec<u8>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

/// Persistence store implementations.
#[derive(Debug, Clone)]
pub enum Store {
    Postgres(PostgresStore),
    Sqlite(SqliteStore),
}

/// Trait for inferring an object type string from a message type.
pub trait ObjectType {
    fn object_type() -> &'static str;
}

/// Trait for extracting an object id from a message instance.
pub trait ObjectId {
    fn object_id(&self) -> &str;
}

/// Trait for extracting an object name from a message instance.
pub trait ObjectName {
    fn object_name(&self) -> &str;
}

/// Generate a random 6-character lowercase alphabetic name.
pub fn generate_name() -> String {
    let mut rng = rand::rng();
    (0..6)
        .map(|_| rng.random_range(b'a'..=b'z') as char)
        .collect()
}

impl Store {
    /// Connect to a persistence store based on the database URL.
    pub async fn connect(url: &str) -> Result<Self> {
        if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            let store = PostgresStore::connect(url).await?;
            store.migrate().await?;
            Ok(Self::Postgres(store))
        } else if url.starts_with("sqlite:") {
            let store = SqliteStore::connect(url).await?;
            store.migrate().await?;
            Ok(Self::Sqlite(store))
        } else {
            Err(Error::config(format!(
                "unsupported database URL scheme: {url}"
            )))
        }
    }

    /// Insert or update an object.
    pub async fn put(&self, object_type: &str, id: &str, name: &str, payload: &[u8]) -> Result<()> {
        match self {
            Self::Postgres(store) => store.put(object_type, id, name, payload).await,
            Self::Sqlite(store) => store.put(object_type, id, name, payload).await,
        }
    }

    /// Fetch an object by id.
    pub async fn get(&self, object_type: &str, id: &str) -> Result<Option<ObjectRecord>> {
        match self {
            Self::Postgres(store) => store.get(object_type, id).await,
            Self::Sqlite(store) => store.get(object_type, id).await,
        }
    }

    /// Fetch an object by name within an object type.
    pub async fn get_by_name(&self, object_type: &str, name: &str) -> Result<Option<ObjectRecord>> {
        match self {
            Self::Postgres(store) => store.get_by_name(object_type, name).await,
            Self::Sqlite(store) => store.get_by_name(object_type, name).await,
        }
    }

    /// Delete an object by id.
    pub async fn delete(&self, object_type: &str, id: &str) -> Result<bool> {
        match self {
            Self::Postgres(store) => store.delete(object_type, id).await,
            Self::Sqlite(store) => store.delete(object_type, id).await,
        }
    }

    /// Delete an object by name within an object type.
    pub async fn delete_by_name(&self, object_type: &str, name: &str) -> Result<bool> {
        match self {
            Self::Postgres(store) => store.delete_by_name(object_type, name).await,
            Self::Sqlite(store) => store.delete_by_name(object_type, name).await,
        }
    }

    /// List objects by type.
    pub async fn list(
        &self,
        object_type: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<ObjectRecord>> {
        match self {
            Self::Postgres(store) => store.list(object_type, limit, offset).await,
            Self::Sqlite(store) => store.list(object_type, limit, offset).await,
        }
    }

    /// Insert or update a protobuf message using its inferred object type, id, and name.
    pub async fn put_message<T: Message + ObjectType + ObjectId + ObjectName>(
        &self,
        message: &T,
    ) -> Result<()> {
        self.put(
            T::object_type(),
            message.object_id(),
            message.object_name(),
            &message.encode_to_vec(),
        )
        .await
    }

    /// Fetch and decode a protobuf message by id.
    pub async fn get_message<T: Message + Default + ObjectType>(
        &self,
        id: &str,
    ) -> Result<Option<T>> {
        let record = self.get(T::object_type(), id).await?;
        let Some(record) = record else {
            return Ok(None);
        };

        T::decode(record.payload.as_slice())
            .map(Some)
            .map_err(|e| Error::execution(format!("protobuf decode error: {e}")))
    }

    /// Fetch and decode a protobuf message by name.
    pub async fn get_message_by_name<T: Message + Default + ObjectType>(
        &self,
        name: &str,
    ) -> Result<Option<T>> {
        let record = self.get_by_name(T::object_type(), name).await?;
        let Some(record) = record else {
            return Ok(None);
        };

        T::decode(record.payload.as_slice())
            .map(Some)
            .map_err(|e| Error::execution(format!("protobuf decode error: {e}")))
    }
}

fn current_time_ms() -> Result<i64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::execution(format!("time error: {e}")))?;
    i64::try_from(now.as_millis())
        .map_err(|e| Error::execution(format!("time conversion error: {e}")))
}

fn map_db_error(error: &sqlx::Error) -> Error {
    Error::execution(format!("database error: {error}"))
}

fn map_migrate_error(error: &sqlx::migrate::MigrateError) -> Error {
    Error::execution(format!("migration error: {error}"))
}

#[cfg(test)]
mod tests;
