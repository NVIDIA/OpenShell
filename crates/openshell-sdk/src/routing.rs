// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Routes long-lived sandbox calls to the replica that owns the sandbox.

use openshell_core::replica_routing::{
    OWNER_REPLICA_HEADER, OWNER_REQUEST_HEADER, ROUTE_REPLICA_HEADER,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use tonic::metadata::AsciiMetadataValue;

/// A stale owner is safe: a live non-owner replica relays the call.
const OWNER_TTL: Duration = Duration::from_secs(30);
const MAX_OWNERS: usize = 1024;

type Entries = HashMap<(String, String), (Instant, Option<AsciiMetadataValue>)>;

/// Owner the gateway last reported; `None` means it reported none.
pub struct Cached(pub Option<AsciiMetadataValue>);

/// Reported owners keyed by workspace and sandbox name.
#[derive(Clone, Default)]
pub struct OwnerCache(Arc<Mutex<Entries>>);

impl OwnerCache {
    pub fn get(&self, workspace: &str, name: &str) -> Option<Cached> {
        let entries = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let (stored, owner) = entries.get(&key(workspace, name))?;
        (stored.elapsed() < OWNER_TTL).then(|| Cached(owner.clone()))
    }

    pub fn insert(&self, workspace: &str, name: &str, owner: Option<AsciiMetadataValue>) {
        let mut entries = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.len() >= MAX_OWNERS {
            entries.clear();
        }
        entries.insert(key(workspace, name), (Instant::now(), owner));
    }

    pub fn forget(&self, workspace: &str, name: &str) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&key(workspace, name));
    }
}

fn key(workspace: &str, name: &str) -> (String, String) {
    (workspace.to_string(), name.to_string())
}

pub fn with_owner_hint<T>(message: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    request
        .metadata_mut()
        .insert(OWNER_REQUEST_HEADER, AsciiMetadataValue::from_static("1"));
    request
}

pub fn owner_replica<T>(response: &tonic::Response<T>) -> Option<AsciiMetadataValue> {
    response.metadata().get(OWNER_REPLICA_HEADER).cloned()
}

pub fn routed_to<T>(message: T, replica: Option<&AsciiMetadataValue>) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    if let Some(replica) = replica {
        request
            .metadata_mut()
            .insert(ROUTE_REPLICA_HEADER, replica.clone());
    }
    request
}

/// Envoy Gateway answers a replica route with no ready endpoints with
/// `grpc-status: 14` and no message; gateway errors always carry one.
pub fn retry_unrouted(replica: Option<&AsciiMetadataValue>, status: &tonic::Status) -> bool {
    let message = status.message();
    replica.is_some()
        && status.code() == tonic::Code::Unavailable
        && (message.is_empty()
            || message.contains("no healthy upstream")
            || message.contains("connection failure"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_unrouted_unavailable_is_retried() {
        let replica = AsciiMetadataValue::from_static("openshell-1");
        let unavailable = |message| tonic::Status::unavailable(message);
        assert!(retry_unrouted(Some(&replica), &unavailable("")));
        assert!(retry_unrouted(
            Some(&replica),
            &unavailable("no healthy upstream")
        ));
        assert!(!retry_unrouted(None, &unavailable("")));
        assert!(!retry_unrouted(
            Some(&replica),
            &unavailable("supervisor not connected")
        ));
        assert!(!retry_unrouted(
            Some(&replica),
            &tonic::Status::not_found("")
        ));
    }

    #[test]
    fn cache_distinguishes_unknown_from_no_owner() {
        let cache = OwnerCache::default();
        assert!(cache.get("default", "box").is_none());
        cache.insert("default", "box", None);
        assert!(cache.get("default", "box").is_some_and(|c| c.0.is_none()));
        assert!(cache.get("team", "box").is_none());
        cache.forget("default", "box");
        assert!(cache.get("default", "box").is_none());
    }
}
