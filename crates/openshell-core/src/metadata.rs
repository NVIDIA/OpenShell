// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Object metadata accessors for Kubernetes-style resources.
//!
//! These traits provide uniform access to `ObjectMeta` fields across all resource types.

use crate::proto::{
    InferenceRoute, ObjectForTest, Provider, Sandbox, ServiceEndpoint, SshSession,
    StoredProviderCredentialRefreshState, StoredProviderProfile,
};
use std::collections::HashMap;

/// Provides access to the object's unique identifier.
pub trait ObjectId {
    fn object_id(&self) -> &str;
}

/// Provides access to the object's human-readable name.
pub trait ObjectName {
    fn object_name(&self) -> &str;
}

/// Provides access to the object's labels (key-value metadata).
pub trait ObjectLabels {
    fn object_labels(&self) -> Option<HashMap<String, String>>;
}

/// Provides mutable access to set the object's resource version from persistence.
pub trait SetResourceVersion {
    fn set_resource_version(&mut self, version: u64);
}

/// Provides read access to the object's current resource version.
pub trait GetResourceVersion {
    fn get_resource_version(&self) -> u64;
}

// Implementations for Sandbox
impl ObjectId for Sandbox {
    fn object_id(&self) -> &str {
        self.metadata.as_ref().map_or("", |m| m.id.as_str())
    }
}

impl ObjectName for Sandbox {
    fn object_name(&self) -> &str {
        self.metadata.as_ref().map_or("", |m| m.name.as_str())
    }
}

impl ObjectLabels for Sandbox {
    fn object_labels(&self) -> Option<HashMap<String, String>> {
        self.metadata.as_ref().map(|m| m.labels.clone())
    }
}

impl SetResourceVersion for Sandbox {
    fn set_resource_version(&mut self, version: u64) {
        if let Some(meta) = self.metadata.as_mut() {
            meta.resource_version = version;
        }
    }
}

impl GetResourceVersion for Sandbox {
    fn get_resource_version(&self) -> u64 {
        self.metadata.as_ref().map_or(0, |m| m.resource_version)
    }
}

// Implementations for Provider
impl ObjectId for Provider {
    fn object_id(&self) -> &str {
        self.metadata.as_ref().map_or("", |m| m.id.as_str())
    }
}

impl ObjectName for Provider {
    fn object_name(&self) -> &str {
        self.metadata.as_ref().map_or("", |m| m.name.as_str())
    }
}

impl ObjectLabels for Provider {
    fn object_labels(&self) -> Option<HashMap<String, String>> {
        self.metadata.as_ref().map(|m| m.labels.clone())
    }
}

impl SetResourceVersion for Provider {
    fn set_resource_version(&mut self, version: u64) {
        if let Some(meta) = self.metadata.as_mut() {
            meta.resource_version = version;
        }
    }
}

impl GetResourceVersion for Provider {
    fn get_resource_version(&self) -> u64 {
        self.metadata.as_ref().map_or(0, |m| m.resource_version)
    }
}

// Implementations for StoredProviderProfile
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

// Implementations for StoredProviderCredentialRefreshState
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

// Implementations for SshSession
impl ObjectId for SshSession {
    fn object_id(&self) -> &str {
        self.metadata.as_ref().map_or("", |m| m.id.as_str())
    }
}

impl ObjectName for SshSession {
    fn object_name(&self) -> &str {
        self.metadata.as_ref().map_or("", |m| m.name.as_str())
    }
}

impl ObjectLabels for SshSession {
    fn object_labels(&self) -> Option<HashMap<String, String>> {
        self.metadata.as_ref().map(|m| m.labels.clone())
    }
}

impl SetResourceVersion for SshSession {
    fn set_resource_version(&mut self, version: u64) {
        if let Some(meta) = self.metadata.as_mut() {
            meta.resource_version = version;
        }
    }
}

impl GetResourceVersion for SshSession {
    fn get_resource_version(&self) -> u64 {
        self.metadata.as_ref().map_or(0, |m| m.resource_version)
    }
}

// Implementations for ServiceEndpoint
impl ObjectId for ServiceEndpoint {
    fn object_id(&self) -> &str {
        self.metadata.as_ref().map_or("", |m| m.id.as_str())
    }
}

impl ObjectName for ServiceEndpoint {
    fn object_name(&self) -> &str {
        self.metadata.as_ref().map_or("", |m| m.name.as_str())
    }
}

impl ObjectLabels for ServiceEndpoint {
    fn object_labels(&self) -> Option<HashMap<String, String>> {
        self.metadata.as_ref().map(|m| m.labels.clone())
    }
}

impl SetResourceVersion for ServiceEndpoint {
    fn set_resource_version(&mut self, version: u64) {
        if let Some(meta) = self.metadata.as_mut() {
            meta.resource_version = version;
        }
    }
}

impl GetResourceVersion for ServiceEndpoint {
    fn get_resource_version(&self) -> u64 {
        self.metadata.as_ref().map_or(0, |m| m.resource_version)
    }
}

// Implementations for InferenceRoute
impl ObjectId for InferenceRoute {
    fn object_id(&self) -> &str {
        self.metadata.as_ref().map_or("", |m| m.id.as_str())
    }
}

impl ObjectName for InferenceRoute {
    fn object_name(&self) -> &str {
        self.metadata.as_ref().map_or("", |m| m.name.as_str())
    }
}

impl ObjectLabels for InferenceRoute {
    fn object_labels(&self) -> Option<HashMap<String, String>> {
        self.metadata.as_ref().map(|m| m.labels.clone())
    }
}

impl SetResourceVersion for InferenceRoute {
    fn set_resource_version(&mut self, version: u64) {
        if let Some(meta) = self.metadata.as_mut() {
            meta.resource_version = version;
        }
    }
}

impl GetResourceVersion for InferenceRoute {
    fn get_resource_version(&self) -> u64 {
        self.metadata.as_ref().map_or(0, |m| m.resource_version)
    }
}

// Implementations for ObjectForTest (test-only proto type)
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

impl ObjectLabels for ObjectForTest {
    fn object_labels(&self) -> Option<HashMap<String, String>> {
        None
    }
}

impl SetResourceVersion for ObjectForTest {
    fn set_resource_version(&mut self, _version: u64) {
        // ObjectForTest doesn't have metadata, so this is a no-op
    }
}

impl GetResourceVersion for ObjectForTest {
    fn get_resource_version(&self) -> u64 {
        // ObjectForTest doesn't have metadata
        0
    }
}
