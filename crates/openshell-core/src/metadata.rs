// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Object metadata accessors for Kubernetes-style resources.
//!
//! These traits provide uniform access to `ObjectMeta` fields across all resource types.

use crate::proto::{
    InferenceRoute, ObjectForTest, Provider, Sandbox, SshSession, StoredProviderProfile,
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
