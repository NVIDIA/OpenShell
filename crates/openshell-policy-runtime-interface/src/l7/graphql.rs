// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::Serialize;

pub const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GraphqlRequestInfo {
    pub operations: Vec<GraphqlOperationInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GraphqlOperationInfo {
    pub operation_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_name: Option<String>,
    pub fields: Vec<String>,
    pub persisted_query: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persisted_query_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persisted_query_id: Option<String>,
}
