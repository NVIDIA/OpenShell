// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod secrets;

use miette::{Result, miette};
use openshell_core::proto::{HttpRequestEvaluation, HttpRequestResult, MiddlewareBinding};

pub fn describe() -> Vec<MiddlewareBinding> {
    vec![secrets::describe()]
}

pub fn validate_config(binding_id: &str, config: &prost_types::Struct) -> Result<()> {
    match binding_id {
        secrets::BINDING_ID => secrets::validate_config(config),
        other => Err(miette!(
            "middleware implementation '{other}' is not available in phase 1"
        )),
    }
}

pub fn evaluate_http_request(evaluation: &HttpRequestEvaluation) -> Result<HttpRequestResult> {
    match evaluation.binding_id.as_str() {
        secrets::BINDING_ID => secrets::evaluate_http_request(evaluation),
        other => Err(miette!(
            "middleware implementation '{other}' is not available in phase 1"
        )),
    }
}
