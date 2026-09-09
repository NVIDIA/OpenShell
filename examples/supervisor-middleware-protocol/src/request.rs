// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(crate) fn evaluate(request: HttpRequestEvaluation) -> Result<HttpRequestResult, Status> {
    if request.phase != PHASE as i32 {
        return Err(Status::invalid_argument("expected PRE_CREDENTIALS"));
    }
    // Only this route demonstrates request replacement. Response routes pass through.
    let selected = request
        .target
        .as_ref()
        .is_some_and(|target| target.path == "/request");
    Ok(HttpRequestResult {
        decision: Decision::Allow as i32,
        body: if selected {
            request.body.to_ascii_uppercase()
        } else {
            Vec::new()
        },
        has_body: selected,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replaces_only_the_selected_request() {
        for path in ["/request", "/whole-body"] {
            let result = evaluate(HttpRequestEvaluation {
                phase: PHASE as i32,
                target: Some(openshell_core::proto::HttpRequestTarget {
                    path: path.into(),
                    ..Default::default()
                }),
                body: b"request body".to_vec(),
                ..Default::default()
            })
            .unwrap();
            assert_eq!(result.has_body, path == "/request");
            if result.has_body {
                assert_eq!(result.body, b"REQUEST BODY");
            }
        }
    }
}
