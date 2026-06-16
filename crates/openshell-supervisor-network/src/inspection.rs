// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Minimal inspection primitives for runtime-boundary experimentation.
//!
//! This module intentionally does not introduce control-plane configuration or
//! plugin registration. It provides a small decision vocabulary that the
//! supervisor network path can invoke when a caller wires in an inspector.

use crate::l7::provider::L7Request;
use crate::l7::relay::L7EvalContext;
use miette::{Result, miette};
use serde_json::Value as Json;

#[derive(Debug, Clone, PartialEq)]
pub enum InspectionTarget {
    LlmRequest {
        provider: String,
        request: Json,
    },
    ToolRequest {
        tool_name: String,
        input: Json,
    },
    HttpRequest {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InspectionContext {
    pub sandbox_id: Option<String>,
    pub scope_id: Option<String>,
    pub provider: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InspectionDecision {
    Allow,
    Deny {
        reason: String,
        findings: Vec<Finding>,
    },
    Mutate {
        target: InspectionTarget,
        findings: Vec<Finding>,
    },
}

pub trait Inspector: Send + Sync {
    fn inspect(
        &self,
        target: InspectionTarget,
        ctx: &InspectionContext,
    ) -> Result<InspectionDecision>;
}

#[allow(dead_code)]
pub(crate) enum HttpInspectionOutcome {
    Allow,
    Deny {
        reason: String,
        findings: Vec<Finding>,
    },
    Mutate {
        findings: Vec<Finding>,
    },
}

pub(crate) fn inspect_http_request(
    req: &mut L7Request,
    ctx: &L7EvalContext,
) -> Result<HttpInspectionOutcome> {
    let Some(inspector) = ctx.request_inspector.as_ref() else {
        return Ok(HttpInspectionOutcome::Allow);
    };

    let headers = parse_headers(&req.raw_header)?;
    let decision = inspector.inspect(
        InspectionTarget::HttpRequest {
            method: req.action.clone(),
            path: req.target.clone(),
            headers,
            body: Vec::new(),
        },
        &InspectionContext::default(),
    )?;

    match decision {
        InspectionDecision::Allow => Ok(HttpInspectionOutcome::Allow),
        InspectionDecision::Deny { reason, findings } => {
            Ok(HttpInspectionOutcome::Deny { reason, findings })
        }
        InspectionDecision::Mutate { target, findings } => match target {
            InspectionTarget::HttpRequest {
                method,
                path,
                headers,
                ..
            } => {
                if method != req.action {
                    return Err(miette!(
                        "http inspection mutation attempted to rewrite method after policy evaluation"
                    ));
                }
                if path != req.target {
                    return Err(miette!(
                        "http inspection mutation attempted to rewrite path after policy evaluation"
                    ));
                }
                rewrite_headers(req, &headers)?;
                Ok(HttpInspectionOutcome::Mutate { findings })
            }
            other => Err(miette!(
                "http inspection returned non-http target for mutation: {other:?}"
            )),
        },
    }
}

fn header_end(raw: &[u8]) -> Result<usize> {
    raw.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .ok_or_else(|| miette!("http request headers missing CRLF terminator"))
}

fn parse_request_line(raw: &[u8]) -> Result<(String, String, String)> {
    let eol = raw
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| miette!("http request line missing CRLF"))?;
    let line = std::str::from_utf8(&raw[..eol]).map_err(|error| miette!(error.to_string()))?;
    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| miette!("missing http method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| miette!("missing http target"))?
        .to_string();
    let version = parts
        .next()
        .ok_or_else(|| miette!("missing http version"))?
        .to_string();
    Ok((method, path, version))
}

fn parse_headers(raw: &[u8]) -> Result<Vec<(String, String)>> {
    let header_end = header_end(raw)?;
    let header_str =
        std::str::from_utf8(&raw[..header_end]).map_err(|error| miette!(error.to_string()))?;
    let mut headers = Vec::new();
    for line in header_str.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(miette!("malformed http header line"));
        };
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    Ok(headers)
}

fn rewrite_headers(req: &mut L7Request, headers: &[(String, String)]) -> Result<()> {
    let header_end = header_end(&req.raw_header)?;
    let (_, _, version) = parse_request_line(&req.raw_header)?;
    let overflow = req.raw_header[header_end..].to_vec();

    let mut raw = format!("{} {} {}\r\n", req.action, req.target, version).into_bytes();
    for (name, value) in headers {
        raw.extend_from_slice(name.as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(value.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(&overflow);
    req.raw_header = raw;
    Ok(())
}
