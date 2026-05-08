// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! GraphQL-over-HTTP L7 inspection.

use crate::l7::provider::{BodyLength, L7Provider, L7Request};
use apollo_parser::Parser;
use apollo_parser::cst;
use miette::{IntoDiagnostic, Result, miette};
use serde::Serialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

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

pub struct GraphqlHttpRequest {
    pub request: L7Request,
    pub info: GraphqlRequestInfo,
}

pub async fn parse_graphql_http_request<C: AsyncRead + AsyncWrite + Unpin + Send>(
    client: &mut C,
    max_body_bytes: usize,
    canonicalize_options: crate::l7::path::CanonicalizeOptions,
) -> Result<Option<GraphqlHttpRequest>> {
    let provider = crate::l7::rest::RestProvider::with_options(canonicalize_options);
    let Some(mut request) = provider.parse_request(client).await? else {
        return Ok(None);
    };

    let info = inspect_graphql_request(client, &mut request, max_body_bytes).await?;

    Ok(Some(GraphqlHttpRequest { request, info }))
}

pub(crate) async fn inspect_graphql_request<C: AsyncRead + Unpin>(
    client: &mut C,
    request: &mut L7Request,
    max_body_bytes: usize,
) -> Result<GraphqlRequestInfo> {
    let header_str = header_str(request)?;
    reject_unsupported_headers(header_str)?;
    let body = read_body_for_inspection(client, request, max_body_bytes).await?;
    Ok(classify_request(request, &body))
}

pub fn classify_request(request: &L7Request, body: &[u8]) -> GraphqlRequestInfo {
    match classify_request_inner(request, body) {
        Ok(operations) => GraphqlRequestInfo {
            operations,
            error: None,
        },
        Err(err) => GraphqlRequestInfo {
            operations: Vec::new(),
            error: Some(err),
        },
    }
}

fn classify_request_inner(
    request: &L7Request,
    body: &[u8],
) -> std::result::Result<Vec<GraphqlOperationInfo>, String> {
    match request.action.to_ascii_uppercase().as_str() {
        "GET" => classify_get(request),
        "POST" => classify_post(body),
        method => Err(format!("unsupported GraphQL HTTP method {method}")),
    }
}

fn classify_get(request: &L7Request) -> std::result::Result<Vec<GraphqlOperationInfo>, String> {
    let query = unique_query_value(&request.query_params, "query")?;
    let operation_name = unique_query_value(&request.query_params, "operationName")?;
    let extensions = unique_query_value(&request.query_params, "extensions")?
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok());
    let id = unique_persisted_query_id(&request.query_params)?;

    classify_envelope(
        query.as_deref(),
        operation_name.as_deref(),
        extensions.as_ref(),
        id,
    )
}

fn classify_post(body: &[u8]) -> std::result::Result<Vec<GraphqlOperationInfo>, String> {
    if body.is_empty() {
        return Err("GraphQL POST body is empty".to_string());
    }
    let value: Value = serde_json::from_slice(body)
        .map_err(|err| format!("GraphQL request body is not valid JSON: {err}"))?;

    match value {
        Value::Array(items) => {
            if items.is_empty() {
                return Err("GraphQL batch request is empty".to_string());
            }
            let mut operations = Vec::new();
            for item in items {
                operations.extend(classify_json_envelope(&item)?);
            }
            Ok(operations)
        }
        Value::Object(_) => classify_json_envelope(&value),
        _ => Err("GraphQL JSON envelope must be an object or array".to_string()),
    }
}

fn classify_json_envelope(value: &Value) -> std::result::Result<Vec<GraphqlOperationInfo>, String> {
    let obj = value
        .as_object()
        .ok_or_else(|| "GraphQL batch item must be an object".to_string())?;
    let query = obj.get("query").and_then(Value::as_str);
    let operation_name = obj.get("operationName").and_then(Value::as_str);
    let extensions = obj.get("extensions");
    let id = obj
        .get("id")
        .or_else(|| obj.get("documentId"))
        .or_else(|| obj.get("queryId"))
        .and_then(Value::as_str)
        .map(ToString::to_string);

    classify_envelope(query, operation_name, extensions, id)
}

fn classify_envelope(
    query: Option<&str>,
    operation_name: Option<&str>,
    extensions: Option<&Value>,
    persisted_id: Option<String>,
) -> std::result::Result<Vec<GraphqlOperationInfo>, String> {
    let persisted_hash = persisted_query_hash(extensions);
    let query = query.filter(|q| !q.trim().is_empty());

    if let Some(query) = query {
        let mut operation = classify_document(query, operation_name)?;
        if let Some(hash) = persisted_hash {
            operation.persisted_query = true;
            operation.persisted_query_hash = Some(hash);
        }
        if let Some(id) = persisted_id {
            operation.persisted_query = true;
            operation.persisted_query_id = Some(id);
        }
        return Ok(vec![operation]);
    }

    if persisted_hash.is_some() || persisted_id.is_some() {
        return Ok(vec![GraphqlOperationInfo {
            operation_type: String::new(),
            operation_name: operation_name.map(ToString::to_string),
            fields: Vec::new(),
            persisted_query: true,
            persisted_query_hash: persisted_hash,
            persisted_query_id: persisted_id,
        }]);
    }

    Err("GraphQL request has no query document or persisted query identifier".to_string())
}

fn classify_document(
    query: &str,
    operation_name: Option<&str>,
) -> std::result::Result<GraphqlOperationInfo, String> {
    let parser = Parser::new(query).recursion_limit(128).token_limit(20_000);
    let cst = parser.parse();
    let mut parse_errors = cst.errors();
    if let Some(err) = parse_errors.next() {
        return Err(format!("GraphQL document parse error: {err}"));
    }

    let document = cst.document();
    let mut operations = Vec::new();
    let mut fragments = HashMap::new();

    for definition in document.definitions() {
        match definition {
            cst::Definition::OperationDefinition(operation) => operations.push(operation),
            cst::Definition::FragmentDefinition(fragment) => {
                if let Some(name) = fragment.fragment_name().and_then(|n| n.name()) {
                    fragments.insert(name.text().to_string(), fragment);
                }
            }
            _ => {}
        }
    }

    if operations.is_empty() {
        return Err("GraphQL document contains no executable operation".to_string());
    }

    let selected = if let Some(expected_name) = operation_name.filter(|name| !name.is_empty()) {
        operations
            .into_iter()
            .find(|op| {
                op.name()
                    .is_some_and(|name| name.text().as_ref() == expected_name)
            })
            .ok_or_else(|| format!("GraphQL operationName {expected_name:?} was not found"))?
    } else if operations.len() == 1 {
        operations.remove(0)
    } else {
        return Err("GraphQL document has multiple operations but no operationName".to_string());
    };

    let operation_type = operation_type(&selected);
    let operation_name = selected.name().map(|name| name.text().to_string());
    let selection_set = selected
        .selection_set()
        .ok_or_else(|| "GraphQL operation has no selection set".to_string())?;
    let mut fields = HashSet::new();
    let mut visited_fragments = HashSet::new();
    collect_root_fields(
        selection_set,
        &fragments,
        &mut visited_fragments,
        &mut fields,
    );
    let mut fields: Vec<_> = fields.into_iter().collect();
    fields.sort();

    Ok(GraphqlOperationInfo {
        operation_type,
        operation_name,
        fields,
        persisted_query: false,
        persisted_query_hash: None,
        persisted_query_id: None,
    })
}

fn operation_type(operation: &cst::OperationDefinition) -> String {
    let Some(operation_type) = operation.operation_type() else {
        return "query".to_string();
    };
    if operation_type.mutation_token().is_some() {
        "mutation".to_string()
    } else if operation_type.subscription_token().is_some() {
        "subscription".to_string()
    } else {
        "query".to_string()
    }
}

fn collect_root_fields(
    selection_set: cst::SelectionSet,
    fragments: &HashMap<String, cst::FragmentDefinition>,
    visited_fragments: &mut HashSet<String>,
    fields: &mut HashSet<String>,
) {
    for selection in selection_set.selections() {
        match selection {
            cst::Selection::Field(field) => {
                if let Some(name) = field.name() {
                    fields.insert(name.text().to_string());
                }
            }
            cst::Selection::InlineFragment(fragment) => {
                if let Some(selection_set) = fragment.selection_set() {
                    collect_root_fields(selection_set, fragments, visited_fragments, fields);
                }
            }
            cst::Selection::FragmentSpread(spread) => {
                let Some(name) = spread.fragment_name().and_then(|n| n.name()) else {
                    continue;
                };
                let name = name.text().to_string();
                if !visited_fragments.insert(name.clone()) {
                    continue;
                }
                if let Some(fragment) = fragments.get(&name)
                    && let Some(selection_set) = fragment.selection_set()
                {
                    collect_root_fields(selection_set, fragments, visited_fragments, fields);
                }
            }
        }
    }
}

fn persisted_query_hash(extensions: Option<&Value>) -> Option<String> {
    extensions?
        .get("persistedQuery")?
        .get("sha256Hash")?
        .as_str()
        .filter(|hash| !hash.is_empty())
        .map(ToString::to_string)
}

fn unique_query_value(
    params: &HashMap<String, Vec<String>>,
    key: &str,
) -> std::result::Result<Option<String>, String> {
    let Some(values) = params.get(key) else {
        return Ok(None);
    };
    if values.len() > 1 {
        return Err(format!(
            "GraphQL GET parameter {key:?} must not appear more than once"
        ));
    }
    Ok(values.first().filter(|value| !value.is_empty()).cloned())
}

fn unique_persisted_query_id(
    params: &HashMap<String, Vec<String>>,
) -> std::result::Result<Option<String>, String> {
    let mut selected: Option<(String, String)> = None;
    for key in ["id", "documentId", "queryId"] {
        let Some(value) = unique_query_value(params, key)? else {
            continue;
        };
        if let Some((existing_key, _)) = selected {
            return Err(format!(
                "GraphQL GET persisted-query id parameters {existing_key:?} and {key:?} must not be combined"
            ));
        }
        selected = Some((key.to_string(), value));
    }
    Ok(selected.map(|(_, value)| value))
}

async fn read_body_for_inspection<C: AsyncRead + Unpin>(
    client: &mut C,
    request: &mut L7Request,
    max_body_bytes: usize,
) -> Result<Vec<u8>> {
    let header_end = request
        .raw_header
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(request.raw_header.len(), |p| p + 4);
    let overflow = request.raw_header[header_end..].to_vec();

    match request.body_length {
        BodyLength::None => Ok(Vec::new()),
        BodyLength::ContentLength(len) => {
            let len = usize::try_from(len)
                .map_err(|_| miette!("GraphQL request body length exceeds platform limit"))?;
            if len > max_body_bytes {
                return Err(miette!(
                    "GraphQL request body exceeds {max_body_bytes} byte inspection limit"
                ));
            }
            if overflow.len() > len {
                return Err(miette!(
                    "GraphQL request contains more body bytes than Content-Length"
                ));
            }
            let remaining = len - overflow.len();
            let mut body = overflow;
            if remaining > 0 {
                let start = body.len();
                body.resize(len, 0);
                client
                    .read_exact(&mut body[start..])
                    .await
                    .into_diagnostic()?;
            }
            request.raw_header.truncate(header_end);
            request.raw_header.extend_from_slice(&body);
            Ok(body)
        }
        BodyLength::Chunked => {
            let body = read_chunked_body_for_inspection(
                client,
                request,
                header_end,
                overflow,
                max_body_bytes,
            )
            .await?;
            normalize_chunked_request_to_content_length(request, header_end, &body)?;
            Ok(body)
        }
    }
}

fn normalize_chunked_request_to_content_length(
    request: &mut L7Request,
    header_end: usize,
    body: &[u8],
) -> Result<()> {
    let header_str = std::str::from_utf8(&request.raw_header[..header_end])
        .map_err(|_| miette!("GraphQL HTTP headers contain invalid UTF-8"))?;
    let header_str = header_str
        .strip_suffix("\r\n\r\n")
        .ok_or_else(|| miette!("GraphQL HTTP headers missing terminator"))?;

    let mut normalized = Vec::with_capacity(header_str.len() + body.len() + 32);
    for (idx, line) in header_str.split("\r\n").enumerate() {
        if idx > 0 {
            let name = line
                .split_once(':')
                .map(|(name, _)| name.trim().to_ascii_lowercase());
            if matches!(
                name.as_deref(),
                Some("transfer-encoding" | "content-length" | "trailer")
            ) {
                continue;
            }
        }
        normalized.extend_from_slice(line.as_bytes());
        normalized.extend_from_slice(b"\r\n");
    }
    normalized.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    normalized.extend_from_slice(body);

    request.raw_header = normalized;
    request.body_length = BodyLength::ContentLength(body.len() as u64);
    Ok(())
}

async fn read_chunked_body_for_inspection<C: AsyncRead + Unpin>(
    client: &mut C,
    request: &mut L7Request,
    header_end: usize,
    overflow: Vec<u8>,
    max_body_bytes: usize,
) -> Result<Vec<u8>> {
    let mut raw = overflow;
    let mut decoded = Vec::new();
    let mut pos = 0usize;

    loop {
        let size_line_end = loop {
            if let Some(end) = find_crlf(&raw, pos) {
                break end;
            }
            read_more(client, &mut raw, max_body_bytes).await?;
        };
        let size_line = std::str::from_utf8(&raw[pos..size_line_end])
            .into_diagnostic()
            .map_err(|_| miette!("Invalid UTF-8 in GraphQL chunk-size line"))?;
        let size_token = size_line
            .split(';')
            .next()
            .map(str::trim)
            .unwrap_or_default();
        let chunk_size = usize::from_str_radix(size_token, 16)
            .into_diagnostic()
            .map_err(|_| miette!("Invalid GraphQL chunk size token: {size_token:?}"))?;
        pos = size_line_end + 2;

        if decoded.len().saturating_add(chunk_size) > max_body_bytes {
            return Err(miette!(
                "GraphQL request body exceeds {max_body_bytes} byte inspection limit"
            ));
        }

        if chunk_size == 0 {
            loop {
                let trailer_end = loop {
                    if let Some(end) = find_crlf(&raw, pos) {
                        break end;
                    }
                    read_more(client, &mut raw, max_body_bytes).await?;
                };
                let trailer_line = &raw[pos..trailer_end];
                pos = trailer_end + 2;
                if trailer_line.is_empty() {
                    request.raw_header.truncate(header_end);
                    request.raw_header.extend_from_slice(&raw[..pos]);
                    return Ok(decoded);
                }
            }
        }

        let chunk_end = pos
            .checked_add(chunk_size)
            .ok_or_else(|| miette!("GraphQL chunk size overflow"))?;
        let chunk_with_crlf_end = chunk_end
            .checked_add(2)
            .ok_or_else(|| miette!("GraphQL chunk size overflow"))?;
        while raw.len() < chunk_with_crlf_end {
            read_more(client, &mut raw, max_body_bytes).await?;
        }
        decoded.extend_from_slice(&raw[pos..chunk_end]);
        if raw.get(chunk_end..chunk_with_crlf_end) != Some(&b"\r\n"[..]) {
            return Err(miette!("GraphQL chunk payload missing terminating CRLF"));
        }
        pos = chunk_with_crlf_end;
    }
}

async fn read_more<C: AsyncRead + Unpin>(
    client: &mut C,
    raw: &mut Vec<u8>,
    max_body_bytes: usize,
) -> Result<()> {
    if raw.len() > max_body_bytes.saturating_mul(2).max(max_body_bytes) {
        return Err(miette!(
            "GraphQL chunked request body exceeds inspection framing limit"
        ));
    }
    let mut buf = [0u8; 8192];
    let n = client.read(&mut buf).await.into_diagnostic()?;
    if n == 0 {
        return Err(miette!("GraphQL chunked body ended before terminator"));
    }
    raw.extend_from_slice(&buf[..n]);
    Ok(())
}

fn find_crlf(buf: &[u8], start: usize) -> Option<usize> {
    buf.get(start..)?
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|p| start + p)
}

fn header_str(request: &L7Request) -> Result<&str> {
    let header_end = request
        .raw_header
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(request.raw_header.len(), |p| p + 4);
    std::str::from_utf8(&request.raw_header[..header_end])
        .map_err(|_| miette!("GraphQL HTTP headers contain invalid UTF-8"))
}

fn reject_unsupported_headers(headers: &str) -> Result<()> {
    for line in headers.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-encoding:") {
            let encoding = lower.split_once(':').map_or("", |(_, v)| v.trim());
            if !encoding.is_empty() && encoding != "identity" {
                return Err(miette!(
                    "GraphQL request content-encoding {encoding:?} is not supported"
                ));
            }
        }
        if lower.starts_with("content-type:") {
            let content_type = lower.split_once(':').map_or("", |(_, v)| v.trim());
            if content_type.starts_with("multipart/") {
                return Err(miette!("GraphQL multipart requests are not supported"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str, target: &str) -> L7Request {
        L7Request {
            action: method.to_string(),
            target: target.to_string(),
            query_params: crate::l7::rest::parse_target_query(target).unwrap().1,
            raw_header: format!("{method} {target} HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .into_bytes(),
            body_length: BodyLength::None,
        }
    }

    #[test]
    fn classifies_simple_query() {
        let req = request("POST", "/graphql");
        let info = classify_request(&req, br#"{"query":"query Viewer { viewer { login } }"}"#);
        assert_eq!(info.error, None);
        assert_eq!(info.operations[0].operation_type, "query");
        assert_eq!(info.operations[0].fields, vec!["viewer"]);
    }

    #[test]
    fn classifies_mutation_field_not_alias() {
        let req = request("POST", "/graphql");
        let info = classify_request(
            &req,
            br#"{"query":"mutation M { safeAlias: volumeDelete(volumeId:\"x\") { id } }","operationName":"M"}"#,
        );
        assert_eq!(info.error, None);
        assert_eq!(info.operations[0].operation_type, "mutation");
        assert_eq!(info.operations[0].operation_name.as_deref(), Some("M"));
        assert_eq!(info.operations[0].fields, vec!["volumeDelete"]);
    }

    #[test]
    fn expands_root_fragments() {
        let req = request("POST", "/graphql");
        let info = classify_request(
            &req,
            br#"{"query":"query Q { ...RootFields } fragment RootFields on Query { viewer repository(owner:\"o\", name:\"r\") { id } }"}"#,
        );
        assert_eq!(info.error, None);
        assert_eq!(info.operations[0].fields, vec!["repository", "viewer"]);
    }

    #[test]
    fn multiple_operations_without_name_errors() {
        let req = request("POST", "/graphql");
        let info = classify_request(
            &req,
            br#"{"query":"query A { viewer { login } } query B { rateLimit { limit } }"}"#,
        );
        assert!(info.error.unwrap().contains("multiple operations"));
    }

    #[test]
    fn detects_hash_only_apollo_persisted_query() {
        let req = request("POST", "/graphql");
        let info = classify_request(
            &req,
            br#"{"operationName":"Viewer","extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc123"}}}"#,
        );
        assert_eq!(info.error, None);
        let op = &info.operations[0];
        assert!(op.persisted_query);
        assert_eq!(op.operation_name.as_deref(), Some("Viewer"));
        assert_eq!(op.persisted_query_hash.as_deref(), Some("abc123"));
    }

    #[test]
    fn graphql_get_rejects_duplicate_query_parameter() {
        let req = request(
            "GET",
            "/graphql?query=query+Viewer+%7B+viewer+%7B+login+%7D+%7D&query=mutation+Delete+%7B+volumeDelete(volumeId%3A%22x%22)+%7B+id+%7D+%7D",
        );
        let info = classify_request(&req, b"");
        assert!(
            info.error
                .as_deref()
                .is_some_and(|err| err.contains("must not appear more than once")),
            "expected duplicate control parameter error, got {info:?}"
        );
    }

    #[test]
    fn graphql_get_rejects_ambiguous_persisted_query_ids() {
        let req = request("GET", "/graphql?id=one&queryId=two");
        let info = classify_request(&req, b"");
        assert!(
            info.error
                .as_deref()
                .is_some_and(|err| err.contains("must not be combined")),
            "expected ambiguous persisted-query id error, got {info:?}"
        );
    }

    #[tokio::test]
    async fn chunked_graphql_post_is_normalized_after_inspection() {
        let body = br#"{"query":"query Viewer { viewer { login } }"}"#;
        let mut raw_header =
            b"POST /graphql HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sig\r\nX-Test: yes\r\n\r\n"
                .to_vec();
        raw_header.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
        raw_header.extend_from_slice(body);
        raw_header.extend_from_slice(b"\r\n0\r\nX-Sig: ignored\r\n\r\n");

        let mut req = L7Request {
            action: "POST".to_string(),
            target: "/graphql".to_string(),
            query_params: HashMap::new(),
            raw_header,
            body_length: BodyLength::Chunked,
        };
        let mut client = tokio::io::empty();

        let info = inspect_graphql_request(&mut client, &mut req, DEFAULT_MAX_BODY_BYTES)
            .await
            .expect("chunked body should inspect");

        assert_eq!(info.error, None);
        assert!(matches!(
            req.body_length,
            BodyLength::ContentLength(len) if len == body.len() as u64
        ));
        let forwarded = String::from_utf8_lossy(&req.raw_header);
        assert!(forwarded.contains(&format!("Content-Length: {}", body.len())));
        assert!(forwarded.contains("X-Test: yes\r\n"));
        assert!(!forwarded.to_ascii_lowercase().contains("transfer-encoding"));
        assert!(!forwarded.to_ascii_lowercase().contains("trailer:"));
        assert!(req.raw_header.ends_with(body));
    }

    #[tokio::test]
    async fn absolute_form_chunked_graphql_post_classifies_after_inspection() {
        let body = br#"{"query":"query Viewer { viewer { login } }"}"#;
        let mut raw_header =
            b"POST http://example.com/graphql HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                .to_vec();
        raw_header.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
        raw_header.extend_from_slice(body);
        raw_header.extend_from_slice(b"\r\n0\r\n\r\n");

        let mut req = L7Request {
            action: "POST".to_string(),
            target: "/graphql".to_string(),
            query_params: HashMap::new(),
            raw_header,
            body_length: BodyLength::Chunked,
        };
        let mut client = tokio::io::empty();

        let info = inspect_graphql_request(&mut client, &mut req, DEFAULT_MAX_BODY_BYTES)
            .await
            .expect("absolute-form chunked body should inspect");

        assert_eq!(info.error, None);
        assert_eq!(info.operations[0].operation_type, "query");
        assert_eq!(info.operations[0].fields, vec!["viewer"]);
    }

    #[tokio::test]
    async fn absolute_form_chunked_graphql_post_is_allowed_by_field_policy() {
        let body = br#"{"query":"query Viewer { viewer { login } }"}"#;
        let mut raw_header =
            b"POST http://host.openshell.internal:8080/graphql HTTP/1.1\r\nHost: host.openshell.internal:8080\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                .to_vec();
        raw_header.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
        raw_header.extend_from_slice(body);
        raw_header.extend_from_slice(b"\r\n0\r\n\r\n");

        let mut req = L7Request {
            action: "POST".to_string(),
            target: "/graphql".to_string(),
            query_params: HashMap::new(),
            raw_header,
            body_length: BodyLength::Chunked,
        };
        let mut client = tokio::io::empty();
        let info = inspect_graphql_request(&mut client, &mut req, DEFAULT_MAX_BODY_BYTES)
            .await
            .expect("chunked body should inspect");

        let data = r"
network_policies:
  test_graphql_l7:
    name: test_graphql_l7
    endpoints:
      - host: host.openshell.internal
        port: 8080
        protocol: graphql
        enforcement: enforce
        persisted_queries: allow_registered
        graphql_persisted_queries:
          abc123:
            operation_type: query
            operation_name: Viewer
            fields: [viewer]
        rules:
          - allow:
              operation_type: query
              fields: [viewer]
          - allow:
              operation_type: mutation
              fields: [createIssue]
        deny_rules:
          - operation_type: mutation
            fields: [deleteRepository]
    binaries:
      - { path: /usr/bin/python3 }
";
        let engine = crate::opa::OpaEngine::from_strings(
            include_str!("../../data/sandbox-policy.rego"),
            data,
        )
        .expect("policy should load");
        let ctx = crate::l7::relay::L7EvalContext {
            host: "host.openshell.internal".to_string(),
            port: 8080,
            policy_name: "test_graphql_l7".to_string(),
            binary_path: "/usr/bin/python3".to_string(),
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
            secret_resolver: None,
        };
        let request_info = crate::l7::L7RequestInfo {
            action: req.action,
            target: req.target,
            query_params: req.query_params,
            graphql: Some(info),
        };

        let tunnel_engine = engine
            .clone_engine_for_tunnel(engine.current_generation())
            .expect("tunnel engine should clone");
        let (allowed, reason) =
            crate::l7::relay::evaluate_l7_request(&tunnel_engine, &ctx, &request_info)
                .expect("evaluation should complete");

        assert!(allowed, "expected query to be allowed, got {reason}");
    }
}
