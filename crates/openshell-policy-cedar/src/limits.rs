// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Input bounds that keep Cedar within a known stack budget.
//!
//! Cedar's parser, its policy-to-JSON conversion, this crate's analysis, and
//! Cedar's evaluator recurse once per expression level, and the delimited
//! `like` matcher recurses once per character of its text and pattern. Only
//! Cedar's validator and expression evaluator check the remaining stack, so
//! deep input could otherwise abort the process on a 2 MiB Tokio worker.
//! Policy text is therefore scanned, without recursion, before it is parsed:
//! [`scan`] bounds its bracket nesting and the depth of each policy's
//! expressions, and every parse, analysis, and evaluation runs on a stack
//! sized from that bound. Request strings are capped by
//! [`MAX_REQUEST_FIELD_BYTES`] so the `like` recursion is bounded too.
//!
//! The stack costs below are about twice the peak stack use measured at the
//! bounds, for unoptimized and optimized builds separately: an unoptimized
//! build, as tests run, uses five to twelve times the stack per level.
//! Measured per level, unoptimized / optimized: 62 / 16 KiB per bracket
//! while parsing; 20 / 3 KiB per expression level while loading; 53 / 4.3
//! KiB per expression level while evaluating; 200 / 96 bytes per character
//! of a delimited `like`.

use crate::{CedarEngineError, HttpRequestInput, NetworkConnectRequest};

/// Longest Cedar policy source accepted, in bytes: the gateway's limit on a
/// whole serialized sandbox policy.
pub const MAX_POLICY_SOURCE_BYTES: usize = 262_144;

/// Deepest nesting of `(`, `[`, and `{` accepted in Cedar policy text.
///
/// Hand-written policies nest a few levels; each level costs Cedar's parser
/// tens of KiB of stack in an unoptimized build.
pub const MAX_POLICY_NESTING: usize = 64;

/// Largest expression depth bound accepted for one Cedar policy.
///
/// The bound counts the operators (`&&`, `||`, `==`, `.`, `if`, `like`, ...)
/// and brackets one policy's expressions can nest: operators of one bracket
/// level, plus those of the deepest bracket within it. A long chain such as
/// 1,000 `||` alternatives exceeds it; a set literal with `.contains` or
/// several policies say the same thing without nesting.
pub const MAX_POLICY_EXPRESSION_DEPTH: usize = 1024;

/// Longest request-derived string Cedar evaluates, in bytes.
///
/// A request with a longer host, binary path, method, path, query key or
/// value, SQL command, JSON-RPC method, MCP tool, or GraphQL operation name,
/// type, or field is denied with
/// [`CedarEngineError::RequestFieldTooLong`]. The proxy reads at most 16 KiB
/// of HTTP request head, so the method, path, and query never reach this
/// cap; binary paths are bounded by `PATH_MAX` (4 KiB) and hosts by DNS (253
/// bytes); JSON-RPC methods, MCP tool names, and GraphQL names are
/// identifiers well under 1 KiB in practice.
pub const MAX_REQUEST_FIELD_BYTES: usize = 16 * 1024;

/// Stack every load or evaluation needs regardless of its input.
const BASE_STACK: usize = by_build(1024 * 1024, 256 * 1024);

/// Stack per bracket level while parsing.
const PARSE_STACK_PER_NESTING: usize = by_build(96 * 1024, 32 * 1024);

/// Stack per unit of expression depth bound while loading: parsing,
/// validation, conversion to JSON, analysis, and dropping.
const LOAD_STACK_PER_DEPTH: usize = by_build(48 * 1024, 8 * 1024);

/// Stack per unit of expression depth bound while evaluating.
const EVAL_STACK_PER_DEPTH: usize = by_build(96 * 1024, 8 * 1024);

/// Stack per character of text and pattern in a delimited `like`.
const EVAL_STACK_PER_LIKE_CHAR: usize = by_build(384, 192);

/// Selects the stack cost of an unoptimized build (with debug assertions,
/// as the dev and test profiles build) or an optimized one.
const fn by_build(unoptimized: usize, optimized: usize) -> usize {
    if cfg!(debug_assertions) {
        unoptimized
    } else {
        optimized
    }
}

/// The shape of Cedar policy text that sizes the stack it needs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SourceShape {
    /// The deepest bracket nesting.
    pub(crate) nesting: usize,
    /// The largest expression depth bound of one policy.
    pub(crate) depth: usize,
    /// Whether some policy uses a delimited `like`.
    pub(crate) delimited_like: bool,
    /// The longest delimited `like` pattern, in bytes as written.
    pub(crate) longest_pattern: usize,
}

impl SourceShape {
    /// The stack parsing, validating, and analyzing the text needs.
    pub(crate) fn load_stack(self) -> usize {
        BASE_STACK + self.nesting * PARSE_STACK_PER_NESTING + self.depth * LOAD_STACK_PER_DEPTH
    }

    /// The stack evaluating the text's policies needs for a request whose
    /// longest string is `longest_field` bytes.
    pub(crate) fn eval_stack(self, longest_field: usize) -> usize {
        let like = if self.delimited_like {
            (self.longest_pattern + longest_field) * EVAL_STACK_PER_LIKE_CHAR
        } else {
            0
        };
        BASE_STACK + self.depth * EVAL_STACK_PER_DEPTH + like
    }
}

/// Runs `f` with at least `stack` bytes of stack, on a new stack if the
/// current one has less left.
pub fn with_stack<R>(stack: usize, f: impl FnOnce() -> R) -> R {
    stacker::maybe_grow(stack, stack, f)
}

/// Checks the size, nesting, and expression depth of authored policy text.
///
/// # Errors
///
/// Returns [`CedarEngineError::PolicyTooLarge`],
/// [`CedarEngineError::PolicyNestingTooDeep`], or
/// [`CedarEngineError::PolicyExpressionTooDeep`] for text over a bound.
pub fn check_policy_source(src: &str) -> Result<SourceShape, CedarEngineError> {
    if src.len() > MAX_POLICY_SOURCE_BYTES {
        return Err(CedarEngineError::PolicyTooLarge {
            size: src.len(),
            limit: MAX_POLICY_SOURCE_BYTES,
        });
    }
    check_shape(src)
}

/// Checks the nesting and expression depth of policy text of any size.
///
/// # Errors
///
/// Returns [`CedarEngineError::PolicyNestingTooDeep`] or
/// [`CedarEngineError::PolicyExpressionTooDeep`] for text over a bound.
pub fn check_shape(src: &str) -> Result<SourceShape, CedarEngineError> {
    let scanned = scan(src);
    if let Some(line) = scanned.nesting_line {
        return Err(CedarEngineError::PolicyNestingTooDeep {
            line,
            limit: MAX_POLICY_NESTING,
        });
    }
    if let Some((line, depth)) = scanned.deep_policy {
        return Err(CedarEngineError::PolicyExpressionTooDeep {
            line,
            depth,
            limit: MAX_POLICY_EXPRESSION_DEPTH,
        });
    }
    Ok(scanned.shape)
}

/// What [`scan`] found.
#[derive(Debug, Default)]
pub struct Scanned {
    pub(crate) shape: SourceShape,
    /// The line where bracket nesting first exceeds [`MAX_POLICY_NESTING`].
    nesting_line: Option<usize>,
    /// The starting line and depth bound of the first policy over
    /// [`MAX_POLICY_EXPRESSION_DEPTH`].
    deep_policy: Option<(usize, usize)>,
}

/// Brackets and operators seen directly within one bracket level.
#[derive(Debug, Default)]
struct Level {
    /// Operators and child brackets directly in this level.
    operators: usize,
    /// The largest depth bound of a child bracket.
    deepest_child: usize,
}

impl Level {
    fn depth(&self) -> usize {
        self.operators + self.deepest_child
    }
}

/// Where a delimited `like` pattern may come next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LikeState {
    None,
    /// After the `like` keyword.
    Keyword,
    /// After `like(`: the next string literal is a delimited pattern.
    Open,
}

/// Scans Cedar policy text without recursion, skipping string literals and
/// `//` comments.
///
/// Each AST node of a Cedar expression comes from an operator or bracket of
/// its source, and the nodes enclosing an expression come from the brackets
/// enclosing it or the operators beside them. So a policy's expression
/// depth is at most twice the sum, over the brackets enclosing its deepest
/// point, of the operators and brackets directly within each (twice, since
/// `!=`, `has a.b`, and `is ... in` expand to two nodes per operator).
/// Policies are separated by `;` outside brackets.
///
/// Malformed text, such as unbalanced brackets, is scanned leniently; the
/// parser reports it.
#[must_use]
pub fn scan(src: &str) -> Scanned {
    let bytes = src.as_bytes();
    let mut scanned = Scanned::default();
    let mut levels = vec![Level::default()];
    let mut line = 1;
    let mut policy_line: Option<usize> = None;
    let mut like_state = LikeState::None;
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        let next = bytes.get(index + 1).copied();
        let mut operator = false;
        let mut token = true;
        match byte {
            b'\n' => {
                line += 1;
                token = false;
                index += 1;
            }
            b'/' if next == Some(b'/') => {
                while bytes.get(index).is_some_and(|&b| b != b'\n') {
                    index += 1;
                }
                token = false;
            }
            b'"' => {
                let start = index;
                index += 1;
                while let Some(&b) = bytes.get(index) {
                    index += 1;
                    match b {
                        b'\\' => index += 1,
                        b'"' => break,
                        b'\n' => line += 1,
                        _ => {}
                    }
                }
                if like_state == LikeState::Open {
                    scanned.shape.delimited_like = true;
                    scanned.shape.longest_pattern = scanned
                        .shape
                        .longest_pattern
                        .max(index.min(bytes.len()) - start);
                }
            }
            b'(' | b'[' | b'{' => {
                if let Some(level) = levels.last_mut() {
                    level.operators += 1;
                }
                levels.push(Level::default());
                scanned.shape.nesting = scanned.shape.nesting.max(levels.len() - 1);
                if levels.len() - 1 > MAX_POLICY_NESTING && scanned.nesting_line.is_none() {
                    scanned.nesting_line = Some(line);
                }
                if like_state == LikeState::Keyword && byte == b'(' {
                    like_state = LikeState::Open;
                    policy_line.get_or_insert(line);
                    index += 1;
                    continue;
                }
                index += 1;
            }
            b')' | b']' | b'}' => {
                if levels.len() > 1
                    && let Some(closed) = levels.pop()
                    && let Some(parent) = levels.last_mut()
                {
                    parent.deepest_child = parent.deepest_child.max(closed.depth());
                }
                index += 1;
            }
            b';' if levels.len() == 1 => {
                finish_policy(&mut scanned, &mut levels, policy_line.take());
                token = false;
                index += 1;
            }
            b'&' | b'|' | b'=' if next == Some(byte) => {
                operator = true;
                index += 2;
            }
            b'!' | b'<' | b'>' => {
                operator = true;
                index += if next == Some(b'=') { 2 } else { 1 };
            }
            b'+' | b'-' | b'*' | b'.' => {
                operator = true;
                index += 1;
            }
            b if b.is_ascii_alphabetic() || b == b'_' => {
                let start = index;
                while bytes
                    .get(index)
                    .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
                {
                    index += 1;
                }
                let word = &bytes[start..index];
                operator = matches!(word, b"if" | b"in" | b"has" | b"like" | b"is");
                if word == b"like" {
                    like_state = LikeState::Keyword;
                    policy_line.get_or_insert(line);
                    if let Some(level) = levels.last_mut() {
                        level.operators += 1;
                    }
                    continue;
                }
            }
            b if b.is_ascii_whitespace() => {
                token = false;
                index += 1;
            }
            _ => index += 1,
        }
        if token {
            policy_line.get_or_insert(line);
            like_state = LikeState::None;
        }
        if operator && let Some(level) = levels.last_mut() {
            level.operators += 1;
        }
    }
    finish_policy(&mut scanned, &mut levels, policy_line);
    scanned
}

/// Records the depth bound of the policy that just ended, starting at
/// `policy_line`, and resets the levels for the next one.
fn finish_policy(scanned: &mut Scanned, levels: &mut Vec<Level>, policy_line: Option<usize>) {
    // Unclosed brackets at the end of the text belong to this policy too.
    while levels.len() > 1 {
        if let Some(closed) = levels.pop()
            && let Some(parent) = levels.last_mut()
        {
            parent.deepest_child = parent.deepest_child.max(closed.depth());
        }
    }
    let depth = levels.first().map_or(0, Level::depth);
    levels.clear();
    levels.push(Level::default());
    scanned.shape.depth = scanned.shape.depth.max(depth);
    if depth > MAX_POLICY_EXPRESSION_DEPTH && scanned.deep_policy.is_none() {
        scanned.deep_policy = Some((policy_line.unwrap_or(1), depth));
    }
}

/// Checks the request-derived strings of a `NetworkConnect` request,
/// returning the length of the longest.
///
/// # Errors
///
/// Returns [`CedarEngineError::RequestFieldTooLong`] for the first string
/// over [`MAX_REQUEST_FIELD_BYTES`].
pub fn check_network_request(request: &NetworkConnectRequest) -> Result<usize, CedarEngineError> {
    let mut longest = 0;
    check_field(&mut longest, "host", &request.host)?;
    check_field(&mut longest, "binary_path", &request.binary_path)?;
    for ancestor in &request.ancestors {
        check_field(&mut longest, "ancestors", ancestor)?;
    }
    Ok(longest)
}

/// Checks the request-derived strings of an `HttpRequest` request,
/// returning the length of the longest.
///
/// # Errors
///
/// Returns [`CedarEngineError::RequestFieldTooLong`] for the first string
/// over [`MAX_REQUEST_FIELD_BYTES`].
pub fn check_http_request(request: &HttpRequestInput) -> Result<usize, CedarEngineError> {
    let mut longest = 0;
    for (field, value) in [
        ("host", &request.host),
        ("binary_path", &request.binary_path),
        ("method", &request.method),
        ("path", &request.path),
        ("command", &request.command),
        ("jsonrpc_method", &request.jsonrpc_method),
        ("mcp_tool", &request.mcp_tool),
        ("mcp_method_class", &request.mcp_method_class),
        ("graphql_operation_type", &request.graphql_operation_type),
        ("graphql_operation_name", &request.graphql_operation_name),
    ] {
        check_field(&mut longest, field, value)?;
    }
    for ancestor in &request.ancestors {
        check_field(&mut longest, "ancestors", ancestor)?;
    }
    for field in &request.graphql_fields {
        check_field(&mut longest, "graphql_fields", field)?;
    }
    for (key, values) in &request.query {
        check_field(&mut longest, "query key", key)?;
        for value in values {
            check_field(&mut longest, "query value", value)?;
        }
    }
    Ok(longest)
}

fn check_field(
    longest: &mut usize,
    field: &'static str,
    value: &str,
) -> Result<(), CedarEngineError> {
    if value.len() > MAX_REQUEST_FIELD_BYTES {
        return Err(CedarEngineError::RequestFieldTooLong {
            field,
            length: value.len(),
            limit: MAX_REQUEST_FIELD_BYTES,
        });
    }
    *longest = (*longest).max(value.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(src: &str) -> SourceShape {
        scan(src).shape
    }

    #[test]
    fn depth_counts_operators_along_the_deepest_brackets() {
        // `(` and `{` at the top, `==` in the scope, then the condition.
        let policy = |condition: &str| {
            format!(
                r#"@id("p") permit (principal, action == Sandbox::Action::"HttpRequest", resource) when {{ {condition} }};"#
            )
        };
        // `@id(`, the scope, and the `when` brace are three top-level brackets.
        assert_eq!(shape(&policy("true")).depth, 3 + 1);
        assert_eq!(shape(&policy("a && b || c")).depth, 3 + 2);
        assert_eq!(shape(&policy("context.path != \"x\"")).depth, 3 + 2);
        // `(`, `&&`, `[`, `.`, and `(` directly, and `&&` within the first.
        assert_eq!(
            shape(&policy("(a && b) && [c, d].contains(e)")).depth,
            3 + 5 + 1
        );
        assert_eq!(shape(&policy("if a then b else c has d")).depth, 3 + 2);
        assert_eq!(shape(&policy("((((true))))")).nesting, 5);
        // Policies are bounded one at a time.
        let two = format!("{}{}", policy("a && b"), policy("a"));
        assert_eq!(shape(&two).depth, 3 + 1);
    }

    #[test]
    fn strings_and_comments_are_skipped() {
        let scanned = shape(
            "// ((((( && like(\"long pattern\", \"/\")\npermit (principal, action, resource) \
             when { context.path == \"((((\\\" && ||\" };",
        );
        assert_eq!(scanned.nesting, 1);
        assert_eq!(scanned.depth, 2 + 2);
        assert!(!scanned.delimited_like);
    }

    #[test]
    fn delimited_like_patterns_are_measured() {
        let scanned = shape(
            r#"permit (principal, action, resource) when {
                context.path like "/undelimited/*" &&
                context.path like ("/a/**", "/") &&
                context.mcp_tool like // comment
                    ("github.*", ".")
            };"#,
        );
        assert!(scanned.delimited_like);
        // `"github.*"`, with its quotes.
        assert_eq!(scanned.longest_pattern, 10);
        assert!(
            !shape(r#"permit (principal, action, resource) when { context.path like "/*" };"#)
                .delimited_like
        );
    }
}
