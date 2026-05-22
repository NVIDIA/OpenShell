// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::hint::black_box;
use std::time::Instant;

use openshell_sandbox::l7::privacy_scan::scan_body;

struct Case {
    name: &'static str,
    content_type: &'static str,
    payload: Vec<u8>,
    iterations: usize,
}

struct CaseResult {
    name: &'static str,
    bytes: usize,
    iterations: usize,
    redacted: bool,
    matches: usize,
    mean_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    throughput_mib_s: f64,
}

fn main() {
    let cold_payload = json_small_secrets();
    let started = Instant::now();
    let cold_result = scan_body("application/json", cold_payload.as_bytes());
    let cold_ms = started.elapsed().as_secs_f64() * 1000.0;
    println!(
        "# cold_first_scan_ms={cold_ms:.3} redacted={} matches={}",
        cold_result.redacted, cold_result.match_count
    );
    println!(
        "{:<24} {:>10} {:>8} {:>8} {:>8} {:>10} {:>10} {:>10} {:>10} {:>10} {:>12}",
        "case",
        "bytes",
        "iters",
        "redact",
        "matches",
        "mean_ms",
        "p50_ms",
        "p95_ms",
        "p99_ms",
        "max_ms",
        "MiB/s"
    );

    for case in cases() {
        let result = run_case(&case);
        println!(
            "{:<24} {:>10} {:>8} {:>8} {:>8} {:>10.4} {:>10.4} {:>10.4} {:>10.4} {:>10.4} {:>12.1}",
            result.name,
            result.bytes,
            result.iterations,
            result.redacted,
            result.matches,
            result.mean_ms,
            result.p50_ms,
            result.p95_ms,
            result.p99_ms,
            result.max_ms,
            result.throughput_mib_s,
        );
    }
}

fn run_case(case: &Case) -> CaseResult {
    for _ in 0..100 {
        let result = scan_body(case.content_type, black_box(&case.payload));
        black_box(result.replacement_body.len());
    }

    let mut timings = Vec::with_capacity(case.iterations);
    let mut redacted = false;
    let mut matches = 0;
    for _ in 0..case.iterations {
        let started = Instant::now();
        let result = scan_body(case.content_type, black_box(&case.payload));
        let elapsed = started.elapsed().as_secs_f64() * 1000.0;
        redacted = result.redacted;
        matches = result.match_count;
        black_box(result.replacement_body.len());
        timings.push(elapsed);
    }

    timings.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let total_ms = timings.iter().sum::<f64>();
    let mean_ms = total_ms / timings.len() as f64;
    let bytes_total = case.payload.len() as f64 * case.iterations as f64;
    let throughput_mib_s = (bytes_total / 1024.0 / 1024.0) / (total_ms / 1000.0);

    CaseResult {
        name: case.name,
        bytes: case.payload.len(),
        iterations: case.iterations,
        redacted,
        matches,
        mean_ms,
        p50_ms: percentile(&timings, 50.0),
        p95_ms: percentile(&timings, 95.0),
        p99_ms: percentile(&timings, 99.0),
        max_ms: *timings.last().unwrap_or(&0.0),
        throughput_mib_s,
    }
}

fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = ((pct / 100.0) * (sorted.len().saturating_sub(1) as f64)).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "text_clean_small",
            content_type: "text/plain",
            payload: "hello from the sandbox with no sensitive values".as_bytes().to_vec(),
            iterations: 50_000,
        },
        Case {
            name: "text_secret_small",
            content_type: "text/plain",
            payload: "email alice@example.com ssn 123-45-6789 key sk-proj-abcdefghijklmnopqrstuvwxyz123456"
                .as_bytes()
                .to_vec(),
            iterations: 50_000,
        },
        Case {
            name: "json_clean_small",
            content_type: "application/json",
            payload: br#"{"message":"hello","safe":true,"count":3}"#.to_vec(),
            iterations: 50_000,
        },
        Case {
            name: "json_secret_small",
            content_type: "application/json",
            payload: json_small_secrets().into_bytes(),
            iterations: 50_000,
        },
        Case {
            name: "json_nested",
            content_type: "application/json",
            payload: br#"{"messages":[{"role":"user","content":"contact alice@example.com with ssn 123-45-6789"}],"metadata":{"openai_key":"sk-proj-abcdefghijklmnopqrstuvwxyz123456","phone":"555-123-4567"},"count":2,"ok":true}"#.to_vec(),
            iterations: 25_000,
        },
        Case {
            name: "json_clean_64k",
            content_type: "application/json",
            payload: json_prompt_of_size(64 * 1024, None),
            iterations: 5_000,
        },
        Case {
            name: "json_secret_64k",
            content_type: "application/json",
            payload: json_prompt_of_size(
                64 * 1024,
                Some(" alice@example.com 123-45-6789 sk-proj-abcdefghijklmnopqrstuvwxyz123456"),
            ),
            iterations: 5_000,
        },
        Case {
            name: "json_clean_256k",
            content_type: "application/json",
            payload: json_prompt_of_size(256 * 1024, None),
            iterations: 1_000,
        },
        Case {
            name: "json_secret_256k",
            content_type: "application/json",
            payload: json_prompt_of_size(
                256 * 1024,
                Some(" alice@example.com 123-45-6789 sk-proj-abcdefghijklmnopqrstuvwxyz123456"),
            ),
            iterations: 1_000,
        },
        Case {
            name: "json_clean_1m",
            content_type: "application/json",
            payload: json_prompt_of_size(1024 * 1024, None),
            iterations: 250,
        },
        Case {
            name: "json_secret_1m",
            content_type: "application/json",
            payload: json_prompt_of_size(
                1024 * 1024,
                Some(" alice@example.com 123-45-6789 sk-proj-abcdefghijklmnopqrstuvwxyz123456"),
            ),
            iterations: 250,
        },
        Case {
            name: "text_secret_1m",
            content_type: "text/plain",
            payload: text_of_size(
                1024 * 1024,
                "alice@example.com 123-45-6789 sk-proj-abcdefghijklmnopqrstuvwxyz123456",
            ),
            iterations: 250,
        },
    ]
}

fn json_small_secrets() -> String {
    r#"{"email":"alice@example.com","openai_key":"sk-proj-abcdefghijklmnopqrstuvwxyz123456","ssn":"123-45-6789","phone":"555-123-4567","aws":"AKIA1234567890ABCDEF"}"#.to_string()
}

fn json_prompt_of_size(target_bytes: usize, suffix: Option<&str>) -> Vec<u8> {
    let prefix = r#"{"prompt":""#;
    let suffix = suffix.unwrap_or("");
    let close = r#""}"#;
    let target_content_len = target_bytes
        .saturating_sub(prefix.len())
        .saturating_sub(close.len())
        .saturating_sub(suffix.len());
    let mut body = String::with_capacity(target_bytes + 128);
    body.push_str(prefix);
    while body.len() < prefix.len() + target_content_len {
        body.push_str("safe generated text ");
    }
    body.truncate(prefix.len() + target_content_len);
    body.push_str(suffix);
    body.push_str(close);
    body.into_bytes()
}

fn text_of_size(target_bytes: usize, suffix: &str) -> Vec<u8> {
    let mut body = String::with_capacity(target_bytes + suffix.len());
    while body.len() + suffix.len() < target_bytes {
        body.push_str("safe generated text ");
    }
    body.truncate(target_bytes.saturating_sub(suffix.len()));
    body.push_str(suffix);
    body.into_bytes()
}
