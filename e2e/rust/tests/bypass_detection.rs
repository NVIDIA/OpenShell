// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Verify that sandbox bypass detection provides fast-fail UX: direct TCP
//! connections that skip the HTTP CONNECT proxy are rejected with
//! ECONNREFUSED (immediate) rather than hanging until a network timeout.
//!
//! This test is implementation-agnostic — it validates the observable
//! behavior (fast rejection) regardless of whether the kernel rules are
//! installed via iptables or nftables.

#![cfg(feature = "e2e")]

use openshell_e2e::harness::sandbox::SandboxGuard;

/// Python script that attempts a raw TCP connect bypassing the proxy.
///
/// `socket.connect()` does not honor HTTP_PROXY — it goes directly through
/// the kernel, hitting the OUTPUT chain REJECT rule. The script reports the
/// outcome and wall-clock time so the test can assert on both.
///
/// Target 198.51.100.1 is RFC 5737 TEST-NET-2 — documentation-only address
/// space that will never route. This doesn't matter because the REJECT rule
/// fires in the OUTPUT chain before the packet reaches the network.
fn bypass_attempt_script() -> &'static str {
    r#"
import json, socket, time

start = time.monotonic()
result = "unknown"
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(("198.51.100.1", 80))
    result = "connected"
    s.close()
except ConnectionRefusedError:
    result = "refused"
except socket.timeout:
    result = "timeout"
except OSError as e:
    result = f"error:{e}"

elapsed_ms = int((time.monotonic() - start) * 1000)
print(json.dumps({"bypass_result": result, "elapsed_ms": elapsed_ms}), flush=True)
"#
}

/// A direct TCP connection bypassing the proxy should be rejected
/// immediately (ECONNREFUSED), not hang until a timeout.
#[tokio::test]
async fn bypass_attempt_is_rejected_fast() {
    let guard = SandboxGuard::create(&["--", "python3", "-c", bypass_attempt_script()])
        .await
        .expect("sandbox create");

    let json_line = guard
        .create_output
        .lines()
        .find(|l| l.contains("bypass_result"))
        .unwrap_or_else(|| {
            panic!(
                "no bypass_result JSON in output:\n{}",
                guard.create_output
            )
        });

    let parsed: serde_json::Value = serde_json::from_str(json_line.trim()).unwrap_or_else(|e| {
        panic!("failed to parse JSON '{json_line}': {e}")
    });

    let result = parsed["bypass_result"].as_str().unwrap();
    let elapsed_ms = parsed["elapsed_ms"].as_u64().unwrap();

    assert_eq!(
        result, "refused",
        "expected connection refused (REJECT rule), got '{result}' after {elapsed_ms}ms.\n\
         If 'timeout': REJECT rules may not be installed in the sandbox netns.\n\
         Full output:\n{}",
        guard.create_output
    );

    assert!(
        elapsed_ms < 3000,
        "bypass rejection took {elapsed_ms}ms — expected < 3000ms.\n\
         Fast rejection requires REJECT rules in the sandbox OUTPUT chain."
    );
}
