// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Verify that direct TCP bypass attempts fail promptly at the sandbox
//! syscall boundary instead of reaching the runtime's external network.
//!
//! This test is implementation-agnostic — it validates the observable
//! behavior rather than a particular packet-filter implementation.

#![cfg(feature = "e2e")]

use openshell_e2e::harness::sandbox::SandboxGuard;

/// Python script that attempts a raw TCP connect bypassing the proxy.
///
/// `socket.connect()` does not honor proxy environment variables. The script
/// reports the outcome and wall-clock time so the test can assert that the
/// sandbox's seccomp mediation blocks it before the outer fence is needed.
///
/// Target 198.51.100.1 is RFC 5737 TEST-NET-2 — documentation-only address
/// space that will never route.
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
except PermissionError:
    result = "denied"
except socket.timeout:
    result = "timeout"
except OSError as e:
    result = f"error:{e}"

elapsed_ms = int((time.monotonic() - start) * 1000)
print(json.dumps({"bypass_result": result, "elapsed_ms": elapsed_ms}), flush=True)
"#
}

/// A direct TCP connection bypassing supervision should be denied without
/// waiting for the socket's network timeout.
#[tokio::test]
async fn bypass_attempt_is_rejected_fast() {
    let guard = SandboxGuard::create(&["--", "python3", "-c", bypass_attempt_script()])
        .await
        .expect("sandbox create");

    let json_line = guard
        .create_output
        .lines()
        .find(|l| l.contains("bypass_result"))
        .unwrap_or_else(|| panic!("no bypass_result JSON in output:\n{}", guard.create_output));

    let parsed: serde_json::Value = serde_json::from_str(json_line.trim())
        .unwrap_or_else(|e| panic!("failed to parse JSON '{json_line}': {e}"));

    let result = parsed["bypass_result"].as_str().unwrap();
    let elapsed_ms = parsed["elapsed_ms"].as_u64().unwrap();

    assert_eq!(
        result, "denied",
        "expected seccomp mediation to deny the direct connect, got '{result}' after {elapsed_ms}ms.\n\
         Full output:\n{}",
        guard.create_output
    );

    assert!(
        elapsed_ms < 8000,
        "bypass rejection took {elapsed_ms}ms — expected < 8000ms."
    );
}
