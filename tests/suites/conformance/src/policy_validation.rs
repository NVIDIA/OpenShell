// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy validation at the gateway: which sandbox policies create and
//! update refuse, and what the gateway fills in before it stores a policy.
//!
//! Ported from `e2e/python/test_policy_validation.py` and the ambiguity case
//! of `e2e/python/test_sandbox_policy.py`.

use testkit::policy;
use testkit::sdk::raw::proto;
use testkit::{Context, Error, GrpcCode, Result};

/// The MCP protocol version the gateway stores for an MCP endpoint that
/// names none. Changing the default changes what existing policies mean, so
/// this test pins it.
const DEFAULT_MCP_VERSION: &str = "2025-11-25";

/// Create refuses a policy that runs the workload as root, has `..` in a
/// filesystem path, or makes `/` writable, and says which rule it broke.
#[testkit::test]
async fn create_rejects_unsafe_policies(cx: &mut Context) -> testkit::Result {
    let mut root = policy::base();
    root.process.get_or_insert_default().run_as_user = "root".to_string();

    let mut traversal = policy::base();
    traversal.filesystem.get_or_insert_default().read_only = vec!["/usr/../etc/shadow".to_string()];

    let mut broad = policy::base();
    broad.filesystem.get_or_insert_default().read_write = vec!["/".to_string()];

    for (suffix, policy, reason) in [
        ("ur", root, "root"),
        ("ut", traversal, "traversal"),
        ("ub", broad, "broad"),
    ] {
        let message = expect_refused(cx, suffix, policy, GrpcCode::InvalidArgument).await?;
        testkit::ensure!(
            message.to_lowercase().contains(reason),
            "policy {suffix} was refused without mentioning {reason:?}: {message}"
        );
    }
    Ok(())
}

/// Create refuses a policy whose rules pin the same endpoint to different
/// destination addresses, before it launches anything.
#[testkit::test]
async fn create_rejects_ambiguous_endpoint_pinning(cx: &mut Context) -> testkit::Result {
    const HOST: &str = "10.200.0.2";
    const PORT: u16 = 19876;
    let mut ambiguous = policy::base();
    policy::allow(&mut ambiguous, "user_rule", HOST, PORT, &["/**"]);
    policy::allow(&mut ambiguous, "approved_rule", HOST, PORT, &["/**"]).allowed_ips =
        vec!["10.200.0.0/24".to_string()];

    let message = expect_refused(cx, "amb", ambiguous, GrpcCode::FailedPrecondition).await?;
    testkit::ensure!(
        message.contains("network endpoint ambiguity validation failed")
            && message.contains("allowed_ips"),
        "the refusal doesn't name the ambiguous allowed_ips: {message}"
    );
    Ok(())
}

/// An MCP endpoint without MCP options is stored, and served to the
/// supervisor, with the default protocol version.
#[testkit::test]
async fn create_stores_default_mcp_version(cx: &mut Context) -> testkit::Result {
    let mut mcp = policy::base();
    let endpoint = policy::allow(&mut mcp, "mcp_default", "mcp.example.com", 443, &["/**"]);
    endpoint.protocol = "mcp".to_string();
    endpoint.rules = vec![proto::L7Rule {
        allow: Some(proto::L7Allow {
            method: "initialize".to_string(),
            ..proto::L7Allow::default()
        }),
    }];
    testkit::ensure!(endpoint.mcp.is_none(), "the test policy names MCP options");

    // The policy is stored at create, so the sandbox needn't become ready.
    let sandbox = cx.sandbox("mcp").policy(mcp).create().await?;

    let stored = sandbox.spec().await?.and_then(|spec| spec.policy);
    expect_default_mcp_version("the stored policy", stored.as_ref())?;

    let served = sandbox.config().await?.policy;
    expect_default_mcp_version("the sandbox config", served.as_ref())
}

/// Fail unless the gateway refuses to create a sandbox with `policy` with
/// `code`, and return the refusal.
async fn expect_refused(
    cx: &Context,
    suffix: &str,
    policy: proto::SandboxPolicy,
    code: GrpcCode,
) -> Result<String> {
    match cx.sandbox(suffix).policy(policy).create().await {
        Ok(sandbox) => Err(Error::msg(format!(
            "the gateway accepted sandbox {}",
            sandbox.name()
        ))),
        Err(error) if error.grpc_code() == Some(code) => Ok(error.to_string()),
        Err(error) => Err(error.context(format!("expected {code:?}"))),
    }
}

fn expect_default_mcp_version(what: &str, policy: Option<&proto::SandboxPolicy>) -> Result {
    let versions = policy
        .and_then(|policy| policy.network_policies.get("mcp_default"))
        .and_then(|rule| rule.endpoints.first())
        .and_then(|endpoint| endpoint.mcp.as_ref())
        .map(|mcp| mcp.versions.clone());
    testkit::ensure!(
        versions.as_deref() == Some(&[DEFAULT_MCP_VERSION.to_string()][..]),
        "{what} has MCP versions {versions:?}; expected [{DEFAULT_MCP_VERSION:?}]"
    );
    Ok(())
}
