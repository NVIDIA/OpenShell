// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Live policy updates through `policy set` and `policy update`: revisions
//! and versions, idempotent updates, scoped rule changes, and the revision a
//! supervisor writes when it fills in a sparse initial policy.
//!
//! Ported from the `live_policy_update` e2e tests. Revisions are read from
//! `policy get` and `policy list` with `--output json`.

use std::time::Duration;

use serde_json::Value;
use testkit::policy;
use testkit::sdk::raw::proto;
use testkit::{Context, Result, Sandbox};

use crate::support::policy_revisions;

/// A network-only policy the supervisor fills in with the filesystem paths it
/// needs at startup, which makes a second revision.
const SPARSE_POLICY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../examples/policy-advisor/sandbox-policy.yaml"
));

/// How long a revision may take to be loaded.
const LOAD_TIMEOUT: Duration = Duration::from_mins(2);

/// Each new policy makes a newer version with a different hash, and setting
/// the same policy again makes no new version. Starts from a policy without
/// network rules, adds one rule, then a second. Every revision is listed, and
/// none is left pending.
#[testkit::test]
async fn policy_set_versions_and_ignores_repeats(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .sandbox("pset")
        .policy(policy::base())
        .command(["sleep", "infinity"])
        .create_ready()
        .await?;
    let initial = settled(cx, &sandbox).await?;

    let mut one_rule = policy::base();
    policy::allow(&mut one_rule, "rule_0", "api.anthropic.com", 443, &["/**"]);
    let mut two_rules = one_rule.clone();
    policy::allow(&mut two_rules, "rule_1", "example.com", 443, &["/**"]);

    let mut previous = initial.clone();
    let mut versions = vec![version(&initial)?];
    for (step, next) in [("one rule", &one_rule), ("two rules", &two_rules)] {
        policy::set(&sandbox, next).await?;
        let updated = settled(cx, &sandbox).await?;
        testkit::ensure!(
            version(&updated)? > version(&previous)?,
            "setting {step} didn't make a newer version: before {previous}, after {updated}"
        );
        testkit::ensure!(
            updated["hash"] != previous["hash"],
            "setting {step} didn't change the hash: {}",
            updated["hash"]
        );

        policy::set(&sandbox, next).await?;
        let repeated = settled(cx, &sandbox).await?;
        for field in ["version", "hash"] {
            testkit::ensure!(
                repeated[field] == updated[field],
                "setting {step} again changed the {field}: {} became {}",
                updated[field],
                repeated[field]
            );
        }
        versions.push(version(&updated)?);
        previous = updated;
    }

    let revisions = policy_revisions(cx, &sandbox).await?;
    let listed: Vec<u64> = revisions["revisions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|revision| revision["version"].as_u64())
        .collect();
    let missing: Vec<_> = versions.iter().filter(|v| !listed.contains(v)).collect();
    testkit::ensure!(
        missing.is_empty(),
        "policy list is missing versions {missing:?}: {revisions}"
    );
    Ok(())
}

/// `policy update` with an explicit rule and binaries changes only the
/// endpoint they select, even when another rule has the same host and ports.
/// An update whose ports or binaries match the rule only in part is rejected
/// without a new revision.
#[testkit::test]
async fn policy_update_changes_only_the_selected_endpoint(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .sandbox("pscop")
        .policy(scoped_policy()?)
        .command(["sleep", "infinity"])
        .create_ready()
        .await?;
    let before = settled(cx, &sandbox).await?;
    let rules_before = &before["policy"]["network_policies"];
    testkit::ensure!(
        rules_before.is_object(),
        "policy get has no network policies: {before}"
    );

    // Each partial update matches one of ports and binaries fully, so a check
    // that needs both to mismatch can't pass.
    for (target, binaries) in [
        (
            "api.example.com:443:POST:/admin",
            &["/usr/bin/curl", "/usr/bin/python3"][..],
        ),
        (
            "api.example.com:443,8443:POST:/admin",
            &["/usr/bin/curl"][..],
        ),
    ] {
        let mut args = vec![
            "policy",
            "update",
            sandbox.name(),
            "--rule-name",
            "internal_api",
            "--add-allow",
            target,
        ];
        for binary in binaries {
            args.extend(["--binary", binary]);
        }
        cx.cli(args).await?.failure()?;
        let unchanged = policy_get(cx, &sandbox).await?;
        for field in ["version", "hash", "policy"] {
            testkit::ensure!(
                unchanged[field] == before[field],
                "rejected update {target} with {binaries:?} changed the {field}"
            );
        }
    }

    update(
        cx,
        &sandbox,
        "--add-allow",
        "api.example.com:443,8443:POST:/admin",
    )
    .await?;
    let allowed = policy_get(cx, &sandbox).await?;
    testkit::ensure!(
        version(&allowed)? > version(&before)? && allowed["hash"] != before["hash"],
        "the allow didn't make a new revision: before {before}, after {allowed}"
    );
    let rules = &allowed["policy"]["network_policies"];
    testkit::ensure!(
        rules["sibling"] == rules_before["sibling"],
        "the allow changed the sibling rule: {}",
        rules["sibling"]
    );
    testkit::ensure!(
        rules["internal_api"]["endpoints"][1] == rules_before["internal_api"]["endpoints"][1],
        "the allow changed the other endpoint: {}",
        rules["internal_api"]["endpoints"][1]
    );
    testkit::ensure!(
        has_rule(&rules["internal_api"]["endpoints"][0]["rules"], |rule| {
            rule["allow"]["method"] == "POST" && rule["allow"]["path"] == "/admin"
        }),
        "the endpoint has no POST /admin allow rule: {}",
        rules["internal_api"]["endpoints"][0]
    );

    update(
        cx,
        &sandbox,
        "--add-deny",
        "api.example.com:443,8443:POST:/admin/private",
    )
    .await?;
    let denied = policy_get(cx, &sandbox).await?;
    testkit::ensure!(
        version(&denied)? > version(&allowed)?,
        "the deny didn't make a new revision: before {allowed}, after {denied}"
    );
    let rules = &denied["policy"]["network_policies"];
    testkit::ensure!(
        rules["sibling"] == rules_before["sibling"],
        "the deny changed the sibling rule: {}",
        rules["sibling"]
    );
    testkit::ensure!(
        has_rule(
            &rules["internal_api"]["endpoints"][0]["deny_rules"],
            |rule| { rule["method"] == "POST" && rule["path"] == "/admin/private" }
        ),
        "the endpoint has no POST /admin/private deny rule: {}",
        rules["internal_api"]["endpoints"][0]
    );
    Ok(())
}

/// A sandbox created with a sparse policy gets a second revision with the
/// paths the supervisor added, and the supervisor reports it loaded: the
/// first is superseded and neither stays pending. Regression for #2159.
#[testkit::test]
async fn sparse_initial_policy_revision_is_loaded(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .cli_sandbox("spars")
        .policy_yaml(SPARSE_POLICY)
        .command(["sleep", "infinity"])
        .create_ready()
        .await?;
    testkit::poll_until(
        "the filled-in revision 2 to be loaded",
        LOAD_TIMEOUT,
        Duration::from_secs(2),
        async || {
            let active = policy_get(cx, &sandbox).await?;
            let revisions = policy_revisions(cx, &sandbox).await?;
            let statuses = statuses(&revisions);
            let expected = [(1_u64, "superseded".to_string()), (2, "loaded".to_string())];
            Ok(
                if active["version"] == 2 && statuses.as_slice() == expected {
                    testkit::Poll::Ready(())
                } else {
                    testkit::Poll::Pending(format!(
                        "active version {}, revisions {statuses:?}",
                        active["version"]
                    ))
                },
            )
        },
    )
    .await
}

/// [`policy::base`] with two rules that share a host and ports: `internal_api`
/// with a second endpoint, and `sibling` for other binaries.
fn scoped_policy() -> Result<proto::SandboxPolicy> {
    policy::base_with(
        "network_policies:
  internal_api:
    name: internal_api
    binaries: [{path: /usr/bin/curl}, {path: /usr/bin/python3}]
    endpoints:
      - {host: api.example.com, ports: [443, 8443], protocol: rest, access: read-only}
      - {host: other.example.com, port: 443, protocol: rest, access: read-only}
  sibling:
    name: sibling
    binaries: [{path: /usr/bin/wget}]
    endpoints:
      - {host: api.example.com, ports: [443, 8443], protocol: rest, access: read-only}
",
    )
}

/// Add `rule` to the `internal_api` rule for curl and Python with
/// `policy update --wait`.
async fn update(cx: &Context, sandbox: &Sandbox, flag: &str, rule: &str) -> Result {
    cx.cli([
        "policy",
        "update",
        sandbox.name(),
        "--rule-name",
        "internal_api",
        "--binary",
        "/usr/bin/curl",
        "--binary",
        "/usr/bin/python3",
        flag,
        rule,
        "--wait",
    ])
    .await?
    .success()?;
    Ok(())
}

/// The sandbox's active policy, from `policy get --full --output json`.
async fn policy_get(cx: &Context, sandbox: &Sandbox) -> Result<Value> {
    let active: Value = cx
        .cli([
            "policy",
            "get",
            sandbox.name(),
            "--full",
            "--output",
            "json",
        ])
        .await?
        .success()?
        .json()?;
    version(&active)?;
    testkit::ensure!(
        active["hash"].as_str().is_some_and(|hash| !hash.is_empty()),
        "policy get has no hash: {active}"
    );
    Ok(active)
}

/// The active policy once its revision is loaded and no revision is pending.
/// Fails if a revision failed to load.
async fn settled(cx: &Context, sandbox: &Sandbox) -> Result<Value> {
    testkit::poll_until(
        &format!("the policy of sandbox {} to be loaded", sandbox.name()),
        LOAD_TIMEOUT,
        Duration::from_secs(1),
        async || {
            let active = policy_get(cx, sandbox).await?;
            let revisions = policy_revisions(cx, sandbox).await?;
            let statuses = statuses(&revisions);
            testkit::ensure!(
                statuses.iter().all(|(_, status)| status != "failed"),
                "a policy revision failed to load: {revisions}"
            );
            let active_version = version(&active)?;
            let loaded = statuses
                .iter()
                .any(|(version, status)| *version == active_version && status == "loaded");
            let pending = statuses.iter().any(|(_, status)| status == "pending");
            Ok(if loaded && !pending {
                testkit::Poll::Ready(active)
            } else {
                testkit::Poll::Pending(format!(
                    "active version {active_version}, revisions {statuses:?}"
                ))
            })
        },
    )
    .await
}

/// Each revision's version and status, oldest first.
fn statuses(revisions: &Value) -> Vec<(u64, String)> {
    let mut statuses: Vec<_> = revisions["revisions"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|revision| {
            (
                revision["version"].as_u64().unwrap_or_default(),
                revision["status"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    statuses.sort();
    statuses
}

fn version(policy: &Value) -> Result<u64> {
    policy["version"]
        .as_u64()
        .ok_or_else(|| testkit::Error::msg(format!("policy get has no version: {policy}")))
}

fn has_rule(rules: &Value, matches: impl Fn(&Value) -> bool) -> bool {
    rules
        .as_array()
        .is_some_and(|rules| rules.iter().any(matches))
}
