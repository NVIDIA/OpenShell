// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::proto::{NetworkEndpoint as InternalEndpoint, SandboxPolicy as InternalPolicy};
use openshell_policy::{
    lower_authored_policy, parse_authored_policy, project_base_policy, serialize_authored_policy,
};

#[test]
fn public_policy_lowers_and_projects_semantically() {
    let authored = parse_authored_policy(
        r"
version: 1
filesystem_policy: {}
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        ports: [443]
        protocol: mcp
        mcp: {}
        rules:
          - allow:
              method: tools/call
              tool:
                glob: search_*
    binaries:
      - path: /usr/bin/agent
",
    )
    .unwrap();

    let internal = lower_authored_policy(authored).unwrap();
    let endpoint = &internal.network_policies["mcp"].endpoints[0];
    assert!(!endpoint.advisor_proposed);
    assert!(!endpoint.provider_credentialed);
    assert_eq!(endpoint.mcp.as_ref().unwrap().versions, ["2025-11-25"]);
    assert_eq!(
        endpoint.rules[0].allow.as_ref().unwrap().params["name"].glob,
        "search_*"
    );

    let projected = project_base_policy(&internal).unwrap();
    let canonical = serialize_authored_policy(&projected).unwrap();
    assert!(canonical.contains("glob: search_*"));
    assert!(!canonical.contains("advisor_proposed"));
    assert!(!canonical.contains("provider_credentialed"));
    assert_eq!(lower_authored_policy(projected).unwrap(), internal);
}

#[test]
fn projection_removes_internal_authority_without_mutating_internal_policy() {
    let mut internal = InternalPolicy {
        version: 1,
        ..Default::default()
    };
    internal.network_policies.insert(
        "advisor".to_string(),
        openshell_core::proto::NetworkPolicyRule {
            name: "advisor".to_string(),
            endpoints: vec![InternalEndpoint {
                host: "example.com".to_string(),
                port: 443,
                ports: vec![443],
                advisor_proposed: true,
                provider_credentialed: true,
                ..Default::default()
            }],
            ..Default::default()
        },
    );

    let projected = project_base_policy(&internal).unwrap();
    let lowered = lower_authored_policy(projected).unwrap();
    let lowered_endpoint = &lowered.network_policies["advisor"].endpoints[0];
    assert!(!lowered_endpoint.advisor_proposed);
    assert!(!lowered_endpoint.provider_credentialed);
    assert!(internal.network_policies["advisor"].endpoints[0].advisor_proposed);
    assert!(internal.network_policies["advisor"].endpoints[0].provider_credentialed);
}

#[test]
fn omitted_and_empty_public_binary_lists_lower_to_no_binary_matches() {
    for binaries in ["", "    binaries: []\n"] {
        let source = format!(
            "version: 1\nnetwork_policies:\n  api:\n    endpoints:\n      - host: api.example.com\n        ports: [443]\n{binaries}"
        );
        let authored = parse_authored_policy(&source).expect("public policy must parse");
        let lowered = lower_authored_policy(authored).expect("public policy must lower");

        assert!(
            lowered.network_policies["api"].binaries.is_empty(),
            "omitted and explicit-empty public lists must remain the same no-match scope"
        );
    }
}
