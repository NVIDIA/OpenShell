// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Formal policy verification for `OpenShell` sandboxes.
//!
//! Encodes sandbox policies, binary capabilities, and credential scopes as Z3
//! SMT constraints, then checks reachability queries to detect data exfiltration
//! paths and write-bypass violations.

pub mod accepted_risks;
pub mod credentials;
pub mod envelope;
pub mod finding;
pub mod model;
pub mod policy;
pub mod queries;
pub mod registry;
pub mod report;

use std::path::Path;

use miette::Result;

use accepted_risks::{apply_accepted_risks, load_accepted_risks};
use model::build_model;
use policy::parse_policy;
use queries::run_all_queries;
use report::{render_compact, render_report};

/// Run the prover end-to-end and return an exit code.
///
/// - `0` — pass (no critical/high findings, or all accepted)
/// - `1` — fail (critical or high findings present)
/// - `2` — input error
///
/// Binary and API capability registries are embedded at compile time.
/// Pass `registry_dir` to override with a custom filesystem registry.
pub fn prove(
    policy_path: &str,
    credentials_path: &str,
    registry_dir: Option<&str>,
    accepted_risks_path: Option<&str>,
    compact: bool,
) -> Result<i32> {
    let policy = parse_policy(Path::new(policy_path))?;

    let (credential_set, binary_registry) = match registry_dir {
        Some(dir) => {
            let dir = Path::new(dir);
            (
                credentials::load_credential_set_from_dir(Path::new(credentials_path), dir)?,
                registry::load_binary_registry_from_dir(dir)?,
            )
        }
        None => (
            credentials::load_credential_set_embedded(Path::new(credentials_path))?,
            registry::load_embedded_binary_registry()?,
        ),
    };

    let z3_model = build_model(policy, credential_set, binary_registry);
    let mut findings = run_all_queries(&z3_model);

    if let Some(ar_path) = accepted_risks_path {
        let accepted = load_accepted_risks(Path::new(ar_path))?;
        findings = apply_accepted_risks(findings, &accepted);
    }

    let exit_code = if compact {
        render_compact(&findings, policy_path, credentials_path)
    } else {
        render_report(&findings, policy_path, credentials_path)
    };

    Ok(exit_code)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn testdata_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata")
    }

    // 1. Parse testdata/policy.yaml, verify structure.
    #[test]
    fn test_parse_policy() {
        let path = testdata_dir().join("policy.yaml");
        let model = parse_policy(&path).expect("failed to parse policy");
        assert_eq!(model.version, 1);
        assert!(model.network_policies.contains_key("github_api"));
        let rule = &model.network_policies["github_api"];
        assert_eq!(rule.name, "github-api");
        assert_eq!(rule.endpoints.len(), 2);
        assert!(rule.binaries.len() >= 4);
    }

    // 2. Verify readable_paths.
    #[test]
    fn test_filesystem_policy() {
        let path = testdata_dir().join("policy.yaml");
        let model = parse_policy(&path).expect("failed to parse policy");
        let readable = model.filesystem_policy.readable_paths();
        assert!(readable.contains(&"/usr".to_owned()));
        assert!(readable.contains(&"/sandbox".to_owned()));
        assert!(readable.contains(&"/tmp".to_owned()));
    }

    // 3. Workdir NOT included by default (matches runtime behavior).
    #[test]
    fn test_include_workdir_default() {
        let yaml = r"
version: 1
filesystem_policy:
  read_only:
    - /usr
";
        let model = policy::parse_policy_str(yaml).expect("parse");
        let readable = model.filesystem_policy.readable_paths();
        assert!(!readable.contains(&"/sandbox".to_owned()));
    }

    // 4. Workdir excluded when include_workdir: false.
    #[test]
    fn test_include_workdir_false() {
        let yaml = r"
version: 1
filesystem_policy:
  include_workdir: false
  read_only:
    - /usr
";
        let model = policy::parse_policy_str(yaml).expect("parse");
        let readable = model.filesystem_policy.readable_paths();
        assert!(!readable.contains(&"/sandbox".to_owned()));
    }

    // 5. No duplicate when workdir already in read_write.
    #[test]
    fn test_include_workdir_no_duplicate() {
        let yaml = r"
version: 1
filesystem_policy:
  include_workdir: true
  read_write:
    - /sandbox
    - /tmp
";
        let model = policy::parse_policy_str(yaml).expect("parse");
        let readable = model.filesystem_policy.readable_paths();
        let sandbox_count = readable.iter().filter(|p| *p == "/sandbox").count();
        assert_eq!(sandbox_count, 1);
    }

    // 6. End-to-end: testdata policy with a github credential in scope and a
    // bypass-L7 binary (git) emits an `l7_bypass_credentialed` finding.
    // The prover output is categorical, not severity-graded.
    #[test]
    fn test_findings_for_github_policy() {
        use finding::category;

        let policy_path = testdata_dir().join("policy.yaml");
        let creds_path = testdata_dir().join("credentials.yaml");

        let pol = parse_policy(&policy_path).expect("parse policy");
        let cred_set = credentials::load_credential_set_embedded(&creds_path).expect("load creds");
        let bin_reg = registry::load_embedded_binary_registry().expect("load registry");

        let z3_model = build_model(pol, cred_set, bin_reg);
        let findings = run_all_queries(&z3_model);

        let categories: std::collections::HashSet<&str> =
            findings.iter().map(|f| f.query.as_str()).collect();
        assert!(
            categories.contains(category::L7_BYPASS_CREDENTIALED),
            "expected l7_bypass_credentialed finding for bypass-L7 binary with credential in scope; \
             got categories: {categories:?}"
        );
        // Every emitted category must be one of the four v1 categories.
        let allowed: std::collections::HashSet<&str> = [
            category::LINK_LOCAL_REACH,
            category::L7_BYPASS_CREDENTIALED,
            category::CREDENTIAL_REACH_EXPANSION,
            category::CAPABILITY_EXPANSION,
        ]
        .into_iter()
        .collect();
        for c in &categories {
            assert!(
                allowed.contains(*c),
                "unexpected category {c} emitted by the prover"
            );
        }
    }

    #[test]
    fn test_wildcard_endpoint_covering_credential_host_emits_credential_reach() {
        use finding::{FindingPath, category};

        let policy = policy::parse_policy_str(
            r#"
version: 1
network_policies:
  github_wildcard:
    name: github-wildcard
    endpoints:
      - host: "*.github.com"
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-write
    binaries:
      - path: /usr/bin/curl
"#,
        )
        .expect("parse policy");
        let cred_set =
            credentials::load_credential_set_embedded(&testdata_dir().join("credentials.yaml"))
                .expect("load creds");
        let bin_reg = registry::load_embedded_binary_registry().expect("load registry");

        let z3_model = build_model(policy, cred_set, bin_reg);
        let findings = run_all_queries(&z3_model);

        let reach = findings
            .iter()
            .find(|finding| finding.query == category::CREDENTIAL_REACH_EXPANSION)
            .expect("wildcard host covering api.github.com must be credentialed");
        assert!(reach.paths.iter().any(|path| matches!(
            path,
            FindingPath::Exfil(exfil)
                if exfil.endpoint_host == "*.github.com" && exfil.binary == "/usr/bin/curl"
        )));
    }

    #[test]
    fn test_known_metadata_hostname_emits_link_local_finding() {
        use finding::{FindingPath, category};

        let policy = policy::parse_policy_str(
            r"
version: 1
network_policies:
  metadata:
    name: metadata
    endpoints:
      - host: metadata.google.internal
        port: 80
    binaries:
      - path: /usr/bin/curl
",
        )
        .expect("parse policy");
        let bin_reg = registry::load_embedded_binary_registry().expect("load registry");

        let z3_model = build_model(policy, credentials::CredentialSet::default(), bin_reg);
        let findings = run_all_queries(&z3_model);

        let link_local = findings
            .iter()
            .find(|finding| finding.query == category::LINK_LOCAL_REACH)
            .expect("known metadata hostname must emit link-local/metadata finding");
        assert!(link_local.paths.iter().any(|path| matches!(
            path,
            FindingPath::Exfil(exfil)
                if exfil.endpoint_host == "metadata.google.internal"
        )));
    }

    // 7. Empty policy produces no findings.
    #[test]
    fn test_empty_policy_no_findings() {
        let policy_path = testdata_dir().join("empty-policy.yaml");
        let creds_path = testdata_dir().join("credentials.yaml");

        let pol = parse_policy(&policy_path).expect("parse policy");
        let cred_set = credentials::load_credential_set_embedded(&creds_path).expect("load creds");
        let bin_reg = registry::load_embedded_binary_registry().expect("load registry");

        let z3_model = build_model(pol, cred_set, bin_reg);
        let findings = run_all_queries(&z3_model);

        assert!(
            findings.is_empty(),
            "deny-all policy should produce no findings, got: {findings:?}"
        );
    }
}
