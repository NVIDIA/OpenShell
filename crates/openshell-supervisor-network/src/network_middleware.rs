// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub use openshell_policy_runtime_interface::network_middleware::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_types::{MiddlewareConfig, MiddlewareEndpointSelector};
    use openshell_core::proto::SandboxPolicy as ProtoSandboxPolicy;
    use openshell_supervisor_middleware::ChainEntry;

    fn matching_configs(count: usize) -> MiddlewareConfigs {
        MiddlewareConfigs::new(
            (0..count)
                .map(|index| MiddlewareConfig {
                    policy_key: format!("stage-{index}"),
                    middleware: "openshell/regex".to_string(),
                    endpoints: Some(MiddlewareEndpointSelector {
                        include: vec!["api.example.com".to_string()],
                        exclude: Vec::new(),
                    }),
                    ..Default::default()
                })
                .collect(),
        )
    }

    #[test]
    fn select_accepts_maximum_selected_stages() {
        let chain = matching_configs(openshell_supervisor_middleware::MAX_MIDDLEWARE_CHAIN_STAGES)
            .select("api.example.com")
            .expect("maximum selected chain");
        assert_eq!(
            chain.len(),
            openshell_supervisor_middleware::MAX_MIDDLEWARE_CHAIN_STAGES
        );
    }

    #[test]
    fn select_rejects_selected_stages_over_capacity() {
        let error =
            matching_configs(openshell_supervisor_middleware::MAX_MIDDLEWARE_CHAIN_STAGES + 1)
                .select("api.example.com")
                .expect_err("selected chain over capacity");
        assert!(
            error
                .to_string()
                .contains("selected middleware stage count exceeds platform maximum 10")
        );
    }

    fn middleware_proto() -> ProtoSandboxPolicy {
        let middleware = |order: i32, include: &str, exclude: &[&str]| {
            openshell_core::proto::NetworkMiddlewareConfig {
                middleware: "openshell/regex".to_string(),
                order,
                endpoints: Some(openshell_core::proto::MiddlewareEndpointSelector {
                    include: vec![include.to_string()],
                    exclude: exclude.iter().map(ToString::to_string).collect(),
                }),
                ..Default::default()
            }
        };
        let mut policy = ProtoSandboxPolicy::default();
        policy
            .network_middlewares
            .insert("late".to_string(), middleware(20, "**.example.com", &[]));
        policy.network_middlewares.insert(
            "early".to_string(),
            middleware(10, "*.example.com", &["trusted.example.com"]),
        );
        policy
    }

    /// A Cedar sandbox selects from the proto exactly what a YAML sandbox
    /// selects from the Rego data built from the same proto.
    #[test]
    fn proto_configs_select_like_the_rego_data_built_from_the_same_proto() {
        let policy = middleware_proto();
        let opa = crate::opa::OpaEngine::from_proto(&policy).expect("YAML engine loads");
        let configs = MiddlewareConfigs::from_proto(&policy);
        for host in [
            "api.example.com",
            "trusted.example.com",
            "deep.api.example.com",
            "example.org",
        ] {
            let input = crate::policy_types::NetworkInput {
                host: host.to_string(),
                port: 443,
                binary_path: "/usr/bin/curl".into(),
                binary_sha256: String::new(),
                ancestors: Vec::new(),
                cmdline_paths: Vec::new(),
            };
            let (rego, _) = opa
                .query_middleware_chain_with_generation(&input)
                .expect("Rego selection");
            let rust = configs.select(host).expect("Rust selection");
            let names = |chain: &[ChainEntry]| {
                chain
                    .iter()
                    .map(|entry| (entry.name.clone(), entry.order))
                    .collect::<Vec<_>>()
            };
            assert_eq!(names(&rust), names(&rego), "host {host}");
        }
    }

    #[cfg(feature = "cedar")]
    #[test]
    fn commit_advances_the_generation_before_publishing() {
        let state = MiddlewareState::new(MiddlewareConfigs::default());
        let before = state.generation_guard(0).expect("current guard");
        let mut stale_during_prepare = true;
        let mut stale_during_publish = false;
        let guard = state
            .commit(
                MiddlewareConfigs::from_proto(&middleware_proto()),
                None,
                || {
                    stale_during_prepare = before.is_stale();
                    Ok(())
                },
                |(), _| stale_during_publish = before.is_stale(),
            )
            .expect("commit");
        assert!(!stale_during_prepare);
        assert!(stale_during_publish);
        assert_eq!(guard.captured_generation(), 1);
        let (chain, generation) = state
            .select_with_generation("api.example.com")
            .expect("select");
        assert_eq!(generation, 1);
        assert_eq!(chain.len(), 2);
    }

    /// A failed preparation commits nothing: the guard stays current and the
    /// middleware stays on the previous configs.
    #[cfg(feature = "cedar")]
    #[test]
    fn commit_changes_nothing_when_preparation_fails() {
        let state = MiddlewareState::new(MiddlewareConfigs::default());
        let before = state.generation_guard(0).expect("current guard");
        let mut published = false;
        let error = state
            .commit(
                MiddlewareConfigs::from_proto(&middleware_proto()),
                None,
                || Err::<(), _>(miette::miette!("lock poisoned")),
                |(), _| published = true,
            )
            .expect_err("preparation fails");
        assert!(error.to_string().contains("lock poisoned"));
        assert!(!published);
        assert!(!before.is_stale());
        let (chain, generation) = state
            .select_with_generation("api.example.com")
            .expect("select");
        assert_eq!(generation, 0);
        assert!(chain.is_empty());
    }

    #[cfg(feature = "cedar")]
    #[test]
    fn change_configuration_advances_only_when_changed() {
        let state = MiddlewareState::new(MiddlewareConfigs::default());
        let before = state.generation_guard(0).expect("current guard");
        let kept: u64 = state
            .change_configuration(|| Ok((7, false)))
            .expect("unchanged");
        assert_eq!(kept, 7);
        assert!(!before.is_stale());
        state
            .change_configuration(|| Ok(((), true)))
            .expect("changed");
        assert!(before.is_stale());
        assert_eq!(state.current_generation(), 1);
    }
}
