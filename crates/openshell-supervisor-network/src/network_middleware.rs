// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Engine-neutral network middleware selection and state.
//!
//! [`MiddlewareConfigs`] holds one policy revision's `network_middlewares`
//! and selects the ordered chain for a destination host in Rust, with the
//! same host-selector semantics as endpoint admission. Both engines use it:
//! a YAML sandbox converts the configs out of its Rego data, and a Cedar
//! sandbox builds them from the policy proto.
//!
//! [`MiddlewareState`] is a Cedar sandbox's live middleware: the active
//! configs, the connected service registry, and a generation counter that
//! each middleware change and each committed runtime configuration advance.
//! It replaces the empty-policy OPA engine Cedar sandboxes once carried for
//! this purpose, so a Cedar sandbox evaluates no Rego.
//!
//! Configs are [`MiddlewareConfig`] values: the OPA engine converts its Rego
//! data into them, and the Cedar engine builds them from the proto.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use miette::Result;
use openshell_core::host_pattern::HostSelector;
use openshell_core::proto::SandboxPolicy as ProtoSandboxPolicy;
use openshell_supervisor_middleware::{ChainEntry, ChainRunner, MiddlewareRegistry};
use tokio::sync::watch;

use crate::policy_types::{
    MiddlewareConfig, MiddlewareEndpointSelector, PolicyGenerationGuard, generation_guard_for,
};

/// The `network_middlewares` of one policy revision, ready for selection.
///
/// Cloning is cheap and shares the configs.
#[derive(Clone, Debug, Default)]
pub struct MiddlewareConfigs(Arc<[MiddlewareConfig]>);

impl MiddlewareConfigs {
    /// Holds `configs` in the order given.
    pub fn new(configs: Vec<MiddlewareConfig>) -> Self {
        Self(configs.into())
    }

    /// Reads the `network_middlewares` of a policy proto, keyed by config
    /// name in sorted order.
    ///
    /// Produces the same configs a YAML sandbox reads from the Rego data
    /// built from the same proto.
    pub fn from_proto(policy: &ProtoSandboxPolicy) -> Self {
        let mut entries: Vec<_> = policy.network_middlewares.iter().collect();
        entries.sort_by_key(|(name, _)| name.as_str());
        Self::new(
            entries
                .into_iter()
                .map(|(name, mw)| MiddlewareConfig {
                    policy_key: name.clone(),
                    middleware: mw.middleware.clone(),
                    order: mw.order,
                    config: mw.config.clone().unwrap_or_default(),
                    on_error: mw.on_error.clone(),
                    endpoints: mw
                        .endpoints
                        .as_ref()
                        .map(|selector| MiddlewareEndpointSelector {
                            include: selector.include.clone(),
                            exclude: selector.exclude.clone(),
                        }),
                })
                .collect(),
        )
    }

    /// Returns the ordered middleware chain whose selectors match `host`.
    ///
    /// # Errors
    ///
    /// Returns an error if a selector or `on_error` value is invalid, or more
    /// stages match than the platform allows.
    pub fn select(&self, host: &str) -> Result<Vec<ChainEntry>> {
        let mut entries = Vec::new();
        for config in self.0.iter() {
            if selector_matches(config, host)? {
                if entries.len() >= openshell_supervisor_middleware::MAX_MIDDLEWARE_CHAIN_STAGES {
                    return Err(miette::miette!(
                        "selected middleware stage count exceeds platform maximum {}",
                        openshell_supervisor_middleware::MAX_MIDDLEWARE_CHAIN_STAGES
                    ));
                }
                entries.push(chain_entry(config)?);
            }
        }
        openshell_supervisor_middleware::sort_chain_entries(&mut entries);
        Ok(entries)
    }

    /// Returns the number of configs.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

fn selector_matches(config: &MiddlewareConfig, host: &str) -> Result<bool> {
    let Some(selector) = &config.endpoints else {
        return Ok(false);
    };
    let selector = HostSelector::new(&selector.include, &selector.exclude)
        .map_err(|error| miette::miette!(error))?;
    Ok(selector.matches(host))
}

fn chain_entry(config: &MiddlewareConfig) -> Result<ChainEntry> {
    Ok(ChainEntry {
        name: config.policy_key.clone(),
        implementation: config.middleware.clone(),
        order: config.order,
        config: config.config.clone(),
        on_error: openshell_supervisor_middleware::OnError::parse(&config.on_error)?,
    })
}

/// The middleware configs and services in effect at one time.
#[derive(Clone)]
pub struct ActiveMiddleware {
    pub configs: MiddlewareConfigs,
    pub runner: ChainRunner,
}

/// A Cedar sandbox's live middleware configs, services, and generation.
///
/// The generation advances when the service registry is replaced, when a
/// runtime configuration is committed, and when a quarantine starts or ends
/// (see [`Self::change_configuration`]), under the write lock, so a reader
/// that observes a generation under the read lock also sees the middleware
/// that produced it. It is independent of the Cedar policy generation: a
/// middleware-only change does not close inspected tunnels, which keep the
/// middleware they started with.
pub struct MiddlewareState {
    active: RwLock<ActiveMiddleware>,
    generation: Arc<AtomicU64>,
    generation_tx: watch::Sender<u64>,
}

impl std::fmt::Debug for MiddlewareState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MiddlewareState")
            .field(
                "configs",
                &self.active.read().map(|active| active.configs.len()).ok(),
            )
            .field("generation", &self.current_generation())
            .finish_non_exhaustive()
    }
}

impl MiddlewareState {
    /// Starts at generation 0 with `configs` and no connected services.
    pub fn new(configs: MiddlewareConfigs) -> Self {
        let (generation_tx, _) = watch::channel(0);
        Self {
            active: RwLock::new(ActiveMiddleware {
                configs,
                runner: ChainRunner::default(),
            }),
            generation: Arc::new(AtomicU64::new(0)),
            generation_tx,
        }
    }

    fn read(&self) -> Result<std::sync::RwLockReadGuard<'_, ActiveMiddleware>> {
        self.active
            .read()
            .map_err(|_| miette::miette!("middleware state lock poisoned"))
    }

    fn write(&self) -> Result<std::sync::RwLockWriteGuard<'_, ActiveMiddleware>> {
        self.active
            .write()
            .map_err(|_| miette::miette!("middleware state lock poisoned"))
    }

    /// Advances the generation. Callers hold the write lock.
    fn advance_generation(&self) -> u64 {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.generation_tx.send_replace(generation);
        generation
    }

    /// Returns the current middleware generation.
    pub fn current_generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Pins `expected_generation`.
    ///
    /// # Errors
    ///
    /// Returns an error if `expected_generation` is already stale.
    pub fn generation_guard(&self, expected_generation: u64) -> Result<PolicyGenerationGuard> {
        generation_guard_for(
            expected_generation,
            self.current_generation(),
            &self.generation,
            &self.generation_tx,
        )
    }

    /// Selects the chain for `host` and returns the generation it came from.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or selection fails (see
    /// [`MiddlewareConfigs::select`]).
    pub fn select_with_generation(&self, host: &str) -> Result<(Vec<ChainEntry>, u64)> {
        let active = self.read()?;
        let generation = self.current_generation();
        Ok((active.configs.select(host)?, generation))
    }

    /// Returns the configs and services in effect now, for a tunnel to keep.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned.
    pub fn snapshot(&self) -> Result<ActiveMiddleware> {
        Ok(self.read()?.clone())
    }

    /// Returns the services in effect now.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned.
    pub fn runner(&self) -> Result<ChainRunner> {
        Ok(self.read()?.runner.clone())
    }

    /// Replaces the service registry and advances the generation.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned.
    pub fn replace_registry(&self, registry: MiddlewareRegistry) -> Result<()> {
        let mut active = self.write()?;
        active.runner = active.runner.with_replacement_registry(registry);
        self.advance_generation();
        Ok(())
    }

    /// Activates `configs`, and `registry` when given, as a new generation.
    ///
    /// `prepare` runs under the write lock before the generation advances;
    /// it acquires whatever else the commit needs and may fail. `publish`
    /// runs with its result after the generation advances, so existing
    /// guards are already stale, and before the new middleware is visible:
    /// readers stay blocked until it returns. Neither may call back into
    /// this state.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or `prepare` fails; nothing
    /// is changed then, no guard becomes stale, and `publish` is not called.
    pub fn commit<P>(
        &self,
        configs: MiddlewareConfigs,
        registry: Option<MiddlewareRegistry>,
        prepare: impl FnOnce() -> Result<P>,
        publish: impl FnOnce(P),
    ) -> Result<PolicyGenerationGuard> {
        let mut active = self.write()?;
        let prepared = prepare()?;
        let runner = registry.map(|registry| active.runner.with_replacement_registry(registry));
        let generation = self.advance_generation();
        publish(prepared);
        active.configs = configs;
        if let Some(runner) = runner {
            active.runner = runner;
        }
        drop(active);
        self.generation_guard(generation)
    }

    /// Applies a configuration change that keeps the middleware itself.
    ///
    /// `change` runs under the write lock and returns whether the
    /// configuration changed; when it did, the generation advances so every
    /// pinned guard becomes stale. Quarantine entry and exit use this: the
    /// configuration a guard was pinned to is no longer the active one, even
    /// though the middleware configs and services are unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or `change` fails; the
    /// generation does not advance then.
    pub fn change_configuration<T>(&self, change: impl FnOnce() -> Result<(T, bool)>) -> Result<T> {
        let _active = self.write()?;
        let (result, changed) = change()?;
        if changed {
            self.advance_generation();
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                |()| stale_during_publish = before.is_stale(),
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
                |()| published = true,
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
