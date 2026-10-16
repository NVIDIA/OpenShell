// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Baseline factory source fixture: no image-update trait or new hook required.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriver;

use crate::test_support::FakeComputeDriver;
use crate::{
    ComputeDriverBuildContext, ComputeDriverFactory, ComputeDriverInstance,
    ComputeDriverRegistration, ComputeDriverRegistry, DriverWatchStream, SharedComputeDriver,
    SharedComputeDriverImageUpdates,
};

// Written using only the baseline generated trait, not the new optional trait.
type BaselineDriver =
    Arc<dyn ComputeDriver<WatchSandboxesStream = DriverWatchStream> + Send + Sync>;

struct BaselineFactory {
    driver: BaselineDriver,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl ComputeDriverFactory for BaselineFactory {
    async fn build(
        &self,
        _context: ComputeDriverBuildContext<'_>,
    ) -> openshell_core::Result<ComputeDriverInstance> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        // This unchanged baseline expression must compile without a new trait.
        Ok(ComputeDriverInstance::InProcess(self.driver.clone()))
    }
}

struct OptInFactory {
    driver: Arc<FakeComputeDriver>,
    legacy_build_calls: Arc<AtomicUsize>,
    opt_in_calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl ComputeDriverFactory for OptInFactory {
    async fn build(
        &self,
        _context: ComputeDriverBuildContext<'_>,
    ) -> openshell_core::Result<ComputeDriverInstance> {
        self.legacy_build_calls.fetch_add(1, Ordering::SeqCst);
        Ok(ComputeDriverInstance::InProcess(self.driver.clone()))
    }

    async fn build_with_image_updates(
        &self,
        _context: ComputeDriverBuildContext<'_>,
    ) -> openshell_core::Result<(
        ComputeDriverInstance,
        Option<SharedComputeDriverImageUpdates>,
    )> {
        self.opt_in_calls.fetch_add(1, Ordering::SeqCst);
        Ok((
            ComputeDriverInstance::InProcess(self.driver.clone()),
            Some(self.driver.clone()),
        ))
    }
}

async fn registered_runtime(factory: impl ComputeDriverFactory + 'static) -> crate::ComputeRuntime {
    let mut registry = ComputeDriverRegistry::new();
    registry
        .install(ComputeDriverRegistration::new("fixture", 0, None, factory).unwrap())
        .unwrap();
    let selection = registry.select(Some("fixture")).unwrap();
    let config = openshell_core::Config::new(None);
    let overrides = BTreeMap::new();
    let startup = crate::compute::driver_config::DriverStartupContext {
        file: None,
        guest_tls: None,
        gateway_port: 8080,
        gateway_tls_enabled: false,
        endpoint_overrides: &overrides,
    };
    let store = Arc::new(crate::persistence::test_store().await);
    crate::build_compute_runtime(
        &registry,
        &selection,
        &config,
        startup,
        store,
        crate::sandbox_index::SandboxIndex::new(),
        crate::sandbox_watch::SandboxWatchBus::new(),
        crate::tracing_bus::TracingLogBus::new(),
        Arc::new(crate::supervisor_session::SupervisorSessionRegistry::new()),
        tokio::sync::watch::channel(false).1,
    )
    .await
    .unwrap()
    .with_sandbox_image_updates(true)
}

#[tokio::test]
async fn baseline_factory_and_trait_object_still_build_without_opt_in() {
    // This concrete fixture implements only the baseline generated trait.
    let driver: BaselineDriver = Arc::new(crate::compute::NoopTestDriver::default());
    let shared: SharedComputeDriver = driver.clone();
    // Exhaustive baseline enum match also prevents adding a required new variant.
    match ComputeDriverInstance::InProcess(shared) {
        ComputeDriverInstance::InProcess(actual) => assert!(Arc::ptr_eq(&actual, &driver)),
        ComputeDriverInstance::ManagedRemote(_) => panic!("expected in-process driver"),
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let runtime = registered_runtime(BaselineFactory {
        driver,
        calls: calls.clone(),
    })
    .await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        runtime
            .update_sandbox_image("not-created", "example/workload:v2".into(), 1)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unimplemented
    );
}

#[tokio::test]
async fn capability_alone_does_not_register_an_in_process_image_updater() {
    let driver = Arc::new(FakeComputeDriver::new().with_sandbox_image_updates());
    let runtime = registered_runtime(BaselineFactory {
        driver: driver.clone(),
        calls: Arc::new(AtomicUsize::new(0)),
    })
    .await;
    driver.clear_calls();
    assert_eq!(
        runtime
            .update_sandbox_image("not-created", "example/workload:v2".into(), 1)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unimplemented
    );
    assert!(driver.calls().is_empty());
}

#[tokio::test]
async fn registered_opt_in_hook_supplies_the_optional_updater() {
    let legacy_calls = Arc::new(AtomicUsize::new(0));
    let opt_in_calls = Arc::new(AtomicUsize::new(0));
    let runtime = registered_runtime(OptInFactory {
        driver: Arc::new(FakeComputeDriver::new().with_sandbox_image_updates()),
        legacy_build_calls: legacy_calls.clone(),
        opt_in_calls: opt_in_calls.clone(),
    })
    .await;
    assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);
    assert_eq!(opt_in_calls.load(Ordering::SeqCst), 1);
    // Passing capability/registration admission reaches the sandbox lookup.
    assert_eq!(
        runtime
            .update_sandbox_image("not-created", "example/workload:v2".into(), 1)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
}
