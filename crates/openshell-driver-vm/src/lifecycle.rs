// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use openshell_core::proto::compute::v1::DriverSandbox as Sandbox;

use crate::runtime::VmBackend;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchAbortReason {
    LauncherSpawnFailed,
    BeforeLaunchHookFailed,
    GuestPrepareFailed,
}

#[derive(Debug, Clone)]
pub struct LifecycleError {
    message: String,
    resource_exhausted: bool,
}

impl LifecycleError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            resource_exhausted: false,
        }
    }

    pub fn resource_exhausted(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            resource_exhausted: true,
        }
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub fn is_resource_exhausted(&self) -> bool {
        self.resource_exhausted
    }
}

impl std::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for LifecycleError {}

pub type LifecycleResult<T> = Result<T, LifecycleError>;

/// A capability an extension can require from the VM backend.
///
/// Extensions declare features they need (e.g. PCI passthrough or an
/// external kernel image) and the VM driver resolves a concrete
/// [`VmBackend`] that can satisfy them. The mapping from feature to
/// backend lives in [`BackendFeature::requires_qemu`] for now; once a
/// third backend exists this should evolve into a per-backend capability
/// table that the resolver intersects against feature requirements.
///
/// # Current limitations
///
/// Until the non-GPU QEMU launch path (PCI device transport / VFIO root
/// port wiring) lands, the driver still rejects launches where the
/// resolved backend is QEMU but the sandbox has no GPU. As a result,
/// declaring [`Self::PciPassthrough`] or [`Self::ExternalKernelImage`] on
/// a non-GPU sandbox is accepted by [`LifecycleExtensionRegistry::validate`]
/// at registration time but will fail provisioning with a
/// `FailedPrecondition` status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendFeature {
    /// Extension supplies its own kernel image via
    /// [`LaunchPlan::kernel_image`]. Currently QEMU-only.
    ExternalKernelImage,
    /// Extension contributes guest init drop-ins via
    /// [`LaunchPlan::guest_init_dropins`]. Supported by all backends.
    GuestInitDropins,
    /// Extension needs PCI device passthrough on the guest. Currently
    /// QEMU-only and currently rejected for non-GPU sandboxes pending the
    /// non-GPU QEMU launch path landing.
    PciPassthrough,
    /// Extension needs a host TAP device wired into the guest. Currently
    /// QEMU-only (libkrun does not expose a TAP transport).
    TapNetworking,
}

impl BackendFeature {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExternalKernelImage => "external-kernel-image",
            Self::GuestInitDropins => "guest-init-dropins",
            Self::PciPassthrough => "pci-passthrough",
            Self::TapNetworking => "tap-networking",
        }
    }

    /// Returns true when satisfying this feature requires the QEMU backend
    /// today. This is the simplest possible resolver and is expected to be
    /// replaced with a per-backend capability table once a third backend
    /// exists.
    #[must_use]
    pub fn requires_qemu(self) -> bool {
        matches!(
            self,
            Self::ExternalKernelImage | Self::PciPassthrough | Self::TapNetworking
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExtensionCapabilities {
    pub kernel_profiles: Vec<String>,
    pub guest_init_dropins: Vec<String>,
    pub launch_features: Vec<String>,
    pub host_resources: Vec<String>,
}

/// A registration-time description of what a lifecycle extension provides
/// and requires.
///
/// `required_backends` and `required_backend_features` are merged into the
/// launch plan unconditionally for every sandbox. An extension that wants
/// conditional behavior (e.g. only contribute requirements when the
/// sandbox spec asks for it) should leave the descriptor fields empty and
/// call [`LaunchPlan::require_backend`] /
/// [`LaunchPlan::require_backend_feature`] inside
/// [`LifecycleExtension::configure_launch`] instead.
///
/// A future PR will add a per-sandbox activation protocol so the driver
/// can gate this merge on a sandbox spec field. Until that lands, the
/// only knob is "declare in the descriptor (always merged) vs decide in
/// the hook (per-sandbox)".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionDescriptor {
    pub name: String,
    pub provides: ExtensionCapabilities,
    pub required_backends: Vec<VmBackend>,
    pub required_backend_features: Vec<BackendFeature>,
}

impl ExtensionDescriptor {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            provides: ExtensionCapabilities::default(),
            required_backends: Vec::new(),
            required_backend_features: Vec::new(),
        }
    }
}

/// A guest-side init drop-in injected into the sandbox's overlay disk.
///
/// Drop-ins land at `/opt/openshell/init.d/{name}` inside the guest with
/// mode `0o755`. The guest's init script *executes* drop-ins in a child
/// shell in deterministic ASCII-sorted order; it does not source them.
/// Authors should:
///
/// - Begin the file with a `#!/bin/bash` (or equivalent) shebang.
/// - Use the `00-`, `50-`, `99-` prefix convention to control ordering.
/// - Treat the parent shell as immutable: env vars set in a drop-in do not
///   propagate to the rest of init.
///
/// `name` must consist of ASCII letters, digits, `.`, `-`, or `_` (no
/// path separators, no `.`/`..`); duplicates across a single launch plan
/// are rejected by the driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestInitDropin {
    pub name: String,
    pub contents: Vec<u8>,
}

impl GuestInitDropin {
    #[must_use]
    pub fn new(name: impl Into<String>, contents: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            contents: contents.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LaunchPlan {
    pub backend: VmBackend,
    pub vcpus: u8,
    pub mem_mib: u32,
    pub required_backends: Vec<VmBackend>,
    pub required_backend_features: Vec<BackendFeature>,
    pub kernel_profile: Option<String>,
    pub kernel_image: Option<PathBuf>,
    pub gpu_bdf: Option<String>,
    pub tap_device: Option<String>,
    pub guest_ip: Option<String>,
    pub host_ip: Option<String>,
    pub vsock_cid: Option<u32>,
    pub guest_mac: Option<String>,
    pub gateway_port: Option<u16>,
    pub guest_init_dropins: Vec<GuestInitDropin>,
    pub env: Vec<String>,
}

impl LaunchPlan {
    pub fn require_backend(&mut self, backend: VmBackend) {
        if !self.required_backends.contains(&backend) {
            self.required_backends.push(backend);
        }
    }

    pub fn require_backend_feature(&mut self, feature: BackendFeature) {
        if !self.required_backend_features.contains(&feature) {
            self.required_backend_features.push(feature);
        }
    }

    pub fn require_backend_features(
        &mut self,
        features: impl IntoIterator<Item = BackendFeature>,
    ) {
        for feature in features {
            self.require_backend_feature(feature);
        }
    }
}

#[derive(Debug, Clone)]
pub struct RestoreContext {
    pub sandbox: Sandbox,
    pub state_dir: PathBuf,
}

/// Lifecycle hooks an extension can implement to participate in VM sandbox
/// provisioning, launch failure, deletion, and post-restart reconciliation.
///
/// # Hook ordering during a successful launch
///
/// 1. [`configure_launch`](Self::configure_launch) — contribute backend
///    requirements (via [`LaunchPlan::require_backend`] /
///    [`LaunchPlan::require_backend_feature`]) and provisioning inputs
///    (kernel profile, guest init drop-ins, etc.). Called before the driver
///    has resolved the final backend.
/// 2. Driver resolves [`LaunchPlan::backend`] from declared requirements
///    and allocates backend-specific host resources (subnet, tap, vsock).
/// 3. [`before_launch`](Self::before_launch) — perform host-side
///    side effects with the resolved plan in hand, optionally append
///    additional guest env via [`LaunchPlan::env`].
/// 4. The driver spawns the VM launcher process.
///
/// On launch failure or sandbox deletion, the driver invokes
/// [`after_launch_failed`](Self::after_launch_failed) or
/// [`after_delete`](Self::after_delete) in **reverse
/// registration order**, so cleanup mirrors setup.
#[tonic::async_trait]
pub trait LifecycleExtension: std::fmt::Debug + Send + Sync {
    fn name(&self) -> &str;

    fn descriptor(&self) -> ExtensionDescriptor {
        ExtensionDescriptor::new(self.name())
    }

    /// Contribute backend requirements and provisioning inputs to the plan
    /// before the driver picks a backend.
    ///
    /// Use this hook to:
    /// - Declare backend requirements with
    ///   [`LaunchPlan::require_backend`] or
    ///   [`LaunchPlan::require_backend_feature`].
    /// - Set [`LaunchPlan::kernel_profile`] or
    ///   [`LaunchPlan::kernel_image`].
    /// - Append [`LaunchPlan::guest_init_dropins`] entries.
    ///
    /// At this point [`LaunchPlan::backend`] is the driver's tentative
    /// choice and may still change during backend resolution. Do not perform
    /// host-side side effects here — defer them to
    /// [`before_launch`](Self::before_launch).
    async fn configure_launch(
        &self,
        _sandbox: &Sandbox,
        _state_dir: &Path,
        _plan: &mut LaunchPlan,
    ) -> LifecycleResult<()> {
        Ok(())
    }

    /// Perform host-side preparation with the resolved launch plan.
    ///
    /// At this point [`LaunchPlan::backend`],
    /// [`LaunchPlan::required_backends`], and
    /// [`LaunchPlan::required_backend_features`] are finalized and any
    /// backend-specific host resources (subnet, tap, vsock) have been
    /// allocated. This hook is the right place to bind PCI devices, set
    /// up filesystem state, or otherwise prepare the host.
    ///
    /// Implementations MAY append entries to [`LaunchPlan::env`] to
    /// inject additional guest environment variables, and MAY return an
    /// error to abort the launch. Implementations MUST NOT change
    /// [`LaunchPlan::backend`], [`LaunchPlan::required_backends`], or
    /// [`LaunchPlan::required_backend_features`]; those changes are
    /// ignored by the driver once `before_launch` is reached.
    ///
    /// If this hook performs allocations that must be released on failure
    /// or delete, implement
    /// [`after_launch_failed`](Self::after_launch_failed) and
    /// [`after_delete`](Self::after_delete) accordingly.
    async fn before_launch(
        &self,
        _sandbox: &Sandbox,
        _state_dir: &Path,
        _plan: &mut LaunchPlan,
    ) -> LifecycleResult<()> {
        Ok(())
    }

    /// Release anything this extension allocated during
    /// [`configure_launch`](Self::configure_launch) or
    /// [`before_launch`](Self::before_launch) when the launcher
    /// could not be started or aborted before it became healthy.
    ///
    /// Invoked in reverse registration order. Errors are logged but do not
    /// propagate; do best-effort cleanup and return [`Ok`] when possible.
    /// This hook is invoked on every launcher failure, including failures
    /// that happen during a persisted-sandbox restore (in that case
    /// [`after_restore`](Self::after_restore) is *not*
    /// invoked).
    async fn after_launch_failed(
        &self,
        _sandbox: &Sandbox,
        _state_dir: &Path,
        _reason: LaunchAbortReason,
    ) -> LifecycleResult<()> {
        Ok(())
    }

    /// Release per-sandbox resources after a sandbox has been deleted.
    ///
    /// Invoked in reverse registration order. Errors are logged but do not
    /// propagate.
    async fn after_delete(
        &self,
        _sandbox: &Sandbox,
        _state_dir: &Path,
    ) -> LifecycleResult<()> {
        Ok(())
    }

    /// Inspect or reconcile persisted extension state before the driver
    /// attempts to restore a sandbox after a process restart.
    ///
    /// Returning an error causes the driver to skip restoring this
    /// sandbox; the persisted state is left on disk for operator
    /// inspection.
    async fn before_restore(
        &self,
        _sandbox: &RestoreContext,
    ) -> LifecycleResult<()> {
        Ok(())
    }

    /// Notify the extension that a persisted sandbox has been
    /// successfully restored and its launcher is running again.
    ///
    /// Only invoked when restore succeeds. If the restore fails partway
    /// through, [`after_launch_failed`](Self::after_launch_failed)
    /// runs instead.
    async fn after_restore(
        &self,
        _sandbox: &RestoreContext,
    ) -> LifecycleResult<()> {
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct LifecycleExtensionRegistry {
    extensions: Vec<Arc<dyn LifecycleExtension>>,
}

impl std::fmt::Debug for LifecycleExtensionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LifecycleExtensionRegistry")
            .field(
                "names",
                &self
                    .extensions
                    .iter()
                    .map(|ext| ext.name())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl LifecycleExtensionRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(extensions: Vec<Arc<dyn LifecycleExtension>>) -> Self {
        Self { extensions }
    }

    pub fn push(&mut self, extension: Arc<dyn LifecycleExtension>) {
        self.extensions.push(extension);
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.extensions.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.extensions.len()
    }

    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.extensions
            .iter()
            .map(|ext| ext.name().to_string())
            .collect()
    }

    #[must_use]
    pub fn descriptors(&self) -> Vec<ExtensionDescriptor> {
        self.extensions.iter().map(|ext| ext.descriptor()).collect()
    }

    pub fn validate(&self) -> LifecycleResult<()> {
        let mut names = HashSet::new();
        for ext in &self.extensions {
            let descriptor = ext.descriptor();
            validate_extension_name(ext.name())?;
            validate_extension_name(&descriptor.name)?;
            if descriptor.name != ext.name() {
                return Err(LifecycleError::new(format!(
                    "lifecycle extension '{}' descriptor name does not match '{}'",
                    ext.name(),
                    descriptor.name
                )));
            }
            validate_descriptor_strings(&descriptor)?;
            if !names.insert(descriptor.name.clone()) {
                return Err(LifecycleError::new(format!(
                    "duplicate lifecycle extension name: {}",
                    descriptor.name
                )));
            }
        }
        Ok(())
    }

    pub async fn configure_launch(
        &self,
        sandbox: &Sandbox,
        state_dir: &Path,
        plan: &mut LaunchPlan,
    ) -> LifecycleResult<()> {
        for ext in &self.extensions {
            let descriptor = ext.descriptor();
            for backend in descriptor.required_backends {
                plan.require_backend(backend);
            }
            plan.require_backend_features(descriptor.required_backend_features);
            // Snapshot fields where "last writer wins" could mask an
            // extension conflict, so we can flag the conflict instead of
            // silently dropping the earlier value.
            let prev_kernel_profile = plan.kernel_profile.clone();
            let prev_kernel_image = plan.kernel_image.clone();
            ext.configure_launch(sandbox, state_dir, plan).await?;
            warn_on_singleton_overwrite(
                ext.name(),
                "kernel_profile",
                prev_kernel_profile.as_deref(),
                plan.kernel_profile.as_deref(),
            );
            warn_on_singleton_overwrite(
                ext.name(),
                "kernel_image",
                prev_kernel_image
                    .as_deref()
                    .map(|p| p.display().to_string()),
                plan.kernel_image
                    .as_deref()
                    .map(|p| p.display().to_string()),
            );
        }
        Ok(())
    }

    pub async fn before_launch(
        &self,
        sandbox: &Sandbox,
        state_dir: &Path,
        plan: &mut LaunchPlan,
    ) -> LifecycleResult<()> {
        for ext in &self.extensions {
            ext.before_launch(sandbox, state_dir, plan).await?;
        }
        Ok(())
    }

    pub async fn after_launch_failed(
        &self,
        sandbox: &Sandbox,
        state_dir: &Path,
        reason: LaunchAbortReason,
    ) {
        for ext in self.extensions.iter().rev() {
            if let Err(err) = ext
                .after_launch_failed(sandbox, state_dir, reason.clone())
                .await
            {
                tracing::warn!(
                    extension = ext.name(),
                    sandbox_id = %sandbox.id,
                    error = %err,
                    "vm driver: lifecycle extension after_launch_failed hook failed"
                );
            }
        }
    }

    pub async fn after_delete(&self, sandbox: &Sandbox, state_dir: &Path) {
        for ext in self.extensions.iter().rev() {
            if let Err(err) = ext.after_delete(sandbox, state_dir).await {
                tracing::warn!(
                    extension = ext.name(),
                    sandbox_id = %sandbox.id,
                    error = %err,
                    "vm driver: lifecycle extension after_delete hook failed"
                );
            }
        }
    }

    pub async fn before_restore(
        &self,
        sandbox: &RestoreContext,
    ) -> LifecycleResult<()> {
        for ext in &self.extensions {
            ext.before_restore(sandbox).await?;
        }
        Ok(())
    }

    pub async fn after_restore(&self, sandbox: &RestoreContext) {
        for ext in &self.extensions {
            if let Err(err) = ext.after_restore(sandbox).await {
                tracing::warn!(
                    extension = ext.name(),
                    sandbox_id = %sandbox.sandbox.id,
                    error = %err,
                    "vm driver: lifecycle extension after_restore hook failed"
                );
            }
        }
    }
}

fn warn_on_singleton_overwrite<T>(
    extension_name: &str,
    field: &str,
    prev: Option<T>,
    next: Option<T>,
) where
    T: AsRef<str> + std::fmt::Display + PartialEq,
{
    let (Some(prev), Some(next)) = (prev, next) else {
        return;
    };
    if prev == next {
        return;
    }
    tracing::warn!(
        extension = extension_name,
        field,
        previous = %prev,
        next = %next,
        "vm driver: lifecycle extension overwrote a singleton launch-plan field set by an earlier extension"
    );
}

pub fn extension_state_dir(
    sandbox_state_dir: &Path,
    extension_name: &str,
) -> LifecycleResult<PathBuf> {
    validate_extension_name(extension_name)?;
    Ok(sandbox_state_dir.join("extensions").join(extension_name))
}

fn validate_extension_name(name: &str) -> LifecycleResult<()> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(LifecycleError::new(
            "lifecycle extension name is empty or reserved",
        ));
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.')
    {
        return Err(LifecycleError::new(format!(
            "lifecycle extension name '{name}' must contain only ASCII letters, numbers, '.', '-', or '_'"
        )));
    }
    Ok(())
}

fn validate_descriptor_strings(
    descriptor: &ExtensionDescriptor,
) -> LifecycleResult<()> {
    for value in descriptor
        .provides
        .kernel_profiles
        .iter()
        .chain(descriptor.provides.guest_init_dropins.iter())
        .chain(descriptor.provides.launch_features.iter())
        .chain(descriptor.provides.host_resources.iter())
    {
        validate_extension_identifier(value).map_err(|err| {
            LifecycleError::new(format!(
                "lifecycle extension '{}' has invalid provided capability '{}': {err}",
                descriptor.name, value
            ))
        })?;
    }
    Ok(())
}

fn validate_extension_identifier(value: &str) -> Result<(), &'static str> {
    if value.is_empty() || value == "." || value == ".." {
        return Err("identifier is empty or reserved");
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.')
    {
        return Err("identifier must contain only ASCII letters, numbers, '.', '-', or '_'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Mutex;

    use super::*;

    #[derive(Debug)]
    struct RecordingExtension {
        name: String,
        configure_should_fail: bool,
        before_should_fail: bool,
        calls: Mutex<Vec<String>>,
    }

    impl RecordingExtension {
        fn new(name: &str) -> Arc<Self> {
            Arc::new(Self {
                name: name.to_string(),
                configure_should_fail: false,
                before_should_fail: false,
                calls: Mutex::new(Vec::new()),
            })
        }

        fn failing(name: &str) -> Arc<Self> {
            Arc::new(Self {
                name: name.to_string(),
                configure_should_fail: false,
                before_should_fail: true,
                calls: Mutex::new(Vec::new()),
            })
        }

        fn configure_failing(name: &str) -> Arc<Self> {
            Arc::new(Self {
                name: name.to_string(),
                configure_should_fail: true,
                before_should_fail: false,
                calls: Mutex::new(Vec::new()),
            })
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[tonic::async_trait]
    impl LifecycleExtension for RecordingExtension {
        fn name(&self) -> &str {
            &self.name
        }

        fn descriptor(&self) -> ExtensionDescriptor {
            ExtensionDescriptor {
                name: self.name.clone(),
                provides: ExtensionCapabilities {
                    kernel_profiles: vec![format!("profile-{}", self.name)],
                    guest_init_dropins: vec![format!("50-{}.sh", self.name)],
                    launch_features: vec!["guest-init-dropins".to_string()],
                    host_resources: Vec::new(),
                },
                required_backends: Vec::new(),
                required_backend_features: vec![BackendFeature::GuestInitDropins],
            }
        }

        async fn configure_launch(
            &self,
            _sandbox: &Sandbox,
            _state_dir: &Path,
            plan: &mut LaunchPlan,
        ) -> LifecycleResult<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{}:configure_launch", self.name));
            if self.configure_should_fail {
                return Err(LifecycleError::new(format!(
                    "{}: scripted configure_launch failure",
                    self.name
                )));
            }
            plan.kernel_profile = Some(format!("profile-{}", self.name));
            plan.guest_init_dropins.push(GuestInitDropin::new(
                format!("50-{}.sh", self.name),
                b"#!/bin/sh\n".to_vec(),
            ));
            Ok(())
        }

        async fn before_launch(
            &self,
            _sandbox: &Sandbox,
            _state_dir: &Path,
            plan: &mut LaunchPlan,
        ) -> LifecycleResult<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{}:before_launch", self.name));
            if self.before_should_fail {
                return Err(LifecycleError::new(format!(
                    "{}: scripted before_launch failure",
                    self.name
                )));
            }
            plan.env.push(format!("RECORDING_{}=1", self.name));
            Ok(())
        }

        async fn after_launch_failed(
            &self,
            _sandbox: &Sandbox,
            _state_dir: &Path,
            reason: LaunchAbortReason,
        ) -> LifecycleResult<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{}:after_launch_failed:{:?}", self.name, reason));
            Ok(())
        }

        async fn after_delete(
            &self,
            _sandbox: &Sandbox,
            _state_dir: &Path,
        ) -> LifecycleResult<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{}:after_delete", self.name));
            Ok(())
        }
    }

    fn sample_plan(backend: VmBackend) -> LaunchPlan {
        LaunchPlan {
            backend,
            vcpus: 2,
            mem_mib: 2048,
            required_backends: Vec::new(),
            required_backend_features: Vec::new(),
            kernel_profile: None,
            kernel_image: None,
            gpu_bdf: None,
            tap_device: None,
            guest_ip: None,
            host_ip: None,
            vsock_cid: None,
            guest_mac: None,
            gateway_port: None,
            guest_init_dropins: Vec::new(),
            env: Vec::new(),
        }
    }

    fn sample_sandbox() -> Sandbox {
        Sandbox {
            id: "sandbox-123".to_string(),
            name: "sandbox-123".to_string(),
            ..Default::default()
        }
    }

    fn as_extension<T>(extension: &Arc<T>) -> Arc<dyn LifecycleExtension>
    where
        T: LifecycleExtension + 'static,
    {
        extension.clone()
    }

    #[tokio::test]
    async fn configure_launch_runs_each_extension_in_order() {
        let ext_a = RecordingExtension::new("a");
        let ext_b = RecordingExtension::new("b");
        let registry =
            LifecycleExtensionRegistry::with(vec![as_extension(&ext_a), as_extension(&ext_b)]);
        let mut plan = sample_plan(VmBackend::Qemu);
        let sandbox = sample_sandbox();

        registry
            .configure_launch(&sandbox, &PathBuf::from("/tmp/state"), &mut plan)
            .await
            .expect("configure_launch succeeds");

        assert_eq!(plan.kernel_profile.as_deref(), Some("profile-b"));
        assert_eq!(
            plan.guest_init_dropins
                .iter()
                .map(|dropin| dropin.name.as_str())
                .collect::<Vec<_>>(),
            vec!["50-a.sh", "50-b.sh"]
        );
        assert_eq!(ext_a.calls(), vec!["a:configure_launch"]);
        assert_eq!(ext_b.calls(), vec!["b:configure_launch"]);
    }

    #[tokio::test]
    async fn configure_launch_short_circuits_on_first_failure() {
        let ext_a = RecordingExtension::new("a");
        let ext_fail = RecordingExtension::configure_failing("boom");
        let ext_c = RecordingExtension::new("c");
        let registry = LifecycleExtensionRegistry::with(vec![
            as_extension(&ext_a),
            as_extension(&ext_fail),
            as_extension(&ext_c),
        ]);
        let mut plan = sample_plan(VmBackend::Libkrun);
        let sandbox = sample_sandbox();

        let err = registry
            .configure_launch(&sandbox, &PathBuf::from("/tmp/state"), &mut plan)
            .await
            .expect_err("scripted failure should propagate");
        assert!(
            err.message()
                .contains("scripted configure_launch failure")
        );

        assert_eq!(ext_a.calls(), vec!["a:configure_launch"]);
        assert_eq!(ext_fail.calls(), vec!["boom:configure_launch"]);
        assert!(
            ext_c.calls().is_empty(),
            "extensions after the failure must not be invoked"
        );
    }

    #[tokio::test]
    async fn before_launch_runs_each_extension_in_order_and_collects_env() {
        let ext_a = RecordingExtension::new("a");
        let ext_b = RecordingExtension::new("b");
        let registry =
            LifecycleExtensionRegistry::with(vec![as_extension(&ext_a), as_extension(&ext_b)]);
        let mut plan = sample_plan(VmBackend::Qemu);
        let sandbox = sample_sandbox();

        registry
            .before_launch(&sandbox, &PathBuf::from("/tmp/state"), &mut plan)
            .await
            .expect("before_launch succeeds");

        assert_eq!(plan.env, vec!["RECORDING_a=1", "RECORDING_b=1"]);
        assert_eq!(ext_a.calls(), vec!["a:before_launch"]);
        assert_eq!(ext_b.calls(), vec!["b:before_launch"]);
    }

    #[tokio::test]
    async fn before_launch_short_circuits_on_first_failure() {
        let ext_a = RecordingExtension::new("a");
        let ext_fail = RecordingExtension::failing("boom");
        let ext_c = RecordingExtension::new("c");
        let registry = LifecycleExtensionRegistry::with(vec![
            as_extension(&ext_a),
            as_extension(&ext_fail),
            as_extension(&ext_c),
        ]);
        let mut plan = sample_plan(VmBackend::Libkrun);
        let sandbox = sample_sandbox();

        let err = registry
            .before_launch(&sandbox, &PathBuf::from("/tmp/state"), &mut plan)
            .await
            .expect_err("scripted failure should propagate");
        assert!(err.message().contains("scripted before_launch failure"));

        assert_eq!(ext_a.calls(), vec!["a:before_launch"]);
        assert_eq!(ext_fail.calls(), vec!["boom:before_launch"]);
        assert!(
            ext_c.calls().is_empty(),
            "extensions after the failure must not be invoked"
        );
    }

    #[tokio::test]
    async fn after_launch_failed_runs_every_extension_in_reverse_order() {
        let ext_a = RecordingExtension::new("a");
        let ext_b = RecordingExtension::new("b");
        let registry =
            LifecycleExtensionRegistry::with(vec![as_extension(&ext_a), as_extension(&ext_b)]);
        let sandbox = sample_sandbox();

        registry
            .after_launch_failed(
                &sandbox,
                &PathBuf::from("/tmp/state"),
                LaunchAbortReason::LauncherSpawnFailed,
            )
            .await;

        assert_eq!(
            ext_a.calls(),
            vec!["a:after_launch_failed:LauncherSpawnFailed"]
        );
        assert_eq!(
            ext_b.calls(),
            vec!["b:after_launch_failed:LauncherSpawnFailed"]
        );
    }

    #[tokio::test]
    async fn after_delete_runs_every_extension() {
        let ext_a = RecordingExtension::new("a");
        let ext_b = RecordingExtension::new("b");
        let registry =
            LifecycleExtensionRegistry::with(vec![as_extension(&ext_a), as_extension(&ext_b)]);
        let sandbox = sample_sandbox();

        registry
            .after_delete(&sandbox, &PathBuf::from("/tmp/state"))
            .await;

        assert_eq!(ext_a.calls(), vec!["a:after_delete"]);
        assert_eq!(ext_b.calls(), vec!["b:after_delete"]);
    }

    #[test]
    fn resource_exhausted_flag_round_trips() {
        let err = LifecycleError::resource_exhausted("pool empty");
        assert!(err.is_resource_exhausted());
        assert_eq!(err.message(), "pool empty");

        let plain = LifecycleError::new("internal");
        assert!(!plain.is_resource_exhausted());
    }

    #[test]
    fn extension_state_dir_rejects_path_unsafe_names() {
        let base = PathBuf::from("/tmp/sandbox");
        assert_eq!(
            extension_state_dir(&base, "vfio").unwrap(),
            base.join("extensions").join("vfio")
        );
        assert!(extension_state_dir(&base, "../vfio").is_err());
        assert!(extension_state_dir(&base, "").is_err());
    }

    #[test]
    fn validate_rejects_duplicate_extension_names() {
        let registry = LifecycleExtensionRegistry::with(vec![
            RecordingExtension::new("dup"),
            RecordingExtension::new("dup"),
        ]);
        let err = registry
            .validate()
            .expect_err("duplicate names should fail");
        assert!(err.message().contains("duplicate"));
    }

    #[test]
    fn descriptor_tracks_provided_capabilities_and_requirements() {
        let ext = RecordingExtension::new("vfio");
        let registry = LifecycleExtensionRegistry::with(vec![ext]);

        let descriptors = registry.descriptors();
        assert_eq!(descriptors.len(), 1);
        assert_eq!(descriptors[0].name, "vfio");
        assert!(descriptors[0].required_backends.is_empty());
        assert_eq!(
            descriptors[0].required_backend_features,
            vec![BackendFeature::GuestInitDropins]
        );
        assert_eq!(
            descriptors[0].provides.kernel_profiles,
            vec!["profile-vfio".to_string()]
        );
        assert_eq!(
            descriptors[0].provides.guest_init_dropins,
            vec!["50-vfio.sh".to_string()]
        );
    }
}
