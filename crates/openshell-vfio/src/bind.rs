// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::VfioError;
use crate::sysfs::{SysfsRoot, write_sysfs};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

pub(crate) const VFIO_BIND_POLL_INTERVAL: Duration = Duration::from_millis(100);
pub(crate) const VFIO_BIND_MAX_POLL_ATTEMPTS: u32 = 20;

// Process-local registry shared across bind guards to coordinate vfio-pci ID writes.
static VFIO_ID_REGISTRY: LazyLock<Mutex<VfioIdRegistry>> =
    LazyLock::new(|| Mutex::new(VfioIdRegistry::default()));

pub(crate) fn current_driver_name(sysfs: &SysfsRoot, bdf: &str) -> Option<String> {
    sysfs.pci_device_ref(bdf).driver_name()
}

/// Read vendor and device IDs from sysfs and format as `"VVVV DDDD"` (no `0x` prefix).
pub(crate) fn vfio_id_string(sysfs: &SysfsRoot, bdf: &str) -> Option<String> {
    sysfs.pci_device_ref(bdf).vfio_id_string()
}

/// Best-effort registration of a device's vendor:device ID with `vfio-pci`.
///
/// Some kernel configurations require the ID to be pre-registered in
/// `/sys/bus/pci/drivers/vfio-pci/new_id` before `drivers_probe` will bind
/// the device, even when `driver_override` is set. Writing an already
/// registered ID returns `EEXIST`, which we silently ignore.
pub(crate) fn register_vfio_new_id(sysfs: &SysfsRoot, bdf: &str) {
    let Some(id_str) = vfio_id_string(sysfs, bdf) else {
        return;
    };

    let registration = VFIO_ID_REGISTRY.lock().unwrap().register(&id_str);

    if registration != VfioIdRegistration::FirstUser {
        tracing::debug!(
            bdf, id = %id_str,
            "vfio-pci new_id already registered by another device, refcount incremented"
        );
        return;
    }

    let new_id_path = sysfs.vfio_pci_new_id();
    match write_sysfs(&new_id_path, &id_str) {
        Ok(()) => {
            tracing::debug!(bdf, id = %id_str, "registered vfio-pci new_id");
        }
        Err(_) => {
            tracing::debug!(
                bdf, id = %id_str,
                "vfio-pci new_id write skipped (already registered or driver not loaded)"
            );
        }
    }
}

/// Best-effort deregistration of a device's vendor:device ID from `vfio-pci`.
///
/// Reverses the effect of [`register_vfio_new_id`] by writing to
/// `/sys/bus/pci/drivers/vfio-pci/remove_id`. This prevents vfio-pci from
/// winning the probe race against the host driver when `drivers_probe` runs
/// during restore.
///
/// `ENODEV` is silently ignored (the ID may never have been registered or was
/// already removed).
pub(crate) fn deregister_vfio_new_id(sysfs: &SysfsRoot, bdf: &str) {
    let Some(id_str) = vfio_id_string(sysfs, bdf) else {
        return;
    };

    deregister_vfio_id(sysfs, &id_str, Some(bdf));
}

fn deregister_vfio_id(sysfs: &SysfsRoot, id_str: &str, bdf: Option<&str>) {
    let deregistration = VFIO_ID_REGISTRY.lock().unwrap().deregister(id_str);

    if deregistration == VfioIdDeregistration::StillInUse {
        tracing::debug!(
            bdf = ?bdf, id = %id_str,
            "vfio-pci remove_id skipped (other devices still using this ID)"
        );
        return;
    }

    // LastUser and NotTracked both require a best-effort remove_id write.
    let remove_id_path = sysfs.vfio_pci_remove_id();
    match write_sysfs(&remove_id_path, id_str) {
        Ok(()) => {
            tracing::debug!(bdf = ?bdf, id = %id_str, "deregistered vfio-pci new_id");
        }
        Err(_) => {
            tracing::debug!(
                bdf = ?bdf, id = %id_str,
                "vfio-pci remove_id write skipped (not registered or already removed)"
            );
        }
    }
}

/// Best-effort deregistration using a pre-captured ID string.
///
/// Unlike [`deregister_vfio_new_id`], this does not read vendor/device from
/// sysfs at call time, making it reliable even when the device has been
/// physically removed or sysfs is otherwise inaccessible.
pub(crate) fn deregister_vfio_id_by_value(sysfs: &SysfsRoot, id_str: &str) {
    deregister_vfio_id(sysfs, id_str, None);
}

pub(crate) fn clear_vfio_id_refcounts() {
    if let Ok(mut registry) = VFIO_ID_REGISTRY.lock() {
        registry.clear();
    }
}

/// Best-effort rollback of partial bind state. Clears `driver_override` and
/// re-probes so the kernel re-attaches the host driver. Used on failure paths
/// in [`bind_device_to_vfio`] after `driver_override` has been pinned to
/// `vfio-pci` but the bind did not complete; without this the device is left
/// with `driver_override=vfio-pci` and would silently re-bind to vfio-pci on
/// the next probe event.
fn cleanup_partial_bind(sysfs: &SysfsRoot, bdf: &str) {
    let device = sysfs.pci_device_ref(bdf);
    if device.driver_override_path().exists()
        && let Err(err) = device.clear_driver_override()
    {
        tracing::warn!(bdf, %err, "failed to clear driver_override during bind rollback");
    }
    let probe = sysfs.drivers_probe();
    if probe.exists()
        && let Err(err) = write_sysfs(&probe, bdf)
    {
        tracing::warn!(bdf, %err, "failed to re-probe during bind rollback");
    }
}

/// Bind a single PCI device to `vfio-pci`. Skips devices already bound.
pub(crate) fn bind_device_to_vfio(sysfs: &SysfsRoot, bdf: &str) -> Result<bool, VfioError> {
    if let Some(drv) = current_driver_name(sysfs, bdf) {
        if drv == "vfio-pci" {
            return Ok(false);
        }
        let unbind_path = sysfs.pci_device_ref(bdf).driver_unbind_path();
        write_sysfs(&unbind_path, bdf).map_err(|e| VfioError::BindFailed {
            bdf: bdf.to_string(),
            reason: format!("unbind from {drv}: {e}"),
        })?;
        tracing::info!(bdf, driver = %drv, "unbound device from current driver");
    }

    register_vfio_new_id(sysfs, bdf);

    let override_path = sysfs.pci_device_ref(bdf).driver_override_path();
    if let Err(e) = write_sysfs(&override_path, "vfio-pci") {
        deregister_vfio_new_id(sysfs, bdf);
        return Err(VfioError::BindFailed {
            bdf: bdf.to_string(),
            reason: format!("driver_override: {e}"),
        });
    }

    if let Err(e) = write_sysfs(&sysfs.drivers_probe(), bdf) {
        deregister_vfio_new_id(sysfs, bdf);
        cleanup_partial_bind(sysfs, bdf);
        return Err(VfioError::BindFailed {
            bdf: bdf.to_string(),
            reason: format!("drivers_probe: {e}"),
        });
    }

    if matches!(current_driver_name(sysfs, bdf).as_deref(), Some("vfio-pci")) {
        return Ok(true);
    }

    // The kernel processes drivers_probe asynchronously on some systems; poll
    // briefly to let the driver attach before declaring failure.
    for _ in 0..VFIO_BIND_MAX_POLL_ATTEMPTS {
        std::thread::sleep(VFIO_BIND_POLL_INTERVAL);
        if matches!(current_driver_name(sysfs, bdf).as_deref(), Some("vfio-pci")) {
            tracing::debug!(bdf, "vfio-pci binding confirmed after polling");
            return Ok(true);
        }
    }

    deregister_vfio_new_id(sysfs, bdf);
    cleanup_partial_bind(sysfs, bdf);
    Err(VfioError::BindFailed {
        bdf: bdf.to_string(),
        reason: format!(
            "after drivers_probe with {}ms polling, driver is {:?} instead of vfio-pci",
            u64::from(VFIO_BIND_MAX_POLL_ATTEMPTS)
                * u64::try_from(VFIO_BIND_POLL_INTERVAL.as_millis()).unwrap_or(u64::MAX),
            current_driver_name(sysfs, bdf)
                .as_deref()
                .unwrap_or("<none>")
        ),
    })
}

/// Restore a PCI device from `vfio-pci` back to the host's default driver.
pub(crate) fn restore_to_host_driver(sysfs: &SysfsRoot, bdf: &str) -> Result<(), VfioError> {
    restore_to_host_driver_ex(sysfs, bdf, false)
}

/// Inner restore implementation.
///
/// When `skip_deregister` is `true` the caller has already removed the
/// device's vendor:device ID from vfio-pci's match table (e.g. via a cached
/// value), so we skip the sysfs-based deregistration.
pub(crate) fn restore_to_host_driver_ex(
    sysfs: &SysfsRoot,
    bdf: &str,
    skip_deregister: bool,
) -> Result<(), VfioError> {
    let device = sysfs.pci_device_ref(bdf);

    if !skip_deregister {
        // Deregister the device ID from vfio-pci's match table before
        // unbind+reprobe. Without this, drivers_probe re-binds to vfio-pci
        // via the still-registered new_id entry.
        deregister_vfio_new_id(sysfs, bdf);
    }

    let unbind_path = device.driver_unbind_path();
    if unbind_path.exists() {
        write_sysfs(&unbind_path, bdf).map_err(|e| VfioError::UnbindFailed {
            bdf: bdf.to_string(),
            reason: format!("unbind: {e}"),
        })?;
    }

    if device.driver_override_path().exists() {
        device
            .clear_driver_override()
            .map_err(|e| VfioError::UnbindFailed {
                bdf: bdf.to_string(),
                reason: format!("clear driver_override: {e}"),
            })?;
    }

    let probe = sysfs.drivers_probe();
    if probe.exists() {
        write_sysfs(&probe, bdf).map_err(|e| VfioError::UnbindFailed {
            bdf: bdf.to_string(),
            reason: format!("drivers_probe: {e}"),
        })?;
    }

    tracing::info!(bdf, "PCI device restored to host driver");
    Ok(())
}

/// Process-local reference counter for vendor:device ID registrations in the
/// vfio-pci match table. Multiple devices may share the same vendor:device
/// pair. We only write to the kernel's `new_id`/`remove_id` sysfs files when
/// the first device registers or the last device deregisters an ID.
#[derive(Debug, Default)]
struct VfioIdRegistry {
    refcounts: HashMap<String, usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VfioIdRegistration {
    FirstUser,
    AlreadyTracked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VfioIdDeregistration {
    LastUser,
    StillInUse,
    NotTracked,
}

impl VfioIdRegistry {
    /// Record one active user of `id`.
    ///
    /// Returns the resulting process-local registration state.
    fn register(&mut self, id: &str) -> VfioIdRegistration {
        let count = self.refcounts.entry(id.to_string()).or_insert(0);
        *count += 1;
        if *count == 1 {
            VfioIdRegistration::FirstUser
        } else {
            VfioIdRegistration::AlreadyTracked
        }
    }

    /// Record one fewer active user of `id`.
    ///
    /// Returns the resulting process-local deregistration state.
    fn deregister(&mut self, id: &str) -> VfioIdDeregistration {
        match self.refcounts.get_mut(id) {
            Some(count) if *count > 1 => {
                *count -= 1;
                VfioIdDeregistration::StillInUse
            }
            Some(_) => {
                self.refcounts.remove(id);
                VfioIdDeregistration::LastUser
            }
            None => VfioIdDeregistration::NotTracked,
        }
    }

    fn clear(&mut self) {
        self.refcounts.clear();
    }

    #[cfg(test)]
    fn remove(&mut self, id: &str) {
        self.refcounts.remove(id);
    }
}

#[cfg(test)]
pub(crate) mod test_refcounts {
    use super::VFIO_ID_REGISTRY;
    use std::sync::{Mutex, MutexGuard, PoisonError};

    static VFIO_ID_REFCOUNT_TEST_LOCK: Mutex<()> = Mutex::new(());

    pub fn guard() -> MutexGuard<'static, ()> {
        VFIO_ID_REFCOUNT_TEST_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Remove a specific vendor:device key from the global refcount map.
    /// Used by tests to clean up their own entries without disturbing
    /// parallel tests that hold refcounts for different device IDs.
    pub fn clear(id: &str) {
        VFIO_ID_REGISTRY.lock().unwrap().remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        create_new_id_file, create_pci_device, create_probe_file, create_remove_id_file,
        set_mock_driver, setup_mock_sysfs,
    };
    use std::fs;

    #[test]
    fn test_register_vfio_new_id_writes_vendor_device() {
        let _refcount_guard = test_refcounts::guard();
        test_refcounts::clear("10de 26b3");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:2d:00.0",
            "0x10de",
            "0x26b3",
            "0x030000",
            42,
        );
        create_new_id_file(&sysfs);

        register_vfio_new_id(&sysfs, "0000:2d:00.0");

        let written = fs::read_to_string(sysfs.vfio_pci_new_id()).unwrap();
        assert_eq!(written, "10de 26b3");
    }

    #[test]
    fn test_register_vfio_new_id_ignores_missing_new_id_file() {
        let _refcount_guard = test_refcounts::guard();
        test_refcounts::clear("10de 26b4");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:2d:00.0",
            "0x10de",
            "0x26b4",
            "0x030000",
            42,
        );

        register_vfio_new_id(&sysfs, "0000:2d:00.0");
    }

    #[test]
    fn test_deregister_vfio_new_id_writes_vendor_device() {
        let _refcount_guard = test_refcounts::guard();
        test_refcounts::clear("10de 26b5");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:2d:00.0",
            "0x10de",
            "0x26b5",
            "0x030000",
            42,
        );
        create_remove_id_file(&sysfs);

        deregister_vfio_new_id(&sysfs, "0000:2d:00.0");

        let written = fs::read_to_string(sysfs.vfio_pci_remove_id()).unwrap();
        assert_eq!(written, "10de 26b5");
    }

    #[test]
    fn test_deregister_vfio_new_id_ignores_missing_remove_id_file() {
        let _refcount_guard = test_refcounts::guard();
        test_refcounts::clear("10de 26b6");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:2d:00.0",
            "0x10de",
            "0x26b6",
            "0x030000",
            42,
        );

        deregister_vfio_new_id(&sysfs, "0000:2d:00.0");
    }

    #[test]
    fn test_register_deregister_refcount() {
        let _refcount_guard = test_refcounts::guard();
        test_refcounts::clear("10de 26b8");
        let (tmp, sysfs) = setup_mock_sysfs();

        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:2d:00.0",
            "0x10de",
            "0x26b8",
            "0x030000",
            42,
        );
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:3b:00.0",
            "0x10de",
            "0x26b8",
            "0x030200",
            43,
        );
        create_new_id_file(&sysfs);
        create_remove_id_file(&sysfs);

        register_vfio_new_id(&sysfs, "0000:2d:00.0");
        let written = fs::read_to_string(sysfs.vfio_pci_new_id()).unwrap();
        assert_eq!(
            written, "10de 26b8",
            "first register should write to new_id"
        );

        fs::write(sysfs.vfio_pci_new_id(), "").unwrap();
        register_vfio_new_id(&sysfs, "0000:3b:00.0");
        let written = fs::read_to_string(sysfs.vfio_pci_new_id()).unwrap();
        assert_eq!(
            written, "",
            "second register should not write to new_id when refcount > 1"
        );

        deregister_vfio_new_id(&sysfs, "0000:2d:00.0");
        let written = fs::read_to_string(sysfs.vfio_pci_remove_id()).unwrap();
        assert_eq!(
            written, "",
            "first deregister should not write to remove_id"
        );

        deregister_vfio_new_id(&sysfs, "0000:3b:00.0");
        let written = fs::read_to_string(sysfs.vfio_pci_remove_id()).unwrap();
        assert_eq!(
            written, "10de 26b8",
            "second deregister should write to remove_id"
        );
    }

    #[test]
    fn test_deregister_by_cached_value_updates_refcount() {
        let _refcount_guard = test_refcounts::guard();
        test_refcounts::clear("10de 26ba");
        let (tmp, sysfs) = setup_mock_sysfs();

        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:2d:00.0",
            "0x10de",
            "0x26ba",
            "0x030000",
            42,
        );
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:3b:00.0",
            "0x10de",
            "0x26ba",
            "0x030200",
            43,
        );
        create_new_id_file(&sysfs);
        create_remove_id_file(&sysfs);

        register_vfio_new_id(&sysfs, "0000:2d:00.0");
        register_vfio_new_id(&sysfs, "0000:3b:00.0");

        deregister_vfio_id_by_value(&sysfs, "10de 26ba");
        let written = fs::read_to_string(sysfs.vfio_pci_remove_id()).unwrap();
        assert_eq!(
            written, "",
            "cached deregister should respect remaining refcount users"
        );

        deregister_vfio_new_id(&sysfs, "0000:3b:00.0");
        let written = fs::read_to_string(sysfs.vfio_pci_remove_id()).unwrap();
        assert_eq!(
            written, "10de 26ba",
            "final deregister should write remove_id after cached release decremented refcount"
        );
    }

    #[test]
    fn test_bind_device_to_vfio_already_bound() {
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:2d:00.0",
            "0x10de",
            "0x2684",
            "0x030000",
            42,
        );
        create_probe_file(&sysfs);
        set_mock_driver(&sysfs, "0000:2d:00.0", "vfio-pci");

        let was_bound = bind_device_to_vfio(&sysfs, "0000:2d:00.0").unwrap();
        assert!(!was_bound, "should report false when already on vfio-pci");
    }

    #[test]
    fn test_bind_failure_clears_driver_override() {
        // Simulate drivers_probe being unavailable: bind_device_to_vfio
        // writes driver_override successfully but the probe write fails.
        // The rollback must clear driver_override so the device is not
        // wedged with vfio-pci pinned in the override.
        let _refcount_guard = test_refcounts::guard();
        test_refcounts::clear("10de 26b9");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:2d:00.0",
            "0x10de",
            "0x26b9",
            "0x030000",
            42,
        );
        // Deliberately do NOT create the drivers_probe file - the write to
        // it will fail with ENOENT, hitting the failure path under test.
        create_new_id_file(&sysfs);
        create_remove_id_file(&sysfs);
        set_mock_driver(&sysfs, "0000:2d:00.0", "nvidia");

        let err = bind_device_to_vfio(&sysfs, "0000:2d:00.0").unwrap_err();
        assert!(matches!(err, VfioError::BindFailed { .. }));

        let override_val =
            fs::read_to_string(sysfs.pci_device("0000:2d:00.0").join("driver_override")).unwrap();
        assert_eq!(
            override_val.trim(),
            "",
            "driver_override must be cleared when drivers_probe fails"
        );
    }

    #[test]
    fn test_restore_deregisters_new_id_before_reprobe() {
        let _refcount_guard = test_refcounts::guard();
        test_refcounts::clear("10de 26b7");
        let (tmp, sysfs) = setup_mock_sysfs();
        create_pci_device(
            &sysfs,
            tmp.path(),
            "0000:2d:00.0",
            "0x10de",
            "0x26b7",
            "0x030000",
            42,
        );
        create_probe_file(&sysfs);
        create_remove_id_file(&sysfs);
        set_mock_driver(&sysfs, "0000:2d:00.0", "vfio-pci");
        fs::write(
            sysfs.pci_device("0000:2d:00.0").join("driver_override"),
            "vfio-pci",
        )
        .unwrap();

        restore_to_host_driver(&sysfs, "0000:2d:00.0").unwrap();

        let written = fs::read_to_string(sysfs.vfio_pci_remove_id()).unwrap();
        assert_eq!(
            written, "10de 26b7",
            "remove_id should be written during restore"
        );
    }
}
