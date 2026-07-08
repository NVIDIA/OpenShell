// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use crate::e2e::{E2eSelection, E2eSuite};
use crate::machine::{
    HostMount, MachineOptions, MachineProvider, MachineRequest, PersistentDisk, path_hash,
    stable_hash,
};
use crate::platform::{Arch, MachineOs, OsFamily};

const CENTOS_STREAM_OS_SETUP: &str = include_str!("../scripts/machine/os/centos-stream.sh");
const UBUNTU_OS_SETUP: &str = include_str!("../scripts/machine/os/ubuntu.sh");
const CENTOS_STREAM_DEVELOPMENT_SETUP: &str =
    include_str!("../scripts/machine/development/centos-stream.sh");
const UBUNTU_DEVELOPMENT_SETUP: &str = include_str!("../scripts/machine/development/ubuntu.sh");
const COMMON_DEVELOPMENT_SETUP: &str = include_str!("../scripts/machine/development/common.sh");
const CENTOS_STREAM_PODMAN_SETUP: &str =
    include_str!("../scripts/machine/suites/podman/centos-stream.sh");
const UBUNTU_PODMAN_SETUP: &str = include_str!("../scripts/machine/suites/podman/ubuntu.sh");
const COMMON_PODMAN_SETUP: &str = include_str!("../scripts/machine/suites/podman/common.sh");
const SELINUX_AUDIT_VALIDATION: &str =
    include_str!("../scripts/machine/validation/selinux-audit.sh");
const SYNC_DEVELOPMENT_SOURCE: &str = include_str!("../scripts/sync-development-source.sh");
const MISE_TOML: &[u8] = include_bytes!("../../../mise.toml");
const MISE_LOCK: &[u8] = include_bytes!("../../../mise.lock");
const GUEST_SOURCE_DIR: &str = "${HOME}/.local/share/openshell-e2e/source";

fn host_arch() -> Result<Arch, String> {
    match env::consts::ARCH {
        "x86_64" => Ok(Arch::Amd64),
        "aarch64" => Ok(Arch::Arm64),
        arch => Err(format!(
            "unsupported host architecture: {arch} (pass --arch amd64 or --arch arm64)"
        )),
    }
}

pub(crate) fn run(
    selection: &E2eSelection,
    options: &MachineOptions,
) -> Result<ExitStatus, String> {
    run_with_provider(&options.provider, selection, options)
}

fn run_with_provider<P: MachineProvider>(
    provider: &P,
    selection: &E2eSelection,
    options: &MachineOptions,
) -> Result<ExitStatus, String> {
    let source = project_root().canonicalize().map_err(|error| {
        format!(
            "cannot resolve the OpenShell checkout at {}: {error}",
            project_root().display()
        )
    })?;
    if !source.join("mise.toml").is_file() {
        return Err(format!(
            "OpenShell checkout is missing mise.toml: {}",
            source.display()
        ));
    }

    let arch = options.arch.map_or_else(host_arch, Ok)?;
    let cache_disk = options
        .snapshot
        .then(|| development_cache_disk(options.os, arch, selection.suite(), &source));
    let cache_mount = cache_disk
        .as_ref()
        .map(|disk| provider.persistent_disk_mount_point(disk));
    let setup_script = development_setup_script(
        options.os,
        selection.suite(),
        &source,
        cache_mount.as_deref(),
    )?;
    let test_script = e2e_guest_script(selection, options.os, &source, cache_mount.as_deref())?;
    let machine = provider.acquire(
        MachineRequest {
            os: options.os,
            arch,
            purpose: "e2e",
            profile: selection.suite().id(),
            forward_env: vec!["MISE_GITHUB_TOKEN"],
            keep_on_failure: options.keep,
            reuse: options.reuse_policy(stable_hash(&[MISE_TOML, MISE_LOCK])),
            host_mounts: vec![HostMount::read_only(&source)],
            persistent_disks: cache_disk.into_iter().collect(),
        },
        &setup_script,
    )?;

    println!(
        "==> Running {} e2e suite on {} with {}",
        selection.suite().id(),
        options.os.id(),
        machine.name()
    );
    let test_result = machine.run_script(&test_script, "e2e test");

    if options.keep {
        eprintln!("Machine kept for inspection: {}", machine.name());
        return test_result;
    }

    let release_result = machine.release();
    match (test_result, release_result) {
        (Ok(status), Ok(())) => Ok(status),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(release_error)) => {
            Err(format!("{error}; release also failed: {release_error}"))
        }
        (Ok(status), Err(error)) if status.success() => Err(error),
        (Ok(status), Err(error)) => {
            eprintln!("warning: {error}");
            Ok(status)
        }
    }
}

fn project_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn development_cache_disk(
    os: MachineOs,
    arch: Arch,
    suite: E2eSuite,
    source: &Path,
) -> PersistentDisk {
    let arch = match arch {
        Arch::Amd64 => "x64",
        Arch::Arm64 => "a64",
    };
    PersistentDisk::ext4(
        format!(
            "os-e2e-cache-{}-{}-{arch}-{:08x}",
            os.short_name(),
            suite.id(),
            path_hash(source)
        ),
        "50GiB",
    )
}

fn development_setup_script(
    os: MachineOs,
    suite: E2eSuite,
    source: &Path,
    cache_mount: Option<&str>,
) -> Result<String, String> {
    let mut scripts = os_setup_scripts(os);
    scripts.extend(development_setup_scripts(os));
    scripts.extend(suite_setup_scripts(suite, os));
    scripts.push(COMMON_DEVELOPMENT_SETUP);
    scripts.push(SYNC_DEVELOPMENT_SOURCE);

    Ok(format!(
        "{}\n{}\n\
         export PATH=\"${{HOME}}/.local/bin:${{HOME}}/.local/share/mise/shims:${{PATH}}\"\n\
         cd \"${{OPENSHELL_GUEST_SOURCE_DIR}}\"\n\
         mise trust mise.toml\n\
         mise install --locked\n\
         mise reshim\n",
        guest_environment(source, cache_mount)?,
        scripts.join("\n")
    ))
}

fn os_setup_scripts(os: MachineOs) -> Vec<&'static str> {
    match os.family() {
        OsFamily::CentosStream => vec![CENTOS_STREAM_OS_SETUP],
        OsFamily::Ubuntu => vec![UBUNTU_OS_SETUP],
    }
}

fn development_setup_scripts(os: MachineOs) -> Vec<&'static str> {
    match os.family() {
        OsFamily::CentosStream => vec![CENTOS_STREAM_DEVELOPMENT_SETUP],
        OsFamily::Ubuntu => vec![UBUNTU_DEVELOPMENT_SETUP],
    }
}

fn suite_setup_scripts(suite: E2eSuite, os: MachineOs) -> Vec<&'static str> {
    match (suite, os.family()) {
        (E2eSuite::Podman, OsFamily::CentosStream) => {
            vec![CENTOS_STREAM_PODMAN_SETUP, COMMON_PODMAN_SETUP]
        }
        (E2eSuite::Podman, OsFamily::Ubuntu) => {
            vec![UBUNTU_PODMAN_SETUP, COMMON_PODMAN_SETUP]
        }
    }
}

fn e2e_guest_script(
    selection: &E2eSelection,
    os: MachineOs,
    source: &Path,
    cache_mount: Option<&str>,
) -> Result<String, String> {
    let test = selection
        .test()
        .map_or_else(String::new, |test| format!(" --test {}", shell_quote(test)));
    let command = format!(
        "cargo xtask e2e --suite {}{test}",
        shell_quote(selection.suite().id())
    );
    let invocation = match os.family() {
        OsFamily::CentosStream => format!(
            "export OPENSHELL_SELINUX_AUDIT_START=\"$(date -u '+%m/%d/%Y %H:%M:%S')\"\n\
             set +e\n\
             {command}\n\
             e2e_status=$?\n\
             set -e\n\
             {SELINUX_AUDIT_VALIDATION}\n\
             exit \"${{e2e_status}}\""
        ),
        OsFamily::Ubuntu => format!("exec {command}"),
    };
    Ok(format!(
        "{}\n\
         {SYNC_DEVELOPMENT_SOURCE}\n\
         export PATH=\"${{HOME}}/.local/bin:${{HOME}}/.local/share/mise/shims:${{PATH}}\"\n\
         cd \"${{OPENSHELL_GUEST_SOURCE_DIR}}\"\n\
         mise trust mise.toml\n\
         mise install --locked\n\
         {invocation}\n",
        guest_environment(source, cache_mount)?,
    ))
}

fn guest_environment(source: &Path, cache_mount: Option<&str>) -> Result<String, String> {
    let cache_environment = if let Some(mount_point) = cache_mount {
        format!(
            "export OPENSHELL_CACHE_DISK='{}'\n\
             export CARGO_TARGET_DIR=\"${{OPENSHELL_CACHE_DISK}}/cargo-target\"",
            mount_point
        )
    } else {
        "export OPENSHELL_CACHE_DISK=\"${OPENSHELL_GUEST_SOURCE_DIR}/.cache\"\n\
         export CARGO_TARGET_DIR=\"${OPENSHELL_GUEST_SOURCE_DIR}/target\""
            .to_owned()
    };
    Ok(format!(
        "export OPENSHELL_SOURCE_MOUNT={}\n\
         export OPENSHELL_GUEST_SOURCE_DIR=\"{GUEST_SOURCE_DIR}\"\n\
         {cache_environment}",
        shell_quote_path(source)?
    ))
}

fn shell_quote_path(path: &Path) -> Result<String, String> {
    let value = path
        .to_str()
        .ok_or_else(|| format!("source path is not valid UTF-8: {}", path.display()))?;
    Ok(shell_quote(value))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::Provider;

    #[test]
    fn composes_setup_and_delegates_to_the_local_runner() {
        let source = Path::new("/Volumes/work/OpenShell");
        let cache_disk = development_cache_disk(
            MachineOs::Ubuntu24_04,
            Arch::Arm64,
            E2eSuite::Podman,
            source,
        );
        assert_eq!(cache_disk.size, "50GiB");
        assert_eq!(cache_disk.filesystem, "ext4");
        assert_eq!(
            cache_disk.name,
            "os-e2e-cache-ubuntu2404-podman-a64-7e4fa9a2"
        );
        let cache_mount = Provider::Lima.persistent_disk_mount_point(&cache_disk);

        let setup = development_setup_script(
            MachineOs::Ubuntu24_04,
            E2eSuite::Podman,
            source,
            Some(&cache_mount),
        )
        .expect("setup should be supported");
        let os_index = setup.find("Preparing Ubuntu").expect("OS setup");
        let development_index = setup
            .find("Installing OpenShell development dependencies")
            .expect("development setup");
        let podman_index = setup
            .find("Installing rootless Podman")
            .expect("Podman setup");
        let podman_activation_index = setup
            .find("Enabling the rootless Podman socket")
            .expect("Podman common setup");
        assert!(setup.contains("log_driver = \"k8s-file\""));
        assert!(setup.contains("events_logger = \"file\""));
        let mise_index = setup.find("Installing mise").expect("mise setup");
        assert!(os_index < development_index);
        assert!(development_index < podman_index);
        assert!(podman_index < podman_activation_index);
        assert!(podman_activation_index < mise_index);

        let selection = E2eSelection {
            suite: E2eSuite::Podman,
            test: Some("smoke".to_owned()),
        };
        let test = e2e_guest_script(
            &selection,
            MachineOs::Ubuntu24_04,
            source,
            Some(&cache_mount),
        )
        .expect("test should be supported");
        assert!(test.contains("exec cargo xtask e2e --suite 'podman' --test 'smoke'"));
        assert!(!test.contains("OPENSHELL_E2E_PODMAN_TEST"));
        assert!(test.contains("export OPENSHELL_SOURCE_MOUNT='/Volumes/work/OpenShell'"));
        assert!(test.contains(
            "export OPENSHELL_CACHE_DISK='/mnt/lima-os-e2e-cache-ubuntu2404-podman-a64-7e4fa9a2'"
        ));
    }

    #[test]
    fn composes_a_podman_only_centos_stream_selinux_target() {
        let source = Path::new("/Volumes/work/OpenShell");
        let setup =
            development_setup_script(MachineOs::CentosStream10, E2eSuite::Podman, source, None)
                .expect("CentOS Stream setup should be supported");

        let os_index = setup
            .find("Preparing ${PRETTY_NAME:-CentOS Stream 10}")
            .expect("CentOS Stream OS setup");
        let development_index = setup
            .find("Installing OpenShell development dependencies on CentOS Stream")
            .expect("CentOS Stream development setup");
        let z3_index = setup
            .find("Installing Z3 ${z3_version} for OpenShell development")
            .expect("CentOS Stream Z3 setup");
        let podman_index = setup
            .find("Installing rootless Podman on CentOS Stream")
            .expect("CentOS Stream Podman setup");
        let podman_activation_index = setup
            .find("Enabling the rootless Podman socket")
            .expect("common Podman setup");
        assert!(os_index < development_index);
        assert!(development_index < z3_index);
        assert!(z3_index < podman_index);
        assert!(podman_index < podman_activation_index);
        assert!(setup.contains("SELinux must be Enforcing"));
        assert!(!setup.contains("z3-devel"));
        assert!(!setup.contains("dockerd"));
        assert!(!setup.contains("docker.service"));
        assert!(setup.contains("containers.conf.d"));
        assert!(setup.contains("99-openshell.conf"));

        let selection = E2eSelection {
            suite: E2eSuite::Podman,
            test: None,
        };
        let test = e2e_guest_script(&selection, MachineOs::CentosStream10, source, None)
            .expect("CentOS Stream test should be supported");
        assert!(test.contains("cargo xtask e2e --suite 'podman'"));
        assert!(!test.contains("exec cargo xtask e2e"));
        assert!(test.contains("OPENSHELL_SELINUX_AUDIT_START"));
        assert!(test.contains("ausearch"));
        assert!(test.contains("exit \"${e2e_status}\""));
    }

    #[test]
    fn quotes_source_paths_and_test_names_for_the_guest_shell() {
        assert_eq!(
            shell_quote_path(Path::new("/tmp/source'checkout")).expect("path should quote"),
            "'/tmp/source'\"'\"'checkout'"
        );
        assert_eq!(shell_quote("test'name"), "'test'\"'\"'name'");
    }
}
