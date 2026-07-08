// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use crate::e2e::{E2eSelection, E2eSuite};
use crate::platform::MachineOs;

const UBUNTU_OS_SETUP: &str = include_str!("../scripts/machine/os/ubuntu.sh");
const UBUNTU_DEVELOPMENT_SETUP: &str = include_str!("../scripts/machine/development/ubuntu.sh");
const UBUNTU_PODMAN_SETUP: &str = include_str!("../scripts/machine/suites/podman/ubuntu.sh");
const COMMON_PODMAN_SETUP: &str = include_str!("../scripts/machine/suites/podman/common.sh");
const UBUNTU_PODMAN_ROOTLESS_PREFLIGHT: &str =
    include_str!("../scripts/machine/validation/ubuntu-podman-rootless-preflight.sh");
const UBUNTU_APPARMOR_DIAGNOSTICS: &str =
    include_str!("../scripts/machine/validation/ubuntu-apparmor-diagnostics.sh");

pub(crate) fn run(selection: &E2eSelection, os: MachineOs) -> Result<ExitStatus, String> {
    let source = project_root().canonicalize().map_err(|error| {
        format!(
            "cannot resolve the OpenShell checkout at {}: {error}",
            project_root().display()
        )
    })?;
    let script = host_script(selection, os, &source)?;
    println!(
        "==> Preparing this host and running the {} e2e suite on {}",
        selection.suite().id(),
        os.id()
    );
    run_script(&script)
}

fn host_script(selection: &E2eSelection, os: MachineOs, source: &Path) -> Result<String, String> {
    let setup = match selection.suite() {
        E2eSuite::Podman => [
            UBUNTU_OS_SETUP,
            UBUNTU_DEVELOPMENT_SETUP,
            UBUNTU_PODMAN_SETUP,
            COMMON_PODMAN_SETUP,
        ]
        .join("\n"),
    };
    let selected_test = selection
        .test()
        .map_or_else(String::new, |test| format!(" --test {}", shell_quote(test)));
    let command = format!(
        "mise exec -- {}{selected_test}",
        shell_quote(selection.suite().script())
    );
    let invocation = format!(
        "{UBUNTU_PODMAN_ROOTLESS_PREFLIGHT}\n\
         set +e\n\
         {command}\n\
         e2e_status=$?\n\
         set -e\n\
         {UBUNTU_APPARMOR_DIAGNOSTICS}\n\
         exit \"${{e2e_status}}\""
    );

    Ok(format!(
        "export OPENSHELL_EXPECTED_OS={}\n\
         export OPENSHELL_SKIP_PODMAN_SOCKET=1\n\
         {setup}\n\
         if [ -n \"${{OPENSHELL_REGISTRY_HOST:-}}\" ] && \\
            [ -n \"${{OPENSHELL_REGISTRY_USERNAME:-}}\" ] && \\
            [ -n \"${{OPENSHELL_REGISTRY_PASSWORD:-}}\" ]; then\n\
           printf '%s' \"${{OPENSHELL_REGISTRY_PASSWORD}}\" | \\
             podman login \"${{OPENSHELL_REGISTRY_HOST}}\" \\
               --username \"${{OPENSHELL_REGISTRY_USERNAME}}\" --password-stdin\n\
         fi\n\
         cd {}\n\
         mise trust mise.toml\n\
         mise install --locked\n\
         {invocation}\n",
        shell_quote(os.id()),
        shell_quote_path(source)?,
    ))
}

fn run_script(script: &str) -> Result<ExitStatus, String> {
    let mut child = Command::new("bash")
        .arg("-s")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to start prepared-host e2e setup: {error}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "failed to open stdin for prepared-host e2e setup".to_owned())?
        .write_all(script.as_bytes())
        .map_err(|error| format!("failed to send prepared-host e2e setup: {error}"))?;
    child
        .wait()
        .map_err(|error| format!("failed to wait for prepared-host e2e: {error}"))
}

fn project_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
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

    fn podman_selection(test: Option<&str>) -> E2eSelection {
        E2eSelection {
            suite: E2eSuite::Podman,
            test: test.map(str::to_owned),
        }
    }

    #[test]
    fn composes_ubuntu_host_setup_before_the_test() {
        let script = host_script(
            &podman_selection(Some("smoke'name")),
            MachineOs::Ubuntu24_04,
            Path::new("/work/OpenShell"),
        )
        .expect("Ubuntu host setup should compose");

        let os_setup = script.find("Preparing Ubuntu").expect("OS setup");
        let development = script
            .find("Installing OpenShell development dependencies")
            .expect("development setup");
        let podman = script
            .find("Installing rootless Podman")
            .expect("Podman setup");
        let rootless = script
            .find("Preparing rootless Podman")
            .expect("rootless Podman setup");
        let preflight = script
            .find("Probing the rootless capability bounding set")
            .expect("rootless Podman preflight");
        let test = script
            .find("mise exec -- 'e2e/rust/e2e-podman.sh'")
            .expect("test invocation");
        let diagnostics = script
            .find("recent AppArmor denials")
            .expect("AppArmor diagnostics");
        assert!(os_setup < development);
        assert!(development < podman);
        assert!(podman < rootless);
        assert!(rootless < preflight);
        assert!(preflight < test);
        assert!(rootless < test);
        assert!(test < diagnostics);
        assert!(script.contains("export OPENSHELL_EXPECTED_OS='ubuntu-24.04'"));
        assert!(script.contains("export OPENSHELL_SKIP_PODMAN_SOCKET=1"));
        assert!(script.contains("mise exec -- 'e2e/rust/e2e-podman.sh' --test 'smoke'\"'\"'name'"));
        assert!(!script.contains("OPENSHELL_E2E_PODMAN_TEST"));
        assert!(!script.contains("Enabling the rootless Podman socket\nsudo loginctl"));
        assert!(script.contains("expected_podman_major=4"));
        assert!(script.contains("expected_podman_major=5"));
        assert!(script.contains("kernel.apparmor_restrict_unprivileged_userns"));
        assert!(script.contains("e2e/support/capbset-probe.c"));
    }

    #[test]
    fn conditionally_logs_into_the_registry_without_interpolating_secrets() {
        let script = host_script(
            &podman_selection(None),
            MachineOs::Ubuntu26_04,
            Path::new("/work/OpenShell"),
        )
        .expect("Ubuntu host setup should compose");

        assert!(script.contains("[ -n \"${OPENSHELL_REGISTRY_PASSWORD:-}\" ]"));
        assert!(script.contains("printf '%s' \"${OPENSHELL_REGISTRY_PASSWORD}\""));
        assert!(script.contains("--password-stdin"));
    }

    #[test]
    fn generated_host_scripts_are_valid_bash() {
        for os in [MachineOs::Ubuntu24_04, MachineOs::Ubuntu26_04] {
            let script = host_script(&podman_selection(Some("smoke")), os, Path::new("/work"))
                .expect("host setup should compose");
            let status = Command::new("bash")
                .args(["-n", "-c", &script])
                .status()
                .expect("bash syntax validation should run");
            assert!(status.success(), "generated script for {}", os.id());
        }
    }
}
