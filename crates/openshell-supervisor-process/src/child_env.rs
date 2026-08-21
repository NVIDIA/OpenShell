// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
use std::path::Path;

use openshell_core::policy::SandboxPolicy;

const LOCAL_NO_PROXY: &str = "127.0.0.1,localhost,::1";
pub const DEFAULT_CHILD_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
const STANDARD_SBIN_PATHS: &[&str] = &["/usr/local/sbin", "/usr/sbin", "/sbin"];
const ENSURE_STANDARD_SBIN_PATHS_SCRIPT: &str = "for dir in /usr/local/sbin /usr/sbin /sbin; do case \":${PATH:-}:\" in *:\"$dir\":*) ;; *) PATH=\"${PATH:+$PATH:}$dir\" ;; esac; done; export PATH";
const STARTUP_SNIPPET_MARKER: &str = "# OpenShell standard sbin PATH";
const PROFILE_D_SNIPPET_PATH: &str = "/etc/profile.d/openshell-standard-sbin-path.sh";

enum StartupFile {
    Missing,
    Regular(String),
    Unsafe,
}

pub fn standard_sbin_path_repair_enabled(policy: &SandboxPolicy) -> bool {
    let cdi_context = std::env::var(openshell_core::sandbox_env::CDI_CONTEXT);
    standard_sbin_path_repair_enabled_for_context(policy, cdi_context.as_deref().ok())
}

fn standard_sbin_path_repair_enabled_for_context(
    policy: &SandboxPolicy,
    cdi_context: Option<&str>,
) -> bool {
    cdi_context
        .map(str::trim)
        .is_some_and(|path| path == openshell_core::cdi::CDI_CONTEXT_PATH)
        && policy_has_standard_sbin_path(policy)
}

fn policy_has_standard_sbin_path(policy: &SandboxPolicy) -> bool {
    policy
        .filesystem
        .read_only
        .iter()
        .chain(policy.filesystem.read_write.iter())
        .any(|path| STANDARD_SBIN_PATHS.iter().any(|dir| path.starts_with(dir)))
}

pub fn child_path_from_env(repair_standard_sbin: bool) -> String {
    let path = std::env::var("PATH")
        .ok()
        .filter(|path| !path.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_CHILD_PATH.to_string());

    maybe_path_with_standard_sbin_paths(&path, repair_standard_sbin)
}

pub fn maybe_path_with_standard_sbin_paths(path: &str, repair_standard_sbin: bool) -> String {
    if repair_standard_sbin {
        path_with_standard_sbin_paths(path)
    } else {
        path.to_string()
    }
}

pub fn path_with_standard_sbin_paths(path: &str) -> String {
    let mut path = if path.trim().is_empty() {
        DEFAULT_CHILD_PATH.to_string()
    } else {
        path.to_string()
    };

    for dir in STANDARD_SBIN_PATHS {
        if !path.split(':').any(|entry| entry == *dir) {
            if !path.is_empty() {
                path.push(':');
            }
            path.push_str(dir);
        }
    }

    path
}

pub fn shell_command_with_standard_sbin_paths(command: &str) -> String {
    format!("{ENSURE_STANDARD_SBIN_PATHS_SCRIPT}\n{command}")
}

pub fn maybe_shell_command_with_standard_sbin_paths(
    command: &str,
    repair_standard_sbin: bool,
) -> String {
    if repair_standard_sbin {
        shell_command_with_standard_sbin_paths(command)
    } else {
        command.to_string()
    }
}

pub fn install_standard_sbin_path_startup_files(home: Option<&str>) {
    let profile_path = Path::new(PROFILE_D_SNIPPET_PATH);
    if let Err(error) = write_profile_snippet(profile_path) {
        tracing::debug!(
            path = %profile_path.display(),
            error = %error,
            "failed to install OpenShell PATH profile snippet"
        );
    }

    if let Some(home) = home {
        let bashrc_path = Path::new(home).join(".bashrc");
        if let Err(error) = append_startup_snippet(&bashrc_path) {
            tracing::debug!(
                path = %bashrc_path.display(),
                error = %error,
                "failed to install OpenShell PATH shell startup snippet"
            );
        }
    }
}

fn startup_snippet() -> String {
    format!("{STARTUP_SNIPPET_MARKER}\n{ENSURE_STANDARD_SBIN_PATHS_SCRIPT}\n")
}

fn write_profile_snippet(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        ensure_directory_without_symlink(parent)?;
    }

    let snippet = startup_snippet();
    match read_startup_file(path)? {
        StartupFile::Regular(content) if content == snippet => return Ok(()),
        StartupFile::Regular(_) | StartupFile::Missing => {}
        StartupFile::Unsafe => return Ok(()),
    }
    write_startup_file(path, &snippet)
}

fn append_startup_snippet(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !existing_directory_without_symlink(parent)?
    {
        return Ok(());
    }

    let existing = match read_startup_file(path)? {
        StartupFile::Regular(content) => content,
        StartupFile::Missing | StartupFile::Unsafe => return Ok(()),
    };
    if existing.contains(STARTUP_SNIPPET_MARKER) {
        return Ok(());
    }

    let snippet = startup_snippet();
    let mut file = open_startup_file_for_append(path)?;
    if !existing.is_empty() && !existing.ends_with('\n') {
        file.write_all(b"\n")?;
    }
    file.write_all(snippet.as_bytes())
}

fn read_startup_file(path: &Path) -> std::io::Result<StartupFile> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(StartupFile::Missing);
        }
        Err(error) => return Err(error),
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() || !file_type.is_file() {
        tracing::debug!(
            path = %path.display(),
            "skipping OpenShell PATH startup repair for non-regular file"
        );
        return Ok(StartupFile::Unsafe);
    }

    let mut content = String::new();
    open_startup_file_for_read(path)?.read_to_string(&mut content)?;
    Ok(StartupFile::Regular(content))
}

fn ensure_directory_without_symlink(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(std::io::Error::other(format!(
            "directory '{}' is a symlink",
            path.display()
        ))),
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(std::io::Error::other(format!(
            "'{}' is not a directory",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                ensure_directory_without_symlink(parent)?;
            }
            std::fs::create_dir(path)
        }
        Err(error) => Err(error),
    }
}

fn existing_directory_without_symlink(path: &Path) -> std::io::Result<bool> {
    if let Some(parent) = path.parent()
        && parent != path
        && !parent.as_os_str().is_empty()
        && !existing_directory_without_symlink(parent)?
    {
        return Ok(false);
    }

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            tracing::debug!(
                path = %path.display(),
                "skipping OpenShell PATH startup repair through symlink directory"
            );
            Ok(false)
        }
        Ok(metadata) if metadata.is_dir() => Ok(true),
        Ok(_) => {
            tracing::debug!(
                path = %path.display(),
                "skipping OpenShell PATH startup repair through non-directory path"
            );
            Ok(false)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn write_startup_file(path: &Path, content: &str) -> std::io::Result<()> {
    let mut file = no_follow_options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    ensure_opened_file_is_regular(&file, path)?;
    file.write_all(content.as_bytes())
}

fn open_startup_file_for_read(path: &Path) -> std::io::Result<std::fs::File> {
    let file = no_follow_options().read(true).open(path)?;
    ensure_opened_file_is_regular(&file, path)?;
    Ok(file)
}

fn open_startup_file_for_append(path: &Path) -> std::io::Result<std::fs::File> {
    let file = no_follow_options().append(true).open(path)?;
    ensure_opened_file_is_regular(&file, path)?;
    Ok(file)
}

fn ensure_opened_file_is_regular(file: &std::fs::File, path: &Path) -> std::io::Result<()> {
    let metadata = file.metadata()?;
    if metadata.is_file() {
        return Ok(());
    }
    Err(std::io::Error::other(format!(
        "'{}' is not a regular file",
        path.display()
    )))
}

fn no_follow_options() -> std::fs::OpenOptions {
    let mut options = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options
}

pub fn proxy_env_vars(proxy_url: &str) -> [(&'static str, String); 9] {
    [
        ("ALL_PROXY", proxy_url.to_owned()),
        ("HTTP_PROXY", proxy_url.to_owned()),
        ("HTTPS_PROXY", proxy_url.to_owned()),
        ("NO_PROXY", LOCAL_NO_PROXY.to_owned()),
        ("http_proxy", proxy_url.to_owned()),
        ("https_proxy", proxy_url.to_owned()),
        ("no_proxy", LOCAL_NO_PROXY.to_owned()),
        ("grpc_proxy", proxy_url.to_owned()),
        // Node.js only honors HTTP(S)_PROXY for built-in fetch/http clients when
        // proxy support is explicitly enabled at process startup.
        ("NODE_USE_ENV_PROXY", "1".to_owned()),
    ]
}

pub fn tls_env_vars(
    ca_cert_path: &Path,
    combined_bundle_path: &Path,
) -> [(&'static str, String); 6] {
    let ca_cert_path = ca_cert_path.display().to_string();
    let combined_bundle_path = combined_bundle_path.display().to_string();
    [
        ("NODE_EXTRA_CA_CERTS", ca_cert_path.clone()),
        ("DENO_CERT", ca_cert_path),
        ("SSL_CERT_FILE", combined_bundle_path.clone()),
        ("REQUESTS_CA_BUNDLE", combined_bundle_path.clone()),
        ("CURL_CA_BUNDLE", combined_bundle_path.clone()),
        // Ubuntu Noble's git links against libcurl-gnutls, which ignores SSL_CERT_FILE.
        // git reads GIT_SSL_CAINFO (or http.sslCAInfo) to locate the CA bundle.
        ("GIT_SSL_CAINFO", combined_bundle_path),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::process::Stdio;

    #[test]
    fn path_with_standard_sbin_paths_uses_default_for_empty_path() {
        assert_eq!(
            path_with_standard_sbin_paths(""),
            "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"
        );
    }

    #[test]
    fn path_with_standard_sbin_paths_appends_missing_sbin_dirs() {
        assert_eq!(
            path_with_standard_sbin_paths("/sandbox/.venv/bin:/usr/local/bin:/usr/bin:/bin"),
            "/sandbox/.venv/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"
        );
    }

    #[test]
    fn path_with_standard_sbin_paths_is_idempotent() {
        let path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
        assert_eq!(path_with_standard_sbin_paths(path), path);
    }

    #[test]
    fn maybe_path_with_standard_sbin_paths_respects_gate() {
        let path = "/sandbox/.venv/bin:/usr/local/bin:/usr/bin:/bin";

        assert_eq!(maybe_path_with_standard_sbin_paths(path, false), path);
        assert_eq!(
            maybe_path_with_standard_sbin_paths(path, true),
            "/sandbox/.venv/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"
        );
    }

    #[test]
    fn maybe_shell_command_with_standard_sbin_paths_respects_gate() {
        assert_eq!(
            maybe_shell_command_with_standard_sbin_paths("nvidia-smi -L", false),
            "nvidia-smi -L"
        );
        assert!(
            maybe_shell_command_with_standard_sbin_paths("nvidia-smi -L", true)
                .contains("/usr/sbin")
        );
    }

    #[test]
    fn standard_sbin_repair_requires_expected_cdi_context_and_policy_path() {
        let policy = policy_with_read_only(["/usr/sbin/nvidia-smi"]);

        assert!(standard_sbin_path_repair_enabled_for_context(
            &policy,
            Some(openshell_core::cdi::CDI_CONTEXT_PATH)
        ));
        assert!(!standard_sbin_path_repair_enabled_for_context(
            &policy,
            Some("/tmp/cdi-context.json")
        ));
        assert!(!standard_sbin_path_repair_enabled_for_context(
            &policy, None
        ));
    }

    #[test]
    fn standard_sbin_repair_requires_standard_sbin_policy_path() {
        let policy = policy_with_read_only(["/usr/local/bin/nvidia-smi"]);

        assert!(!standard_sbin_path_repair_enabled_for_context(
            &policy,
            Some(openshell_core::cdi::CDI_CONTEXT_PATH)
        ));
    }

    #[test]
    fn standard_sbin_repair_accepts_read_write_standard_sbin_policy_path() {
        let mut policy = policy_with_read_only(std::iter::empty::<&str>());
        policy
            .filesystem
            .read_write
            .push("/sbin/vendor-tool".into());

        assert!(standard_sbin_path_repair_enabled_for_context(
            &policy,
            Some(openshell_core::cdi::CDI_CONTEXT_PATH)
        ));
    }

    fn policy_with_read_only(
        paths: impl IntoIterator<Item = impl Into<std::path::PathBuf>>,
    ) -> SandboxPolicy {
        SandboxPolicy {
            version: 1,
            filesystem: openshell_core::policy::FilesystemPolicy {
                read_only: paths.into_iter().map(Into::into).collect(),
                read_write: Vec::new(),
                include_workdir: false,
            },
            network: openshell_core::policy::NetworkPolicy::default(),
            landlock: openshell_core::policy::LandlockPolicy::default(),
            process: openshell_core::policy::ProcessPolicy::default(),
        }
    }

    #[test]
    fn shell_command_with_standard_sbin_paths_extends_runtime_path() {
        let command = shell_command_with_standard_sbin_paths("printf '%s' \"$PATH\"");
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "PATH=/sandbox/.venv/bin:/usr/local/bin:/usr/bin:/bin\n{command}"
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("spawn shell");

        assert!(
            output.status.success(),
            "shell command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).expect("utf8"),
            "/sandbox/.venv/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"
        );
    }

    #[test]
    fn startup_snippets_are_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let profile_path = dir.path().join("etc/profile.d/openshell-path.sh");
        let home = dir.path().join("sandbox");
        std::fs::create_dir_all(&home).expect("home dir");
        let bashrc_path = home.join(".bashrc");
        std::fs::write(
            &bashrc_path,
            "export PATH=\"/sandbox/.venv/bin:/usr/local/bin:/usr/bin:/bin\"\n",
        )
        .expect("write bashrc");

        write_profile_snippet(&profile_path).expect("write profile snippet");
        append_startup_snippet(&bashrc_path).expect("append startup snippet");
        write_profile_snippet(&profile_path).expect("rewrite profile snippet");
        append_startup_snippet(&bashrc_path).expect("append startup snippet again");

        let profile = std::fs::read_to_string(&profile_path).expect("read profile");
        let bashrc = std::fs::read_to_string(&bashrc_path).expect("read bashrc");

        assert_eq!(profile.matches(STARTUP_SNIPPET_MARKER).count(), 1);
        assert_eq!(bashrc.matches(STARTUP_SNIPPET_MARKER).count(), 1);
        assert!(bashrc.contains("export PATH=\"/sandbox/.venv/bin:/usr/local/bin:/usr/bin:/bin\""));
    }

    #[cfg(unix)]
    #[test]
    fn profile_snippet_skips_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target");
        std::fs::write(&target, "keep me").expect("write target");
        let profile_path = dir.path().join("openshell-path.sh");
        symlink(&target, &profile_path).expect("symlink profile");

        write_profile_snippet(&profile_path).expect("skip symlink profile");

        assert_eq!(
            std::fs::read_to_string(&target).expect("read target"),
            "keep me"
        );
        assert!(
            std::fs::symlink_metadata(&profile_path)
                .expect("profile metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn profile_snippet_rejects_symlink_parent() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("tempdir");
        let target_dir = dir.path().join("target-dir");
        std::fs::create_dir(&target_dir).expect("target dir");
        let parent = dir.path().join("profile.d");
        symlink(&target_dir, &parent).expect("symlink parent");
        let profile_path = parent.join("openshell-path.sh");

        let error = write_profile_snippet(&profile_path).expect_err("reject symlink parent");

        assert!(error.to_string().contains("symlink"));
        assert!(!target_dir.join("openshell-path.sh").exists());
    }

    #[cfg(unix)]
    #[test]
    fn bashrc_snippet_skips_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target");
        std::fs::write(&target, "keep me").expect("write target");
        let bashrc_path = dir.path().join(".bashrc");
        symlink(&target, &bashrc_path).expect("symlink bashrc");

        append_startup_snippet(&bashrc_path).expect("skip symlink bashrc");

        assert_eq!(
            std::fs::read_to_string(&target).expect("read target"),
            "keep me"
        );
        assert!(
            std::fs::symlink_metadata(&bashrc_path)
                .expect("bashrc metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn bashrc_snippet_skips_symlink_parent() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("tempdir");
        let target_dir = dir.path().join("target-dir");
        std::fs::create_dir(&target_dir).expect("target dir");
        std::fs::write(
            target_dir.join(".bashrc"),
            "export PATH=\"/sandbox/.venv/bin:/usr/local/bin:/usr/bin:/bin\"\n",
        )
        .expect("target bashrc");
        let home = dir.path().join("home");
        symlink(&target_dir, &home).expect("symlink home");

        append_startup_snippet(&home.join(".bashrc")).expect("skip symlink home");

        let bashrc = std::fs::read_to_string(target_dir.join(".bashrc")).expect("read target");
        assert!(!bashrc.contains(STARTUP_SNIPPET_MARKER));
    }

    #[test]
    fn apply_proxy_env_includes_node_proxy_opt_in_and_local_bypass() {
        let mut cmd = Command::new("/usr/bin/env");
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        for (key, value) in proxy_env_vars("http://10.200.0.1:3128") {
            cmd.env(key, value);
        }

        let output = cmd.output().expect("spawn env");
        let stdout = String::from_utf8(output.stdout).expect("utf8");

        assert!(stdout.contains("HTTP_PROXY=http://10.200.0.1:3128"));
        assert!(stdout.contains("NO_PROXY=127.0.0.1,localhost,::1"));
        assert!(stdout.contains("NODE_USE_ENV_PROXY=1"));
        assert!(stdout.contains("no_proxy=127.0.0.1,localhost,::1"));
    }

    #[test]
    fn apply_tls_env_sets_node_and_bundle_paths() {
        let mut cmd = Command::new("/usr/bin/env");
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let ca_cert_path = Path::new("/etc/openshell-tls/openshell-ca.pem");
        let combined_bundle_path = Path::new("/etc/openshell-tls/ca-bundle.pem");
        for (key, value) in tls_env_vars(ca_cert_path, combined_bundle_path) {
            cmd.env(key, value);
        }

        let output = cmd.output().expect("spawn env");
        let stdout = String::from_utf8(output.stdout).expect("utf8");

        assert!(stdout.contains("NODE_EXTRA_CA_CERTS=/etc/openshell-tls/openshell-ca.pem"));
        assert!(stdout.contains("DENO_CERT=/etc/openshell-tls/openshell-ca.pem"));
        assert!(stdout.contains("SSL_CERT_FILE=/etc/openshell-tls/ca-bundle.pem"));
        assert!(stdout.contains("REQUESTS_CA_BUNDLE=/etc/openshell-tls/ca-bundle.pem"));
        assert!(stdout.contains("CURL_CA_BUNDLE=/etc/openshell-tls/ca-bundle.pem"));
        assert!(stdout.contains("GIT_SSL_CAINFO=/etc/openshell-tls/ca-bundle.pem"));
    }
}
