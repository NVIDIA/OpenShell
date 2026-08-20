// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::Write;
use std::path::Path;

const LOCAL_NO_PROXY: &str = "127.0.0.1,localhost,::1";
pub const DEFAULT_CHILD_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const STANDARD_SBIN_PATHS: &[&str] = &["/usr/local/sbin", "/usr/sbin", "/sbin"];
const ENSURE_STANDARD_SBIN_PATHS_SCRIPT: &str = "for dir in /usr/local/sbin /usr/sbin /sbin; do case \":${PATH:-}:\" in *:\"$dir\":*) ;; *) PATH=\"${PATH:+$PATH:}$dir\" ;; esac; done; export PATH";
const STARTUP_SNIPPET_MARKER: &str = "# OpenShell standard sbin PATH";
const PROFILE_D_SNIPPET_PATH: &str = "/etc/profile.d/openshell-standard-sbin-path.sh";

pub fn child_path_from_env() -> String {
    std::env::var("PATH")
        .ok()
        .filter(|path| !path.trim().is_empty())
        .map_or_else(
            || DEFAULT_CHILD_PATH.to_string(),
            |path| path_with_standard_sbin_paths(&path),
        )
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
    let snippet = startup_snippet();
    if std::fs::read_to_string(path).is_ok_and(|content| content == snippet) {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, snippet)
}

fn append_startup_snippet(path: &Path) -> std::io::Result<()> {
    let existing = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if existing.contains(STARTUP_SNIPPET_MARKER) {
        return Ok(());
    }

    let snippet = startup_snippet();
    let mut file = std::fs::OpenOptions::new().append(true).open(path)?;
    if !existing.is_empty() && !existing.ends_with('\n') {
        file.write_all(b"\n")?;
    }
    file.write_all(snippet.as_bytes())
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
        assert_eq!(path_with_standard_sbin_paths(""), DEFAULT_CHILD_PATH);
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
        assert_eq!(
            path_with_standard_sbin_paths(DEFAULT_CHILD_PATH),
            DEFAULT_CHILD_PATH
        );
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
