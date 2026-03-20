// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::path::PathBuf;

const LOCAL_NO_PROXY: &str = "127.0.0.1,localhost,::1";
const OPENCODE_AUTH_RELATIVE_PATH: &str = ".local/share/opencode/auth.json";
const SANDBOX_XDG_DATA_HOME: &str = "/sandbox/.local/share";
const SANDBOX_OPENCODE_AUTH_PATH: &str = "/sandbox/.local/share/opencode/auth.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolAdapter {
    ClaudeCode,
    OpenCode,
}

impl ToolAdapter {
    pub(crate) fn command_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude",
            Self::OpenCode => "opencode",
        }
    }
}

pub(crate) fn detect_tool_adapter(command: &[String]) -> Option<ToolAdapter> {
    let first = command.first()?;
    let basename = Path::new(first)
        .file_name()
        .and_then(|name| name.to_str())?;

    match basename {
        "claude" => Some(ToolAdapter::ClaudeCode),
        "opencode" => Some(ToolAdapter::OpenCode),
        _ => None,
    }
}

pub(crate) fn auth_file_projection(
    command: &[String],
    host_home: &Path,
    provider_env: &std::collections::HashMap<String, String>,
) -> Option<(PathBuf, PathBuf)> {
    match detect_tool_adapter(command)? {
        ToolAdapter::OpenCode if is_github_copilot_targeted(provider_env) => Some((
            host_home.join(OPENCODE_AUTH_RELATIVE_PATH),
            PathBuf::from(SANDBOX_OPENCODE_AUTH_PATH),
        )),
        ToolAdapter::ClaudeCode => None,
        ToolAdapter::OpenCode => None,
    }
}

pub(crate) fn tool_runtime_env_vars(
    command: &[String],
    provider_env: &std::collections::HashMap<String, String>,
) -> Option<[(&'static str, String); 1]> {
    match detect_tool_adapter(command)? {
        ToolAdapter::OpenCode if is_github_copilot_targeted(provider_env) => {
            Some([("XDG_DATA_HOME", SANDBOX_XDG_DATA_HOME.to_owned())])
        }
        ToolAdapter::ClaudeCode => None,
        ToolAdapter::OpenCode => None,
    }
}

fn is_github_copilot_targeted(provider_env: &std::collections::HashMap<String, String>) -> bool {
    provider_env.contains_key("GITHUB_TOKEN") || provider_env.contains_key("GH_TOKEN")
}

pub(crate) fn proxy_env_vars(proxy_url: &str) -> [(&'static str, String); 9] {
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

pub(crate) fn tls_env_vars(
    ca_cert_path: &Path,
    combined_bundle_path: &Path,
) -> [(&'static str, String); 4] {
    let ca_cert_path = ca_cert_path.display().to_string();
    let combined_bundle_path = combined_bundle_path.display().to_string();
    [
        ("NODE_EXTRA_CA_CERTS", ca_cert_path.clone()),
        ("SSL_CERT_FILE", combined_bundle_path.clone()),
        ("REQUESTS_CA_BUNDLE", combined_bundle_path.clone()),
        ("CURL_CA_BUNDLE", combined_bundle_path),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::process::Stdio;

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
        assert!(stdout.contains("SSL_CERT_FILE=/etc/openshell-tls/ca-bundle.pem"));
    }

    #[test]
    fn detects_claude_tool_adapter_from_command_basename() {
        let command = vec!["/usr/local/bin/claude".to_string(), "code".to_string()];

        assert_eq!(detect_tool_adapter(&command), Some(ToolAdapter::ClaudeCode));
    }

    #[test]
    fn detects_opencode_tool_adapter_from_command_basename() {
        let command = vec!["opencode".to_string(), "sandbox".to_string()];

        assert_eq!(detect_tool_adapter(&command), Some(ToolAdapter::OpenCode));
    }

    #[test]
    fn rejects_unsupported_tool_adapter_command() {
        let command = vec!["python".to_string(), "script.py".to_string()];

        assert_eq!(detect_tool_adapter(&command), None);
    }

    #[test]
    fn opencode_auth_file_projection_uses_approved_source_and_destination_paths() {
        let command = vec!["/usr/local/bin/opencode".to_string(), "run".to_string()];
        let provider_env =
            std::iter::once(("GITHUB_TOKEN".to_string(), "ghu-test".to_string())).collect();
        let projection = auth_file_projection(&command, Path::new("/home/alice"), &provider_env)
            .expect("opencode should request auth.json projection");

        assert_eq!(
            projection.0,
            PathBuf::from("/home/alice/.local/share/opencode/auth.json")
        );
        assert_eq!(
            projection.1,
            PathBuf::from("/sandbox/.local/share/opencode/auth.json")
        );
    }

    #[test]
    fn claude_does_not_request_auth_file_projection() {
        let command = vec!["claude".to_string(), "code".to_string()];
        let provider_env =
            std::iter::once(("GITHUB_TOKEN".to_string(), "ghu-test".to_string())).collect();

        assert_eq!(
            auth_file_projection(&command, Path::new("/home/alice"), &provider_env),
            None
        );
    }

    #[test]
    fn unsupported_tool_paths_do_not_request_auth_file_projection() {
        let command = vec!["/usr/bin/python3".to_string(), "script.py".to_string()];
        let provider_env =
            std::iter::once(("GITHUB_TOKEN".to_string(), "ghu-test".to_string())).collect();

        assert_eq!(
            auth_file_projection(&command, Path::new("/home/alice"), &provider_env),
            None
        );
    }

    #[test]
    fn opencode_runtime_env_vars_use_sandbox_xdg_data_dir_for_github_path() {
        let command = vec!["opencode".to_string(), "run".to_string()];
        let provider_env =
            std::iter::once(("GITHUB_TOKEN".to_string(), "ghu-test".to_string())).collect();

        assert_eq!(
            tool_runtime_env_vars(&command, &provider_env),
            Some([("XDG_DATA_HOME", "/sandbox/.local/share".to_string())])
        );
    }

    #[test]
    fn unsupported_tools_do_not_receive_runtime_env_vars() {
        let command = vec!["python".to_string(), "script.py".to_string()];
        let provider_env =
            std::iter::once(("GITHUB_TOKEN".to_string(), "ghu-test".to_string())).collect();

        assert_eq!(tool_runtime_env_vars(&command, &provider_env), None);
    }

    #[test]
    fn opencode_without_github_provider_does_not_request_auth_projection_or_xdg_override() {
        let command = vec!["opencode".to_string(), "run".to_string()];
        let provider_env = std::collections::HashMap::new();

        assert_eq!(
            auth_file_projection(&command, Path::new("/home/alice"), &provider_env),
            None
        );
        assert_eq!(tool_runtime_env_vars(&command, &provider_env), None);
    }
}
