// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Declarative provider type profiles.

#![allow(deprecated)] // NetworkBinary::harness remains in the public proto for compatibility.

use openshell_core::proto::{
    NetworkBinary, NetworkEndpoint, NetworkPolicyRule, ProviderProfile, ProviderProfileCredential,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialProfile {
    pub name: &'static str,
    pub description: &'static str,
    pub env_vars: &'static [&'static str],
    pub required: bool,
    pub auth_style: &'static str,
    pub header_name: &'static str,
    pub query_param: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointProfile {
    pub host: &'static str,
    pub port: u32,
    pub protocol: &'static str,
    pub access: &'static str,
    pub enforcement: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderTypeProfile {
    pub id: &'static str,
    pub display_name: &'static str,
    pub description: &'static str,
    pub category: &'static str,
    pub credentials: &'static [CredentialProfile],
    pub endpoints: &'static [EndpointProfile],
    pub binaries: &'static [&'static str],
    pub inference_capable: bool,
}

impl ProviderTypeProfile {
    #[must_use]
    pub fn credential_env_vars(&self) -> Vec<&'static str> {
        let mut vars = Vec::new();
        for credential in self.credentials {
            for env_var in credential.env_vars {
                if !vars.contains(env_var) {
                    vars.push(*env_var);
                }
            }
        }
        vars
    }

    #[must_use]
    pub fn to_proto(&self) -> ProviderProfile {
        ProviderProfile {
            id: self.id.to_string(),
            display_name: self.display_name.to_string(),
            description: self.description.to_string(),
            category: self.category.to_string(),
            credentials: self
                .credentials
                .iter()
                .map(|credential| ProviderProfileCredential {
                    name: credential.name.to_string(),
                    description: credential.description.to_string(),
                    env_vars: credential
                        .env_vars
                        .iter()
                        .map(|env_var| (*env_var).to_string())
                        .collect(),
                    required: credential.required,
                    auth_style: credential.auth_style.to_string(),
                    header_name: credential.header_name.to_string(),
                    query_param: credential.query_param.to_string(),
                })
                .collect(),
            endpoints: self
                .endpoints
                .iter()
                .map(|endpoint| NetworkEndpoint {
                    host: endpoint.host.to_string(),
                    port: endpoint.port,
                    protocol: endpoint.protocol.to_string(),
                    tls: String::new(),
                    enforcement: endpoint.enforcement.to_string(),
                    access: endpoint.access.to_string(),
                    rules: Vec::new(),
                    allowed_ips: Vec::new(),
                    ports: Vec::new(),
                    deny_rules: Vec::new(),
                    allow_encoded_slash: false,
                })
                .collect(),
            binaries: self
                .binaries
                .iter()
                .map(|path| NetworkBinary {
                    path: (*path).to_string(),
                    harness: false,
                })
                .collect(),
            inference_capable: self.inference_capable,
        }
    }

    #[must_use]
    pub fn network_policy_rule(&self, rule_name: &str) -> NetworkPolicyRule {
        NetworkPolicyRule {
            name: rule_name.to_string(),
            endpoints: self.to_proto().endpoints,
            binaries: self
                .binaries
                .iter()
                .map(|path| NetworkBinary {
                    path: (*path).to_string(),
                    harness: false,
                })
                .collect(),
        }
    }
}

const CLAUDE_CREDENTIALS: &[CredentialProfile] = &[CredentialProfile {
    name: "api_key",
    description: "Anthropic API key used by Claude Code",
    env_vars: &["ANTHROPIC_API_KEY", "CLAUDE_API_KEY"],
    required: true,
    auth_style: "header",
    header_name: "x-api-key",
    query_param: "",
}];

const ANTHROPIC_CREDENTIALS: &[CredentialProfile] = &[CredentialProfile {
    name: "api_key",
    description: "Anthropic API key",
    env_vars: &["ANTHROPIC_API_KEY"],
    required: true,
    auth_style: "header",
    header_name: "x-api-key",
    query_param: "",
}];

const OPENAI_CREDENTIALS: &[CredentialProfile] = &[CredentialProfile {
    name: "api_key",
    description: "OpenAI API key",
    env_vars: &["OPENAI_API_KEY"],
    required: true,
    auth_style: "bearer",
    header_name: "authorization",
    query_param: "",
}];

const OPENCODE_CREDENTIALS: &[CredentialProfile] = &[CredentialProfile {
    name: "api_key",
    description: "OpenCode-compatible API key",
    env_vars: &["OPENCODE_API_KEY", "OPENROUTER_API_KEY", "OPENAI_API_KEY"],
    required: true,
    auth_style: "bearer",
    header_name: "authorization",
    query_param: "",
}];

const NVIDIA_CREDENTIALS: &[CredentialProfile] = &[CredentialProfile {
    name: "api_key",
    description: "NVIDIA API key",
    env_vars: &["NVIDIA_API_KEY"],
    required: true,
    auth_style: "bearer",
    header_name: "authorization",
    query_param: "",
}];

const GITHUB_CREDENTIALS: &[CredentialProfile] = &[CredentialProfile {
    name: "api_token",
    description: "GitHub token",
    env_vars: &["GITHUB_TOKEN", "GH_TOKEN"],
    required: true,
    auth_style: "bearer",
    header_name: "authorization",
    query_param: "",
}];

const COPILOT_CREDENTIALS: &[CredentialProfile] = &[CredentialProfile {
    name: "github_token",
    description: "GitHub token used by Copilot tooling",
    env_vars: &["COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"],
    required: true,
    auth_style: "bearer",
    header_name: "authorization",
    query_param: "",
}];

const GITLAB_CREDENTIALS: &[CredentialProfile] = &[CredentialProfile {
    name: "api_token",
    description: "GitLab token",
    env_vars: &["GITLAB_TOKEN", "GLAB_TOKEN", "CI_JOB_TOKEN"],
    required: true,
    auth_style: "bearer",
    header_name: "authorization",
    query_param: "",
}];

const GENERIC_CREDENTIALS: &[CredentialProfile] = &[];
const OUTLOOK_CREDENTIALS: &[CredentialProfile] = &[];

const CLAUDE_ENDPOINTS: &[EndpointProfile] = &[
    EndpointProfile {
        host: "api.anthropic.com",
        port: 443,
        protocol: "rest",
        access: "read-write",
        enforcement: "enforce",
    },
    EndpointProfile {
        host: "statsig.anthropic.com",
        port: 443,
        protocol: "rest",
        access: "read-write",
        enforcement: "enforce",
    },
    EndpointProfile {
        host: "sentry.io",
        port: 443,
        protocol: "rest",
        access: "read-write",
        enforcement: "enforce",
    },
];

const ANTHROPIC_ENDPOINTS: &[EndpointProfile] = &[EndpointProfile {
    host: "api.anthropic.com",
    port: 443,
    protocol: "rest",
    access: "read-write",
    enforcement: "enforce",
}];

const OPENAI_ENDPOINTS: &[EndpointProfile] = &[EndpointProfile {
    host: "api.openai.com",
    port: 443,
    protocol: "rest",
    access: "read-write",
    enforcement: "enforce",
}];

const NVIDIA_ENDPOINTS: &[EndpointProfile] = &[EndpointProfile {
    host: "integrate.api.nvidia.com",
    port: 443,
    protocol: "rest",
    access: "read-write",
    enforcement: "enforce",
}];

const GITHUB_ENDPOINTS: &[EndpointProfile] = &[
    EndpointProfile {
        host: "api.github.com",
        port: 443,
        protocol: "rest",
        access: "read-write",
        enforcement: "enforce",
    },
    EndpointProfile {
        host: "github.com",
        port: 443,
        protocol: "rest",
        access: "read-only",
        enforcement: "enforce",
    },
];

const GITLAB_ENDPOINTS: &[EndpointProfile] = &[
    EndpointProfile {
        host: "gitlab.com",
        port: 443,
        protocol: "rest",
        access: "read-write",
        enforcement: "enforce",
    },
    EndpointProfile {
        host: "api.gitlab.com",
        port: 443,
        protocol: "rest",
        access: "read-write",
        enforcement: "enforce",
    },
];

const EMPTY_ENDPOINTS: &[EndpointProfile] = &[];

const DEFAULT_PROFILES: &[ProviderTypeProfile] = &[
    ProviderTypeProfile {
        id: "anthropic",
        display_name: "Anthropic API",
        description: "Anthropic API access for Claude models",
        category: "inference",
        credentials: ANTHROPIC_CREDENTIALS,
        endpoints: ANTHROPIC_ENDPOINTS,
        binaries: &["/usr/bin/curl", "/usr/local/bin/curl"],
        inference_capable: true,
    },
    ProviderTypeProfile {
        id: "claude",
        display_name: "Claude Code",
        description: "Claude Code CLI",
        category: "inference",
        credentials: CLAUDE_CREDENTIALS,
        endpoints: CLAUDE_ENDPOINTS,
        binaries: &["/usr/bin/claude", "/usr/local/bin/claude"],
        inference_capable: true,
    },
    ProviderTypeProfile {
        id: "codex",
        display_name: "Codex",
        description: "Codex CLI using OpenAI-compatible API credentials",
        category: "inference",
        credentials: OPENAI_CREDENTIALS,
        endpoints: OPENAI_ENDPOINTS,
        binaries: &["/usr/bin/codex", "/usr/local/bin/codex"],
        inference_capable: true,
    },
    ProviderTypeProfile {
        id: "copilot",
        display_name: "GitHub Copilot",
        description: "GitHub Copilot tooling",
        category: "inference",
        credentials: COPILOT_CREDENTIALS,
        endpoints: GITHUB_ENDPOINTS,
        binaries: &["/usr/bin/copilot", "/usr/local/bin/copilot"],
        inference_capable: false,
    },
    ProviderTypeProfile {
        id: "generic",
        display_name: "Generic",
        description: "Generic provider record without managed policy defaults",
        category: "custom",
        credentials: GENERIC_CREDENTIALS,
        endpoints: EMPTY_ENDPOINTS,
        binaries: &[],
        inference_capable: false,
    },
    ProviderTypeProfile {
        id: "github",
        display_name: "GitHub",
        description: "GitHub API and Git operations",
        category: "source-control",
        credentials: GITHUB_CREDENTIALS,
        endpoints: GITHUB_ENDPOINTS,
        binaries: &[
            "/usr/bin/gh",
            "/usr/local/bin/gh",
            "/usr/bin/git",
            "/usr/local/bin/git",
        ],
        inference_capable: false,
    },
    ProviderTypeProfile {
        id: "gitlab",
        display_name: "GitLab",
        description: "GitLab API and Git operations",
        category: "source-control",
        credentials: GITLAB_CREDENTIALS,
        endpoints: GITLAB_ENDPOINTS,
        binaries: &[
            "/usr/bin/glab",
            "/usr/local/bin/glab",
            "/usr/bin/git",
            "/usr/local/bin/git",
        ],
        inference_capable: false,
    },
    ProviderTypeProfile {
        id: "nvidia",
        display_name: "NVIDIA",
        description: "NVIDIA inference endpoints",
        category: "inference",
        credentials: NVIDIA_CREDENTIALS,
        endpoints: NVIDIA_ENDPOINTS,
        binaries: &["/usr/bin/curl", "/usr/local/bin/curl"],
        inference_capable: true,
    },
    ProviderTypeProfile {
        id: "openai",
        display_name: "OpenAI",
        description: "OpenAI API access",
        category: "inference",
        credentials: OPENAI_CREDENTIALS,
        endpoints: OPENAI_ENDPOINTS,
        binaries: &["/usr/bin/curl", "/usr/local/bin/curl"],
        inference_capable: true,
    },
    ProviderTypeProfile {
        id: "opencode",
        display_name: "OpenCode",
        description: "OpenCode-compatible inference provider",
        category: "inference",
        credentials: OPENCODE_CREDENTIALS,
        endpoints: OPENAI_ENDPOINTS,
        binaries: &["/usr/bin/opencode", "/usr/local/bin/opencode"],
        inference_capable: true,
    },
    ProviderTypeProfile {
        id: "outlook",
        display_name: "Outlook",
        description: "Outlook provider record without managed policy defaults",
        category: "messaging",
        credentials: OUTLOOK_CREDENTIALS,
        endpoints: EMPTY_ENDPOINTS,
        binaries: &[],
        inference_capable: false,
    },
];

#[must_use]
pub const fn default_profiles() -> &'static [ProviderTypeProfile] {
    DEFAULT_PROFILES
}

#[must_use]
pub fn get_default_profile(id: &str) -> Option<&'static ProviderTypeProfile> {
    default_profiles()
        .iter()
        .find(|profile| profile.id.eq_ignore_ascii_case(id))
}

#[cfg(test)]
mod tests {
    use super::{default_profiles, get_default_profile};

    #[test]
    fn default_profiles_are_sorted_by_id() {
        let ids = default_profiles()
            .iter()
            .map(|profile| profile.id)
            .collect::<Vec<_>>();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn github_profile_materializes_policy_metadata() {
        let profile = get_default_profile("github").expect("github profile");
        let proto = profile.to_proto();

        assert_eq!(proto.id, "github");
        assert_eq!(proto.category, "source-control");
        assert_eq!(proto.endpoints.len(), 2);
        assert_eq!(proto.binaries.len(), 4);
    }

    #[test]
    fn credential_env_vars_are_deduplicated_in_profile_order() {
        let profile = get_default_profile("copilot").expect("copilot profile");
        assert_eq!(
            profile.credential_env_vars(),
            vec!["COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"]
        );
    }
}
