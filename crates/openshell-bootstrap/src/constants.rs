// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/// Path to the kubeconfig inside the k3s container.
/// Used by in-container kubectl operations (node cleanup, PKI reconciliation, etc.).
pub const KUBECONFIG_PATH: &str = "/etc/rancher/k3s/k3s.yaml";

/// K8s secret holding the server's TLS certificate and private key.
pub const SERVER_TLS_SECRET_NAME: &str = "openshell-server-tls";
/// K8s secret holding the CA certificate used to verify client certificates.
pub const SERVER_CLIENT_CA_SECRET_NAME: &str = "openshell-server-client-ca";
/// K8s secret holding the client TLS certificate, key, and CA cert (shared by CLI and sandboxes).
pub const CLIENT_TLS_SECRET_NAME: &str = "openshell-client-tls";
/// K8s secret holding the SSH handshake HMAC secret (shared by gateway and sandbox pods).
pub const SSH_HANDSHAKE_SECRET_NAME: &str = "openshell-ssh-handshake";
const NODE_NAME_PREFIX: &str = "openshell-";
const NODE_NAME_FALLBACK_SUFFIX: &str = "gateway";
const KUBERNETES_MAX_NAME_LEN: usize = 253;

pub fn container_name(name: &str) -> String {
    format!("openshell-cluster-{name}")
}

/// Deterministic k3s node name derived from the gateway name.
///
/// k3s defaults to using the container hostname (= Docker container ID) as
/// the node name.  When the container is recreated (e.g. after an image
/// upgrade), the container ID changes, creating a new k3s node.  The
/// `clean_stale_nodes` function then deletes PVCs whose backing PVs have
/// node affinity for the old node — wiping the server database and any
/// sandbox persistent volumes.
///
/// By passing a deterministic `--node-name` to k3s, the node identity
/// survives container recreation, and PVCs are never orphaned.
///
/// Gateway names allow Docker-friendly separators and uppercase characters,
/// but Kubernetes node names must be DNS-safe. Normalize the gateway name into
/// a single lowercase RFC 1123 label so previously accepted names such as
/// `prod_us` or `Prod.US` still deploy successfully.
pub fn node_name(name: &str) -> String {
    format!("{NODE_NAME_PREFIX}{}", normalize_node_name_suffix(name))
}

fn normalize_node_name_suffix(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut last_was_separator = false;

    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator {
            normalized.push('-');
            last_was_separator = true;
        }
    }

    let mut normalized = normalized.trim_matches('-').to_string();
    if normalized.is_empty() {
        normalized.push_str(NODE_NAME_FALLBACK_SUFFIX);
    }

    let max_suffix_len = KUBERNETES_MAX_NAME_LEN.saturating_sub(NODE_NAME_PREFIX.len());
    if normalized.len() > max_suffix_len {
        normalized.truncate(max_suffix_len);
        normalized.truncate(normalized.trim_end_matches('-').len());
    }

    if normalized.is_empty() {
        normalized.push_str(NODE_NAME_FALLBACK_SUFFIX);
    }

    normalized
}

pub fn volume_name(name: &str) -> String {
    format!("openshell-cluster-{name}")
}

pub fn network_name(name: &str) -> String {
    format!("openshell-cluster-{name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_name_normalizes_uppercase_and_underscores() {
        assert_eq!(node_name("Prod_US"), "openshell-prod-us");
    }

    #[test]
    fn node_name_collapses_and_trims_separator_runs() {
        assert_eq!(node_name("._Prod..__-Gateway-."), "openshell-prod-gateway");
    }

    #[test]
    fn node_name_falls_back_when_gateway_name_has_no_alphanumerics() {
        assert_eq!(node_name("...___---"), "openshell-gateway");
    }

    #[test]
    fn node_name_truncates_to_kubernetes_name_limit() {
        let gateway_name = "A".repeat(400);
        let node_name = node_name(&gateway_name);

        assert!(node_name.len() <= KUBERNETES_MAX_NAME_LEN);
        assert!(node_name.starts_with(NODE_NAME_PREFIX));
        assert!(node_name.ends_with('a'));
    }
}
