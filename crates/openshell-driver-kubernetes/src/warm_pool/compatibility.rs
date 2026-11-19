// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::config::WarmPoolConfig;
use std::fmt::Write as _;

impl KubernetesComputeDriver {
    /// Hash effective preparation inputs. Fixed coordinates stand in for the
    /// per-runtime identities; inventory policy and claim-time data are excluded.
    pub(super) async fn warm_pool_fingerprint(
        &self,
        pool: &WarmPoolConfig,
        trust: &WarmRuntimeTrust,
    ) -> Result<String, KubernetesDriverError> {
        if pool.revision == u64::MAX {
            return Ok("0".repeat(64));
        }
        let physical_id = "00000000-0000-4000-8000-000000000001";
        let names = SandboxRuntimeNames::for_generation(physical_id, physical_id);
        let namespace = self.warm_runtime_namespace(&pool.workspace).await?;
        let (uid, gid) = self.warm_namespace_identity(&namespace).await?;
        let workload = self.warm_runtime_shape(Some(&pool.spec), physical_id, &names, uid, gid)?;
        let supervisor = if let Some(shared) = &self.shared_supervisor {
            let config = shared.config();
            serde_json::json!({
                "shared": {
                    "service": config.service_name,
                    "namespace": config.service_namespace,
                    "port": config.runtime_port,
                }
            })
        } else {
            let staged = self.read_staged_bootstrap_material().await?;
            let network_ca = self.network_trust_bundle.as_ref().map(|bundle| {
                (
                    network_additional_ca_config_map_name(&self.config.gateway_id, bundle.digest()),
                    bundle.digest(),
                )
            });
            let pod = self.render_sandbox_runtime_supervisor(
                &namespace,
                &names,
                physical_id,
                "",
                OwnerReference::default(),
                uid,
                gid,
                &openshell_core::sandbox_env::MainProcessConfig::encode_driver_spec(None)
                    .map_err(record_error)?,
                "info",
                staged.upstream_proxy_ca_bundle.is_some(),
                true,
                network_ca
                    .as_ref()
                    .map(|(name, digest)| (name.as_str(), *digest)),
            )?;
            serde_json::json!({
                "dedicated": pod.spec,
                // Only public trust is compatibility material, never credentials.
                "gateway_ca": staged.client_tls.as_ref().map(|tls| &tls.ca_certificate),
                "proxy_ca": staged.upstream_proxy_ca_bundle,
            })
        };
        // Managed namespaces render generated pull-secret names; retain their
        // source references as well so changing the source changes compatibility.
        let pull_sources = (self.config.workspace_mode == WorkspaceMode::Managed)
            .then_some((&self.config.namespace, &self.config.image_pull_secrets));
        let canonical = serde_json::json!({
            "version": 1,
            "workload": workload,
            "supervisor": supervisor,
            "namespace": namespace,
            "pull_sources": pull_sources,
            "identity": [self.config.sandbox_uid, self.config.sandbox_gid],
            "host_gateway_ip": self.config.host_gateway_ip.parse::<std::net::IpAddr>().ok(),
            "trust": trust,
        });
        let bytes = serde_json::to_vec(&canonical).map_err(record_error)?;
        let digest = openshell_crypto::sha256(&bytes)
            .map_err(|_| invalid("warm pool fingerprint failed"))?;
        let mut fingerprint = String::with_capacity(64);
        for byte in digest {
            write!(fingerprint, "{byte:02x}").expect("writing to String cannot fail");
        }
        Ok(fingerprint)
    }
}
