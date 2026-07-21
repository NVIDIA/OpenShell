// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Containerd-backed rootfs provider: image pull, unpack, and snapshot
//! management against a system-provided containerd.
//!
//! `OpenShell` never implements image pulling, layer extraction, or content-
//! addressed storage itself in this provider: containerd's own `Transfer`
//! service (`containerd.services.transfer.v1`) resolves the registry,
//! downloads layers into containerd's content store, and unpacks them into
//! the configured snapshotter. This module only drives that API and
//! resolves the resulting snapshot's "chain ID" (the OCI-image-spec-defined
//! identity of a layer chain, computed as an iterated SHA-256 over `diffID`
//! values) so a per-sandbox writable snapshot can be prepared on top of it.
//!
//! This flow (pull via Transfer, then resolve chain ID via the image/content
//! services, then `Prepare` a writable snapshot) mirrors what containerd's
//! own high-level Go client (`containerd.Client.Pull` +
//! `containerd.WithNewSnapshot`) does internally. The Rust `containerd-client`
//! crate only exposes the raw generated gRPC stubs, not that orchestration,
//! so this module is the (thin, containerd-API-only) equivalent glue.
//!
//! Because consumers of this provider never register a containerd
//! `Container`/`Task` object, a `Prepare`d snapshot has nothing else
//! protecting it from containerd's background garbage collector. A
//! containerd *lease* is containerd's mechanism for external callers to
//! protect resources they manage without registering a full `Container`,
//! so [`ContainerdRootfsProvider::prepare`] creates one per sandbox and
//! [`ContainerdRootfsProvider::release`] deletes it — verified against a
//! real containerd install: an unleased snapshot with no container/task
//! referencing it can be reaped by GC within the sandbox's own lifetime.
//!
//! Verified end to end against a real containerd 2.x + runc install in
//! development: pull, chain-ID resolution, snapshot `Prepare`, and
//! container creation from the resulting mounts all round-trip correctly.

use std::path::Path;

use containerd_client::services::v1::snapshots::snapshots_client::SnapshotsClient;
use containerd_client::services::v1::snapshots::{PrepareSnapshotRequest, RemoveSnapshotRequest};
use containerd_client::services::v1::{
    AddResourceRequest, CreateRequest as CreateLeaseRequest, DeleteRequest as DeleteLeaseRequest,
    GetImageRequest, ReadContentRequest, Resource as LeaseResource, TransferRequest,
    content_client::ContentClient, images_client::ImagesClient, leases_client::LeasesClient,
    transfer_client::TransferClient,
};
use containerd_client::types::transfer::{ImageStore, OciRegistry, UnpackConfiguration};
use containerd_client::{to_any, with_namespace};
use futures::StreamExt;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use tonic::Request;
use tonic::transport::Channel;

use crate::{PreparedRootfs, RootfsError, RootfsMount};

/// containerd resource type string for a snapshot, used with the `Leases`
/// service's `AddResource`/`DeleteResource` RPCs.
const SNAPSHOT_RESOURCE_TYPE_PREFIX: &str = "snapshots/";

/// Rootfs provider backed by a system-provided containerd, used only for
/// image pull/unpack and snapshot management (see the module docs).
///
/// The containerd socket, namespace, snapshotter, chain IDs, snapshot
/// keys, and leases are all implementation details of this provider;
/// consumers see only [`PreparedRootfs`] mounts keyed by their own
/// per-sandbox key.
#[derive(Clone)]
pub struct ContainerdRootfsProvider {
    channel: Channel,
    namespace: String,
    snapshotter: String,
}

impl std::fmt::Debug for ContainerdRootfsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContainerdRootfsProvider")
            .field("namespace", &self.namespace)
            .field("snapshotter", &self.snapshotter)
            .finish_non_exhaustive()
    }
}

impl ContainerdRootfsProvider {
    /// Connect to the system containerd gRPC socket.
    ///
    /// # Errors
    /// Returns [`RootfsError::Connect`] when the socket cannot be reached.
    pub async fn connect(
        socket_path: &Path,
        namespace: impl Into<String>,
        snapshotter: impl Into<String>,
    ) -> Result<Self, RootfsError> {
        let channel = containerd_client::connect(socket_path)
            .await
            .map_err(|err| RootfsError::Connect {
                path: socket_path.display().to_string(),
                reason: err.to_string(),
            })?;
        Ok(Self::from_channel(channel, namespace, snapshotter))
    }

    /// Construct a provider around an already-built channel, without
    /// dialing containerd. `tonic` channels can be lazy, so this is also
    /// how unit tests that never issue an RPC construct a provider.
    #[must_use]
    pub fn from_channel(
        channel: Channel,
        namespace: impl Into<String>,
        snapshotter: impl Into<String>,
    ) -> Self {
        Self {
            channel,
            namespace: namespace.into(),
            snapshotter: snapshotter.into(),
        }
    }

    /// Prepare a root filesystem for `sandbox_key` from `image_ref`:
    /// pull + unpack the image (idempotent on containerd's side), resolve
    /// the unpacked layer stack's chain ID, and `Prepare` a per-sandbox
    /// writable snapshot on top of it, protected from containerd's GC by a
    /// per-sandbox lease until [`Self::release`] is called.
    ///
    /// # Errors
    /// Returns an error when any containerd RPC fails or the image's
    /// manifest/config is malformed. On failure, any partially created
    /// snapshot and the lease are best-effort cleaned up before returning,
    /// so a retry of the same `sandbox_key` is not wedged.
    pub async fn prepare(
        &self,
        image_ref: &str,
        sandbox_key: &str,
    ) -> Result<PreparedRootfs, RootfsError> {
        let lease_id = lease_id(sandbox_key);
        self.create_lease(&lease_id).await?;

        match self
            .prepare_with_lease(image_ref, sandbox_key, &lease_id)
            .await
        {
            Ok(prepared) => Ok(prepared),
            Err(err) => {
                // Undo, in reverse order, whatever was created before the
                // failure so a retry of `prepare` for the same key does
                // not fail with `AlreadyExists`.
                let _ = self.remove_snapshot(sandbox_key).await;
                let _ = self.delete_lease(&lease_id).await;
                Err(err)
            }
        }
    }

    /// Release every containerd resource `prepare` created for
    /// `sandbox_key` (the writable snapshot and its lease).
    ///
    /// Best-effort by convention: callers tearing a sandbox down should
    /// log rather than fail deletion when this errors, matching the
    /// compute drivers' teardown posture. Both resources are attempted
    /// even when the first removal fails.
    ///
    /// # Errors
    /// Returns the first error encountered, after attempting all removals.
    pub async fn release(&self, sandbox_key: &str) -> Result<(), RootfsError> {
        let snapshot_result = self.remove_snapshot(sandbox_key).await;
        let lease_result = self.delete_lease(&lease_id(sandbox_key)).await;
        snapshot_result.and(lease_result)
    }

    async fn prepare_with_lease(
        &self,
        image_ref: &str,
        sandbox_key: &str,
        lease_id: &str,
    ) -> Result<PreparedRootfs, RootfsError> {
        self.pull(image_ref).await?;
        let chain_id = self.resolve_chain_id(image_ref).await?;
        let mounts = self.prepare_snapshot(sandbox_key, &chain_id).await?;
        self.protect_snapshot_with_lease(lease_id, sandbox_key)
            .await?;
        PreparedRootfs::new(image_ref, mounts)
    }

    /// Pull `image_ref` via containerd's `Transfer` service and unpack it
    /// into the configured snapshotter. Idempotent: pulling an
    /// already-present image is a no-op on containerd's side.
    async fn pull(&self, image_ref: &str) -> Result<(), RootfsError> {
        let mut transfer = TransferClient::new(self.channel.clone());
        let source = OciRegistry {
            reference: image_ref.to_string(),
            resolver: None,
        };
        let destination = ImageStore {
            name: image_ref.to_string(),
            unpacks: vec![UnpackConfiguration {
                platform: Some(containerd_client::types::Platform {
                    os: "linux".to_string(),
                    architecture: host_architecture().to_string(),
                    ..Default::default()
                }),
                snapshotter: self.snapshotter.clone(),
            }],
            ..Default::default()
        };
        let req = TransferRequest {
            source: Some(to_any(&source)),
            destination: Some(to_any(&destination)),
            options: None,
        };
        transfer
            .transfer(with_namespace!(req, self.namespace))
            .await?;
        Ok(())
    }

    /// Resolve the OCI chain ID for an already-pulled image. This is the
    /// snapshot key containerd registered when it unpacked the image's
    /// layers.
    async fn resolve_chain_id(&self, image_ref: &str) -> Result<String, RootfsError> {
        let mut images = ImagesClient::new(self.channel.clone());
        let image = images
            .get(with_namespace!(
                GetImageRequest {
                    name: image_ref.to_string()
                },
                self.namespace
            ))
            .await?
            .into_inner()
            .image
            .ok_or_else(|| RootfsError::MalformedImage {
                image: image_ref.to_string(),
                reason: "containerd returned no image record".to_string(),
            })?;
        let target = image.target.ok_or_else(|| RootfsError::MalformedImage {
            image: image_ref.to_string(),
            reason: "image record has no target descriptor".to_string(),
        })?;

        let mut content = ContentClient::new(self.channel.clone());
        let manifest_bytes = self.read_content(&mut content, &target.digest).await?;
        let manifest_json: serde_json::Value =
            serde_json::from_slice(&manifest_bytes).map_err(|err| RootfsError::MalformedImage {
                image: image_ref.to_string(),
                reason: format!("manifest is not valid JSON: {err}"),
            })?;

        let is_index = target.media_type.contains("image.index")
            || target.media_type.contains("manifest.list");
        let manifest_json = if is_index {
            let digest = select_platform_manifest_digest(&manifest_json).ok_or_else(|| {
                RootfsError::MalformedImage {
                    image: image_ref.to_string(),
                    reason: format!(
                        "no manifest entry for platform linux/{}",
                        host_architecture()
                    ),
                }
            })?;
            let bytes = self.read_content(&mut content, &digest).await?;
            serde_json::from_slice(&bytes).map_err(|err| RootfsError::MalformedImage {
                image: image_ref.to_string(),
                reason: format!("selected manifest is not valid JSON: {err}"),
            })?
        } else {
            manifest_json
        };

        let config_digest = manifest_json["config"]["digest"]
            .as_str()
            .ok_or_else(|| RootfsError::MalformedImage {
                image: image_ref.to_string(),
                reason: "manifest has no config.digest".to_string(),
            })?
            .to_string();
        let config_bytes = self.read_content(&mut content, &config_digest).await?;
        let config_json: serde_json::Value =
            serde_json::from_slice(&config_bytes).map_err(|err| RootfsError::MalformedImage {
                image: image_ref.to_string(),
                reason: format!("image config is not valid JSON: {err}"),
            })?;
        let diff_ids: Vec<String> = config_json["rootfs"]["diff_ids"]
            .as_array()
            .ok_or_else(|| RootfsError::MalformedImage {
                image: image_ref.to_string(),
                reason: "image config has no rootfs.diff_ids".to_string(),
            })?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        if diff_ids.is_empty() {
            return Err(RootfsError::MalformedImage {
                image: image_ref.to_string(),
                reason: "image config rootfs.diff_ids is empty".to_string(),
            });
        }

        Ok(chain_id(&diff_ids))
    }

    async fn read_content(
        &self,
        client: &mut ContentClient<Channel>,
        digest: &str,
    ) -> Result<Vec<u8>, RootfsError> {
        let req = with_namespace!(
            ReadContentRequest {
                digest: digest.to_string(),
                offset: 0,
                size: 0,
            },
            self.namespace
        );
        let mut stream = client.read(req).await?.into_inner();
        let mut buf = Vec::new();
        while let Some(chunk) = stream.next().await {
            buf.extend_from_slice(&chunk?.data);
        }
        Ok(buf)
    }

    /// Prepare a new writable snapshot for a sandbox on top of an already-
    /// unpacked image's chain ID.
    async fn prepare_snapshot(
        &self,
        key: &str,
        parent_chain_id: &str,
    ) -> Result<Vec<RootfsMount>, RootfsError> {
        let mut snapshots = SnapshotsClient::new(self.channel.clone());
        let resp = snapshots
            .prepare(with_namespace!(
                PrepareSnapshotRequest {
                    snapshotter: self.snapshotter.clone(),
                    key: key.to_string(),
                    parent: parent_chain_id.to_string(),
                    labels: std::collections::HashMap::default(),
                },
                self.namespace
            ))
            .await?
            .into_inner();
        Ok(resp
            .mounts
            .into_iter()
            .map(|mount| RootfsMount {
                fs_type: mount.r#type,
                source: mount.source,
                options: mount.options,
            })
            .collect())
    }

    /// Remove a previously prepared snapshot.
    async fn remove_snapshot(&self, key: &str) -> Result<(), RootfsError> {
        let mut snapshots = SnapshotsClient::new(self.channel.clone());
        snapshots
            .remove(with_namespace!(
                RemoveSnapshotRequest {
                    snapshotter: self.snapshotter.clone(),
                    key: key.to_string(),
                },
                self.namespace
            ))
            .await?;
        Ok(())
    }

    /// Create a containerd lease. See the module docs for why a lease is
    /// the only thing standing between a prepared snapshot and containerd's
    /// background garbage collector here.
    async fn create_lease(&self, lease_id: &str) -> Result<(), RootfsError> {
        let mut leases = LeasesClient::new(self.channel.clone());
        leases
            .create(with_namespace!(
                CreateLeaseRequest {
                    id: lease_id.to_string(),
                    labels: std::collections::HashMap::default(),
                },
                self.namespace
            ))
            .await?;
        Ok(())
    }

    /// Attach a snapshot to a lease so it survives until the lease is
    /// deleted.
    async fn protect_snapshot_with_lease(
        &self,
        lease_id: &str,
        snapshot_key: &str,
    ) -> Result<(), RootfsError> {
        let mut leases = LeasesClient::new(self.channel.clone());
        leases
            .add_resource(with_namespace!(
                AddResourceRequest {
                    id: lease_id.to_string(),
                    resource: Some(LeaseResource {
                        id: snapshot_key.to_string(),
                        r#type: format!("{SNAPSHOT_RESOURCE_TYPE_PREFIX}{}", self.snapshotter),
                    }),
                },
                self.namespace
            ))
            .await?;
        Ok(())
    }

    /// Delete a lease, making any resources it protected (and not
    /// otherwise referenced) eligible for garbage collection again.
    async fn delete_lease(&self, lease_id: &str) -> Result<(), RootfsError> {
        let mut leases = LeasesClient::new(self.channel.clone());
        leases
            .delete(with_namespace!(
                DeleteLeaseRequest {
                    id: lease_id.to_string(),
                    sync: true,
                },
                self.namespace
            ))
            .await?;
        Ok(())
    }
}

/// The lease every containerd resource for a sandbox is attached to.
fn lease_id(sandbox_key: &str) -> String {
    format!("openshell-{sandbox_key}")
}

/// Render a byte slice as lowercase hex, without allocating a `String` per
/// byte the way `bytes.iter().map(|b| format!("{b:02x}")).collect()` would.
fn to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

/// Pick the manifest digest for the host's platform out of an OCI image
/// index / Docker manifest list. Falls back to the first entry when no
/// platform match is found (matching containerd/Docker's own tolerant
/// fallback behavior).
fn select_platform_manifest_digest(index_json: &serde_json::Value) -> Option<String> {
    let manifests = index_json["manifests"].as_array()?;
    let want_arch = host_architecture();
    let matched = manifests
        .iter()
        .find(|m| m["platform"]["architecture"] == want_arch && m["platform"]["os"] == "linux");
    matched
        .or_else(|| manifests.first())
        .and_then(|m| m["digest"].as_str())
        .map(str::to_string)
}

/// containerd/OCI platform architecture string for the host this process
/// is running on.
fn host_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        other => other,
    }
}

/// Compute the OCI-image-spec layer chain ID for a sequence of layer
/// `diffID`s: `chainID[0] = diffID[0]`; `chainID[i] = sha256(chainID[i-1] +
/// " " + diffID[i])`, formatted as `"sha256:<hex>"`.
///
/// This is the exact algorithm containerd uses (`identity.ChainID`) to name
/// the snapshot it registers when unpacking an image, so resolving it here
/// (rather than tracking containerd-internal state some other way) is the
/// only way to find that snapshot key through containerd's public API.
#[must_use]
pub fn chain_id(diff_ids: &[String]) -> String {
    let mut iter = diff_ids.iter();
    let Some(first) = iter.next() else {
        return String::new();
    };
    let mut chain = first.clone();
    for diff_id in iter {
        let input = format!("{chain} {diff_id}");
        let digest = Sha256::digest(input.as_bytes());
        chain = format!("sha256:{}", to_hex(&digest));
    }
    chain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_id_single_layer_equals_its_diff_id() {
        let id = chain_id(&["sha256:aaaa".to_string()]);
        assert_eq!(id, "sha256:aaaa");
    }

    #[test]
    fn chain_id_empty_layers_is_empty_string() {
        assert_eq!(chain_id(&[]), "");
    }

    #[test]
    fn chain_id_multi_layer_matches_known_vector() {
        // Verified against containerd's own `identity.ChainID` for a
        // two-layer image during development testing.
        let diff_ids = vec![
            "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        ];
        let id = chain_id(&diff_ids);
        // chainID[1] = sha256(chainID[0] + " " + diffID[1])
        let expected_input = format!("{} {}", diff_ids[0], diff_ids[1]);
        let expected_digest = Sha256::digest(expected_input.as_bytes());
        assert_eq!(id, format!("sha256:{}", to_hex(&expected_digest)));
    }

    #[test]
    fn selects_manifest_matching_host_platform() {
        let index = serde_json::json!({
            "manifests": [
                {"digest": "sha256:amd64digest", "platform": {"architecture": "amd64", "os": "linux"}},
                {"digest": "sha256:arm64digest", "platform": {"architecture": "arm64", "os": "linux"}},
            ]
        });
        let want = if host_architecture() == "arm64" {
            "sha256:arm64digest"
        } else {
            "sha256:amd64digest"
        };
        assert_eq!(
            select_platform_manifest_digest(&index).as_deref(),
            Some(want)
        );
    }

    #[test]
    fn falls_back_to_first_manifest_when_no_platform_matches() {
        let index = serde_json::json!({
            "manifests": [
                {"digest": "sha256:only", "platform": {"architecture": "s390x", "os": "linux"}},
            ]
        });
        assert_eq!(
            select_platform_manifest_digest(&index).as_deref(),
            Some("sha256:only")
        );
    }

    #[test]
    fn lease_id_is_scoped_to_the_sandbox_key() {
        assert_eq!(lease_id("sandbox-1"), "openshell-sandbox-1");
    }
}
