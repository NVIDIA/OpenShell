// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Extracted credential-driver implementation.

use super::CredentialDriver;
use async_trait::async_trait;
use openshell_core::proto::CredentialHandle;
use openshell_core::proto::credentials::v1::{
    DeleteCredentialRequest, ResolveCredentialRequest, ResolvedCredential, StoreCredentialRequest,
};
use std::collections::HashMap;
use tonic::Status;

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
pub(super) struct TestStaticCredentialDriver {
    values: std::sync::Mutex<HashMap<String, String>>,
    fail_next_store: std::sync::atomic::AtomicBool,
    fail_next_delete: std::sync::atomic::AtomicBool,
    #[cfg(any(test, feature = "test-support"))]
    resolve_gate: std::sync::Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
    #[cfg(any(test, feature = "test-support"))]
    store_gate: std::sync::Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
}

#[cfg(any(test, feature = "test-support"))]
impl TestStaticCredentialDriver {
    pub(super) const NAME: &'static str = "test-static";

    pub(super) fn new() -> Self {
        Self {
            values: std::sync::Mutex::new(HashMap::new()),
            fail_next_store: std::sync::atomic::AtomicBool::new(false),
            fail_next_delete: std::sync::atomic::AtomicBool::new(false),
            #[cfg(any(test, feature = "test-support"))]
            resolve_gate: std::sync::Mutex::new(None),
            #[cfg(any(test, feature = "test-support"))]
            store_gate: std::sync::Mutex::new(None),
        }
    }

    fn handle_from_request(
        request_id: &str,
        handle: Option<CredentialHandle>,
    ) -> Result<CredentialHandle, Status> {
        handle.ok_or_else(|| {
            Status::invalid_argument(format!(
                "test-static credential request '{request_id}' is missing handle"
            ))
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
#[async_trait]
impl CredentialDriver for TestStaticCredentialDriver {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        #[cfg(any(test, feature = "test-support"))]
        let gate = self.store_gate.lock().ok().and_then(|mut gate| gate.take());
        #[cfg(any(test, feature = "test-support"))]
        if let Some((hit, release)) = gate {
            let _ = hit.send(());
            let _ = release.await;
        }
        if self
            .fail_next_store
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(Status::unavailable("injected credential store failure"));
        }
        let handle = request
            .existing_handle
            .map(|handle| handle.handle)
            .filter(|handle| !handle.trim().is_empty())
            .unwrap_or_else(|| {
                format!(
                    "{}:{}:{}",
                    request.provider, request.credential_key, request.object_id
                )
            });
        self.values
            .lock()
            .map_err(|_| Status::internal("test-static credential store lock poisoned"))?
            .insert(handle.clone(), request.value);
        Ok(CredentialHandle {
            driver: Self::NAME.to_string(),
            handle,
            metadata: HashMap::new(),
        })
    }

    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        if self
            .fail_next_delete
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(Status::unavailable("injected credential delete failure"));
        }
        let handle = Self::handle_from_request("delete", request.handle)?;
        self.values
            .lock()
            .map_err(|_| Status::internal("test-static credential store lock poisoned"))?
            .remove(&handle.handle);
        Ok(())
    }

    async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        let mut responses = Vec::with_capacity(requests.len());
        #[cfg(any(test, feature = "test-support"))]
        let gate = self
            .resolve_gate
            .lock()
            .ok()
            .and_then(|mut gate| gate.take());
        #[cfg(any(test, feature = "test-support"))]
        if let Some((hit, release)) = gate {
            let _ = hit.send(());
            let _ = release.await;
        }
        for request in requests {
            let handle = Self::handle_from_request(&request.request_id, request.handle)?;
            let value = self
                .values
                .lock()
                .map_err(|_| Status::internal("test-static credential store lock poisoned"))?
                .get(&handle.handle)
                .cloned()
                .ok_or_else(|| Status::not_found("test-static credential handle not found"))?;
            responses.push(ResolvedCredential {
                request_id: request.request_id,
                value,
                expiration_time: None,
            });
        }

        Ok(responses)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn stored_credential_count(&self) -> Option<usize> {
        self.values.lock().ok().map(|values| values.len())
    }

    #[cfg(any(test, feature = "test-support"))]
    fn fail_next_store(&self) {
        self.fail_next_store
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(any(test, feature = "test-support"))]
    fn gate_next_resolve(
        &self,
    ) -> Option<(
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    )> {
        let (hit_tx, hit_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        *self.resolve_gate.lock().ok()? = Some((hit_tx, release_rx));
        Some((hit_rx, release_tx))
    }

    #[cfg(any(test, feature = "test-support"))]
    fn fail_next_delete(&self) {
        self.fail_next_delete
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(any(test, feature = "test-support"))]
    fn gate_next_store(
        &self,
    ) -> Option<(
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    )> {
        let (hit_tx, hit_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        *self.store_gate.lock().ok()? = Some((hit_tx, release_rx));
        Some((hit_rx, release_tx))
    }
}
