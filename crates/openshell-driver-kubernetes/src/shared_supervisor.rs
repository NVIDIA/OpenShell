// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generations supervised by the gateway's shared supervisor.
//!
//! Each runtime generation records where its supervisor runs when it starts.
//! Every later lifecycle decision reads that record, so changing the gateway
//! topology setting never reinterprets an existing generation.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use kube::core::DynamicObject;
use openshell_sandbox_backend::session_control::{
    SESSION_REMOVAL_TIMEOUT, SESSIONS_PATH, SessionList, SessionRegistration, SessionStatusReport,
};

use crate::config::SharedSupervisorConfig;
use crate::driver::KubernetesDriverError;

/// Supervisor placement of the current generation; absent means a dedicated
/// supervisor Pod.
pub const ANNOTATION_SUPERVISOR_TOPOLOGY: &str = "openshell.ai/sandbox-runtime-supervisor-topology";
/// Route of a generation's session on the shared supervisor.
pub const ANNOTATION_SUPERVISOR_SESSION: &str = "openshell.ai/sandbox-runtime-supervisor-session";
pub const GATEWAY_TOPOLOGY: &str = "gateway";

/// Bound on one session-control request, including connection and TLS.
/// Removals wait for the session's workload to stop and use the contract's
/// longer bound instead.
const SESSION_CONTROL_TIMEOUT: Duration = Duration::from_secs(15);

/// Where a generation's supervisor runs, as recorded when it started.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SupervisorPlacement {
    /// A supervisor Pod paired with this generation's workload Pod.
    Dedicated,
    /// A session on the gateway's shared supervisor.
    Shared { route: String },
}

/// Read the recorded placement. An unknown or incomplete record fails closed.
pub fn supervisor_placement(
    object: &DynamicObject,
) -> Result<SupervisorPlacement, KubernetesDriverError> {
    let annotations = object.metadata.annotations.as_ref();
    let annotation = |key: &str| annotations.and_then(|annotations| annotations.get(key));
    match annotation(ANNOTATION_SUPERVISOR_TOPOLOGY).map(String::as_str) {
        None => Ok(SupervisorPlacement::Dedicated),
        Some(GATEWAY_TOPOLOGY) => {
            let route = annotation(ANNOTATION_SUPERVISOR_SESSION)
                .filter(|route| {
                    openshell_sandbox_backend::runtime_routed::validate_route_handle(route).is_ok()
                })
                .ok_or_else(|| {
                    KubernetesDriverError::Precondition(
                        "shared supervisor generation has no valid session route".to_string(),
                    )
                })?;
            Ok(SupervisorPlacement::Shared {
                route: route.clone(),
            })
        }
        Some(other) => Err(KubernetesDriverError::Precondition(format!(
            "unknown sandbox-runtime supervisor topology {other:?}"
        ))),
    }
}

/// Client for the shared supervisor's session-control API. It authenticates
/// with the gateway's admission certificate, which only Helm issues.
#[derive(Clone, Debug)]
pub struct SharedSupervisor {
    config: SharedSupervisorConfig,
}

impl SharedSupervisor {
    pub fn new(config: SharedSupervisorConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &SharedSupervisorConfig {
        &self.config
    }

    /// Register a generation; an identical registration is accepted again.
    pub async fn register(
        &self,
        registration: &SessionRegistration,
    ) -> Result<SessionStatusReport, KubernetesDriverError> {
        let body = serde_json::to_vec(registration).map_err(|error| {
            KubernetesDriverError::Message(format!("encode session registration: {error}"))
        })?;
        let (status, body) = self
            .request(
                http::Method::PUT,
                &format!("{SESSIONS_PATH}/{}", registration.route),
                Some(body),
            )
            .await?;
        match status {
            http::StatusCode::CREATED | http::StatusCode::OK => decode(&body),
            http::StatusCode::CONFLICT => Err(KubernetesDriverError::Precondition(
                "shared supervisor already hosts this route with different launch material"
                    .to_string(),
            )),
            status => Err(rejected("register session", status, &body)),
        }
    }

    /// Status of one session, or `None` when it is not registered.
    pub async fn status(
        &self,
        route: &str,
    ) -> Result<Option<SessionStatusReport>, KubernetesDriverError> {
        let (status, body) = self
            .request(http::Method::GET, &format!("{SESSIONS_PATH}/{route}"), None)
            .await?;
        match status {
            http::StatusCode::OK => decode(&body).map(Some),
            http::StatusCode::NOT_FOUND => Ok(None),
            status => Err(rejected("read session status", status, &body)),
        }
    }

    /// Stop and forget one session. A missing session is already removed.
    pub async fn remove(&self, route: &str) -> Result<(), KubernetesDriverError> {
        let (status, body) = self
            .request(
                http::Method::DELETE,
                &format!("{SESSIONS_PATH}/{route}"),
                None,
            )
            .await?;
        match status {
            http::StatusCode::OK | http::StatusCode::NOT_FOUND => Ok(()),
            status => Err(rejected("remove session", status, &body)),
        }
    }

    /// Every session the shared supervisor hosts.
    pub async fn list(&self) -> Result<SessionList, KubernetesDriverError> {
        let (status, body) = self.request(http::Method::GET, SESSIONS_PATH, None).await?;
        match status {
            http::StatusCode::OK => decode(&body),
            status => Err(rejected("list sessions", status, &body)),
        }
    }

    async fn request(
        &self,
        method: http::Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(http::StatusCode, Bytes), KubernetesDriverError> {
        let deadline = if method == http::Method::DELETE {
            SESSION_REMOVAL_TIMEOUT
        } else {
            SESSION_CONTROL_TIMEOUT
        };
        tokio::time::timeout(deadline, self.request_once(method, path, body))
            .await
            .map_err(|_| {
                KubernetesDriverError::Message(
                    "timed out calling the shared supervisor session-control API".to_string(),
                )
            })?
    }

    async fn request_once(
        &self,
        method: http::Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(http::StatusCode, Bytes), KubernetesDriverError> {
        let unavailable = |what: &str, error: &dyn std::fmt::Display| {
            KubernetesDriverError::Message(format!("shared supervisor {what}: {error}"))
        };
        // Read the admission material per request so rotated Secrets apply.
        let directory = std::path::Path::new(&self.config.control_tls_dir);
        let read = |name: &str| {
            std::fs::read(directory.join(name))
                .map_err(|error| unavailable(&format!("session-control TLS file {name}"), &error))
        };
        let tls = openshell_sandbox_backend::session_control::client_tls_config(
            &read("tls.crt")?,
            &read("tls.key")?,
            &read("ca.crt")?,
        )
        .map_err(|error| unavailable("session-control TLS", &error))?;
        let host = self.config.service_host();
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|error| unavailable("session-control server name", &error))?;
        let addresses = tokio::net::lookup_host((host.as_str(), self.config.control_port))
            .await
            .map_err(|error| unavailable("resolve", &error))?
            .collect::<Vec<_>>();
        let stream = openshell_core::net::connect_tcp_nodelay_best_effort(&addresses)
            .await
            .map_err(|error| unavailable("connect", &error))?;
        let stream = tokio_rustls::TlsConnector::from(tls)
            .connect(server_name, stream)
            .await
            .map_err(|error| unavailable("TLS", &error))?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .map_err(|error| unavailable("HTTP handshake", &error))?;
        tokio::spawn(connection);
        let request = http::Request::builder()
            .method(method)
            .uri(path)
            .header(http::header::HOST, host)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.unwrap_or_default())))
            .map_err(|error| unavailable("request", &error))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|error| unavailable("request", &error))?;
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|error| unavailable("response", &error))?
            .to_bytes();
        Ok((status, body))
    }
}

fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, KubernetesDriverError> {
    serde_json::from_slice(body).map_err(|error| {
        KubernetesDriverError::Message(format!("decode shared supervisor response: {error}"))
    })
}

fn rejected(what: &str, status: http::StatusCode, body: &[u8]) -> KubernetesDriverError {
    let detail = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(|error| error.as_str().map(str::to_string))
        })
        .unwrap_or_default();
    KubernetesDriverError::Message(format!(
        "shared supervisor rejected {what} ({status}): {detail}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::{ApiResource, GroupVersionKind};

    fn object(annotations: &[(&str, &str)]) -> DynamicObject {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            "agents.x-k8s.io",
            "v1beta1",
            "Sandbox",
        ));
        let mut object = DynamicObject::new("sandbox-a", &resource);
        object.metadata.annotations = Some(
            annotations
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
        );
        object
    }

    #[test]
    fn recorded_placement_is_read_and_unknown_records_fail_closed() {
        assert_eq!(
            supervisor_placement(&object(&[])).unwrap(),
            SupervisorPlacement::Dedicated
        );
        let route = openshell_sandbox_backend::runtime_routed::new_route_handle();
        assert_eq!(
            supervisor_placement(&object(&[
                (ANNOTATION_SUPERVISOR_TOPOLOGY, GATEWAY_TOPOLOGY),
                (ANNOTATION_SUPERVISOR_SESSION, &route),
            ]))
            .unwrap(),
            SupervisorPlacement::Shared { route }
        );
        for annotations in [
            &[(ANNOTATION_SUPERVISOR_TOPOLOGY, GATEWAY_TOPOLOGY)][..],
            &[
                (ANNOTATION_SUPERVISOR_TOPOLOGY, GATEWAY_TOPOLOGY),
                (ANNOTATION_SUPERVISOR_SESSION, "Not/A/Route"),
            ],
            &[(ANNOTATION_SUPERVISOR_TOPOLOGY, "workspace")],
        ] {
            assert!(supervisor_placement(&object(annotations)).is_err());
        }
    }
}
