//! Credentials management, for access to the Docker Hub or a custom Registry.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[allow(missing_docs)]
/// DockerCredentials credentials and server URI to push images using the [Push Image
/// API](crate::Docker::push_image()) or the [Build Image
/// API](../struct.Docker.html#method.build_image).
pub struct DockerCredentials {
    pub username: Option<String>,
    pub password: Option<String>,
    pub auth: Option<String>,
    pub email: Option<String>,
    pub serveraddress: Option<String>,
    pub identitytoken: Option<String>,
    pub registrytoken: Option<String>,
}

pub(crate) enum DockerCredentialsHeader {
    /// Credentials of a single registry sent as an X-Registry-Auth header
    Auth(Option<DockerCredentials>),
    /// Credentials of multiple registries sent as an X-Registry-Config header
    Config(Option<HashMap<String, DockerCredentials>>),
}

pub(crate) fn base64_url_encode(payload: &str) -> String {
    STANDARD.encode(payload)
}
