//! Secret API: manage and inspect docker secrets within a swarm

use crate::models::*;

use super::Docker;
use crate::{docker::BodyType, errors::Error};
use bytes::Bytes;
use http::request::Builder;
use http_body_util::Full;
use hyper::Method;

impl Docker {
    /// ---
    ///
    /// # List Secrets
    ///
    /// Returns a list of secrets.
    ///
    /// # Arguments
    ///
    ///  - Optional [ListSecretsOptions](crate::query_parameters::ListSecretsOptions) struct.
    ///
    /// # Returns
    ///
    ///  - Vector of [Secret](Secret), wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::ListSecretsOptionsBuilder;
    ///
    /// use std::collections::HashMap;
    ///
    /// let mut filters = HashMap::new();
    /// filters.insert("label", vec!["secret-label=label-value"]);
    ///
    /// let options = ListSecretsOptionsBuilder::default()
    ///     .filters(&filters)
    ///     .build();
    ///
    /// docker.list_secrets(Some(options));
    /// ```
    pub async fn list_secrets(
        &self,
        options: Option<crate::query_parameters::ListSecretsOptions>,
    ) -> Result<Vec<Secret>, Error> {
        let url = "/secrets";

        let req = self.build_request(
            url,
            Builder::new().method(Method::GET),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Create Secret
    ///
    /// Create new secret on the docker swarm.
    ///
    /// # Arguments
    ///
    ///  - [SecretSpec](SecretSpec) struct.
    ///
    /// # Returns
    ///
    ///  - A [IdResponse](IdResponse) wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # use std::default::Default;
    /// # use base64::Engine;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::models::SecretSpec;
    ///
    /// use base64;
    ///
    /// let secret_spec = SecretSpec {
    ///     name: Some(String::from("secret-name")),
    ///     data: Some(base64::engine::general_purpose::STANDARD.encode("secret-data")),
    ///     ..Default::default()
    /// };
    ///
    /// docker.create_secret(secret_spec);
    /// ```
    pub async fn create_secret(&self, secret_spec: SecretSpec) -> Result<IdResponse, Error> {
        let url = "/secrets/create";

        let req = self.build_request(
            url,
            Builder::new().method(Method::POST),
            None::<String>,
            Docker::serialize_payload(Some(secret_spec)),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Inspect Secret
    ///
    /// Inspect a secret.
    ///
    /// # Arguments
    ///
    ///  - Secret id or name as a string slice.
    ///
    /// # Returns
    ///
    ///  - [Secret](Secret), wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    ///
    /// docker.inspect_secret("secret-id");
    /// docker.inspect_secret("secret-name");
    /// ```
    pub async fn inspect_secret(&self, secret_id: &str) -> Result<Secret, Error> {
        let url = format!("/secrets/{secret_id}");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::GET),
            None::<String>,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Delete Secret
    ///
    /// Delete a secret, fails when more than one service use that secret..
    ///
    /// # Arguments
    ///
    ///  - Secret id or name as a string slice.
    ///
    /// # Returns
    ///
    ///  - unit type `()`, wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    ///
    /// docker.delete_secret("secret-id");
    /// docker.delete_secret("secret-name");
    /// ```
    pub async fn delete_secret(&self, secret_id: &str) -> Result<(), Error> {
        let url = format!("/secrets/{secret_id}");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::DELETE),
            None::<String>,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Update Secret
    ///
    /// Update an existing secret,
    /// fails when more than one service use that secret or trying update data.
    ///
    /// # Arguments
    ///
    ///  - Secret id or name as a string slice.
    ///  - [SecretSpec](SecretSpec) struct.
    ///  - [UpdateSecretOptions](crate::query_parameters::UpdateSecretOptions) struct.
    ///
    /// # Returns
    ///
    ///  - unit type `()`, wrapped in a Future.
    ///
    /// # Examples
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    ///
    /// use std::collections::HashMap;
    /// use bollard::query_parameters::UpdateSecretOptionsBuilder;
    ///
    /// let result = async move {
    ///     let existing = docker.inspect_secret("my-secret").await?;
    ///     let version = existing.version.unwrap().index.unwrap();
    ///     let mut spec = existing.spec.unwrap().clone();
    ///
    ///     let mut labels = HashMap::new();
    ///     labels.insert(String::from("secret-label"), String::from("label-value"));
    ///     spec.labels = Some(labels.clone());
    ///
    ///     let options = UpdateSecretOptionsBuilder::default()
    ///         .version(version as i64)
    ///         .build();
    ///
    ///     docker.update_secret("my-secret", spec, options).await
    /// };
    /// ```
    pub async fn update_secret(
        &self,
        secret_id: &str,
        secret_spec: SecretSpec,
        options: crate::query_parameters::UpdateSecretOptions,
    ) -> Result<(), Error> {
        let url = format!("/secrets/{secret_id}/update");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::POST),
            Some(options),
            Docker::serialize_payload(Some(secret_spec)),
        );

        self.process_into_unit(req).await
    }
}
