//! Config API: manage and inspect docker configs within a swarm

pub use crate::models::*;

use super::Docker;
use crate::{docker::BodyType, errors::Error};
use bytes::Bytes;
use http::request::Builder;
use http_body_util::Full;
use hyper::Method;

impl Docker {
    /// ---
    ///
    /// # List Configs
    ///
    /// Returns a list of configs.
    ///
    /// # Arguments
    ///
    ///  - Optional [ListConfigsOptions](crate::query_parameters::ListConfigsOptions) struct.
    ///
    /// # Returns
    ///
    ///  - Vector of [Config](Config), wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::ListConfigsOptionsBuilder;
    ///
    /// use std::collections::HashMap;
    /// use std::default::Default;
    ///
    /// let mut filters = HashMap::new();
    /// filters.insert("label", vec!["config-label=label-value"]);
    ///
    /// let filters: HashMap<String, Vec<String>> = filters.into_iter().map(|(k, v)| (k.to_string(), v.into_iter().map(String::from).collect())).collect();
    /// let options = ListConfigsOptionsBuilder::default()
    ///     .filters(&filters)
    ///     .build();
    ///
    /// docker.list_configs(Some(options));
    /// ```
    pub async fn list_configs(
        &self,
        options: Option<crate::query_parameters::ListConfigsOptions>,
    ) -> Result<Vec<Config>, Error> {
        let url = "/configs";

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
    /// # Create Config
    ///
    /// Create a new config on the docker swarm.
    ///
    /// # Arguments
    ///
    ///  - [ConfigSpec](ConfigSpec) struct.
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
    /// use bollard::config::ConfigSpec;
    ///
    /// use base64;
    ///
    /// let config_spec = ConfigSpec {
    ///     name: Some(String::from("config-name")),
    ///     data: Some(base64::engine::general_purpose::STANDARD.encode("config-data")),
    ///     ..Default::default()
    /// };
    ///
    /// docker.create_config(config_spec);
    /// ```
    pub async fn create_config(&self, config_spec: ConfigSpec) -> Result<IdResponse, Error> {
        let url = "/configs/create";

        let req = self.build_request(
            url,
            Builder::new().method(Method::POST),
            None::<String>,
            Docker::serialize_payload(Some(config_spec)),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Inspect Config
    ///
    /// Inspect a config.
    ///
    /// # Arguments
    ///
    ///  - Config id or name as a string slice.
    ///
    /// # Returns
    ///
    ///  - [Config](Config), wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    ///
    /// docker.inspect_config("config-id");
    /// docker.inspect_config("config-name");
    /// ```
    pub async fn inspect_config(&self, config_id: &str) -> Result<Config, Error> {
        let url = format!("/configs/{config_id}");

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
    /// # Delete Config
    ///
    /// Delete a config.
    ///
    /// # Arguments
    ///
    ///  - Config id or name as a string slice.
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
    /// docker.delete_config("config-id");
    /// docker.delete_config("config-name");
    /// ```
    pub async fn delete_config(&self, config_id: &str) -> Result<(), Error> {
        let url = format!("/configs/{config_id}");

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
    /// # Update Config
    ///
    /// Update an existing config.
    ///
    /// # Arguments
    ///
    ///  - Config id or name as a string slice.
    ///  - [ConfigSpec](ConfigSpec) struct.
    ///  - [UpdateConfigOptions](crate::query_parameters::UpdateConfigOptions) struct.
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
    /// use bollard::query_parameters::UpdateConfigOptionsBuilder;
    ///
    /// let result = async move {
    ///     let existing = docker.inspect_config("my-config").await?;
    ///     let version = existing.version.unwrap().index.unwrap();
    ///     let mut spec = existing.spec.unwrap().clone();
    ///
    ///     let mut labels = HashMap::new();
    ///     labels.insert(String::from("config-label"), String::from("label-value"));
    ///     spec.labels = Some(labels.clone());
    ///
    ///     let options = UpdateConfigOptionsBuilder::default()
    ///         .version(version as i64)
    ///         .build();
    ///
    ///     docker.update_config("my-config", spec, options).await
    /// };
    /// ```
    pub async fn update_config(
        &self,
        config_id: &str,
        config_spec: ConfigSpec,
        options: crate::query_parameters::UpdateConfigOptions,
    ) -> Result<(), Error> {
        let url = format!("/configs/{config_id}/update");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::POST),
            Some(options),
            Docker::serialize_payload(Some(config_spec)),
        );

        self.process_into_unit(req).await
    }
}
