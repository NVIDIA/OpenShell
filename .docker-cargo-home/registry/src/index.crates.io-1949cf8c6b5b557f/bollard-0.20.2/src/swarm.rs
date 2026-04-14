//! Swarm API: Docker swarm is a container orchestration tool, meaning that it allows the user to manage multiple containers deployed across multiple host machines.

use crate::docker::BodyType;

use hyper::Method;

use bytes::Bytes;
use http::request::Builder;
use http_body_util::Full;

use super::Docker;
use crate::errors::Error;

use crate::models::*;

impl Docker {
    /// ---
    ///
    /// # Init Swarm
    ///
    /// Initialize a new swarm.
    ///
    /// # Arguments
    ///
    ///  - [SwarmInitRequest](SwarmInitRequest) struct.
    ///
    /// # Returns
    ///
    ///  - A String wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::models::SwarmInitRequest;
    ///
    /// use std::default::Default;
    ///
    /// let config = SwarmInitRequest {
    ///     advertise_addr: Some("127.0.0.1".to_string()),
    ///     listen_addr: Some("0.0.0.0:2377".to_string()),
    ///     ..Default::default()
    /// };
    ///
    /// docker.init_swarm(config);
    /// ```
    pub async fn init_swarm(&self, config: SwarmInitRequest) -> Result<String, Error> {
        let url = "/swarm/init";

        let req = self.build_request(
            url,
            Builder::new().method(Method::POST),
            None::<String>,
            Docker::serialize_payload(Some(config)),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Inspect Swarm
    ///
    /// Inspect swarm.
    ///
    /// # Arguments
    ///
    /// # Returns
    ///
    ///  - [Swarm](Swarm) struct, wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    ///
    /// docker.inspect_swarm();
    /// ```
    pub async fn inspect_swarm(&self) -> Result<Swarm, Error> {
        let url = "/swarm";

        let req = self.build_request(
            url,
            Builder::new().method(Method::GET),
            None::<String>,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Join a Swarm
    ///
    /// # Arguments
    ///
    ///  - [SwarmJoinRequest](SwarmJoinRequest) struct.
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
    /// use bollard::models::SwarmJoinRequest;
    ///
    /// let config = SwarmJoinRequest {
    ///     advertise_addr: Some("127.0.0.1".to_string()),
    ///     join_token: Some("token".to_string()),
    ///     ..Default::default()
    /// };
    /// docker.join_swarm(config);
    /// ```
    pub async fn join_swarm(&self, config: SwarmJoinRequest) -> Result<(), Error> {
        let url = "/swarm/join";

        let req = self.build_request(
            url,
            Builder::new().method(Method::POST),
            None::<String>,
            Docker::serialize_payload(Some(config)),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Leave a Swarm
    ///
    /// # Arguments
    ///
    ///  - Optional [LeaveSwarmOptions](crate::query_parameters::LeaveSwarmOptions) struct.
    ///
    /// # Returns
    ///
    ///  - unit type `()`, wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # use bollard::query_parameters::LeaveSwarmOptionsBuilder;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    ///
    /// let options = LeaveSwarmOptionsBuilder::default()
    ///     .force(true)
    ///     .build();
    ///
    /// docker.leave_swarm(Some(options));
    /// ```
    pub async fn leave_swarm(
        &self,
        options: Option<crate::query_parameters::LeaveSwarmOptions>,
    ) -> Result<(), Error> {
        let url = "/swarm/leave";

        let req = self.build_request(
            url,
            Builder::new().method(Method::POST),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Update a Swarm
    ///
    /// Update a swarm's configuration.
    ///
    /// # Arguments
    ///
    ///  - [SwarmSpec](SwarmSpec) struct.
    ///  - [UpdateSwarmOptions](crate::query_parameters::UpdateSwarmOptions) struct.
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
    /// use bollard::query_parameters::UpdateSwarmOptionsBuilder;
    ///
    /// let result = async move {
    ///     let swarm = docker.inspect_swarm().await?;
    ///     let version = swarm.version.unwrap().index.unwrap();
    ///     let spec = swarm.spec.unwrap();
    ///
    ///     let options = UpdateSwarmOptionsBuilder::default()
    ///         .version(version as i64)
    ///         .build();
    ///
    ///     docker.update_swarm(spec, options).await
    /// };
    /// ```
    pub async fn update_swarm(
        &self,
        swarm_spec: SwarmSpec,
        options: crate::query_parameters::UpdateSwarmOptions,
    ) -> Result<(), Error> {
        let url = "/swarm/update";

        let req = self.build_request(
            url,
            Builder::new().method(Method::POST),
            Some(options),
            Docker::serialize_payload(Some(swarm_spec)),
        );

        self.process_into_unit(req).await
    }
}
