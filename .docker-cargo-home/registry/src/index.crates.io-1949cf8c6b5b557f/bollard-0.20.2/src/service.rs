//! Service API: manage and inspect docker services within a swarm

use crate::container::LogOutput;
use crate::docker::BodyType;
pub use crate::models::*;

use super::Docker;
use crate::auth::{DockerCredentials, DockerCredentialsHeader};
use crate::errors::Error;
use bytes::Bytes;
use futures_core::Stream;
use http::header::CONTENT_TYPE;
use http::request::Builder;
use http_body_util::Full;
use hyper::Method;

impl Docker {
    /// ---
    ///
    /// # List Services
    ///
    /// Returns a list of services.
    ///
    /// # Arguments
    ///
    ///  - Optional [ListServicesOptions](crate::query_parameters::ListServicesOptions) struct.
    ///
    /// # Returns
    ///
    ///  - Vector of [Services](Service), wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::ListServicesOptionsBuilder;
    ///
    /// use std::collections::HashMap;
    ///
    /// let mut filters = HashMap::new();
    /// filters.insert("mode", vec!["global"]);
    ///
    /// let options = ListServicesOptionsBuilder::default()
    ///     .filters(&filters)
    ///     .build();
    ///
    /// docker.list_services(Some(options));
    /// ```
    pub async fn list_services(
        &self,
        options: Option<crate::query_parameters::ListServicesOptions>,
    ) -> Result<Vec<Service>, Error> {
        let url = "/services";

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
    /// # Create Service
    ///
    /// Dispatch a new service on the docker swarm
    ///
    /// # Arguments
    ///
    ///  - [ServiceSpec](ServiceSpec) struct.
    ///  - Optional [Docker Credentials](DockerCredentials) struct.
    ///
    /// # Returns
    ///
    ///  - A [Service Create Response](ServiceCreateResponse) struct,
    ///    wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # use std::collections::HashMap;
    /// # use std::default::Default;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::service::{
    ///     ServiceSpec,
    ///     ServiceSpecMode,
    ///     ServiceSpecModeReplicated,
    ///     TaskSpec,
    ///     TaskSpecContainerSpec
    /// };
    ///
    /// let service = ServiceSpec {
    ///     name: Some(String::from("my-service")),
    ///     mode: Some(ServiceSpecMode {
    ///         replicated: Some(ServiceSpecModeReplicated {
    ///             replicas: Some(2)
    ///         }),
    ///         ..Default::default()
    ///     }),
    ///     task_template: Some(TaskSpec {
    ///         container_spec: Some(TaskSpecContainerSpec {
    ///             image: Some(String::from("hello-world")),
    ///             ..Default::default()
    ///         }),
    ///         ..Default::default()
    ///     }),
    ///     ..Default::default()
    /// };
    /// let credentials = None;
    ///
    /// docker.create_service(service, credentials);
    /// ```
    pub async fn create_service(
        &self,
        service_spec: ServiceSpec,
        credentials: Option<DockerCredentials>,
    ) -> Result<ServiceCreateResponse, Error> {
        let url = "/services/create";

        let req = self.build_request_with_registry_auth(
            url,
            Builder::new()
                .method(Method::POST)
                .header(CONTENT_TYPE, "application/json"),
            None::<String>,
            Docker::serialize_payload(Some(service_spec)),
            DockerCredentialsHeader::Auth(credentials),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Inspect Service
    ///
    /// Inspect a service.
    ///
    /// # Arguments
    ///
    ///  - Service name or id as a string slice.
    ///  - Optional [Inspect Service Options](crate::query_parameters::InspectServiceOptions) struct.
    ///
    /// # Returns
    ///
    ///  - [Service](Service), wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::InspectServiceOptionsBuilder;
    ///
    /// let options = InspectServiceOptionsBuilder::default()
    ///     .insert_defaults(true)
    ///     .build();
    ///
    /// docker.inspect_service("my-service", Some(options));
    /// ```
    pub async fn inspect_service(
        &self,
        service_name: &str,
        options: Option<crate::query_parameters::InspectServiceOptions>,
    ) -> Result<Service, Error> {
        let url = format!("/services/{service_name}");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::GET),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Delete Service
    ///
    /// Delete a service.
    ///
    /// # Arguments
    ///
    /// - Service name or id as a string slice.
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
    /// docker.delete_service("my-service");
    /// ```
    pub async fn delete_service(&self, service_name: &str) -> Result<(), Error> {
        let url = format!("/services/{service_name}");

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
    /// # Update Service
    ///
    /// Update an existing service
    ///
    /// # Arguments
    ///
    ///  - Service name or id as a string slice.
    ///  - [ServiceSpec](ServiceSpec) struct.
    ///  - [UpdateServiceOptions](crate::query_parameters::UpdateServiceOptions) struct.
    ///  - Optional [Docker Credentials](DockerCredentials) struct.
    ///
    /// # Returns
    ///
    ///  - A [Service Update Response](ServiceUpdateResponse) struct,
    ///    wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::UpdateServiceOptionsBuilder;
    /// use bollard::service::{
    ///     ServiceSpec,
    ///     ServiceSpecMode,
    ///     ServiceSpecModeReplicated,
    ///     TaskSpec,
    ///     TaskSpecContainerSpec,
    /// };
    ///
    /// use std::default::Default;
    ///
    /// let result = async move {
    ///     let service_name = "my-service";
    ///     let current_version = docker.inspect_service(
    ///         service_name,
    ///         None
    ///     ).await?.version.unwrap().index.unwrap();
    ///     let service = ServiceSpec {
    ///         mode: Some(ServiceSpecMode {
    ///             replicated: Some(ServiceSpecModeReplicated {
    ///                 replicas: Some(0)
    ///             }),
    ///             ..Default::default()
    ///         }),
    ///         ..Default::default()
    ///     };
    ///     let options = UpdateServiceOptionsBuilder::default()
    ///         .version(current_version as i32)
    ///         .build();
    ///     let credentials = None;
    ///
    ///     docker.update_service("my-service", service, options, credentials).await
    /// };
    /// ```
    pub async fn update_service(
        &self,
        service_name: &str,
        service_spec: ServiceSpec,
        options: crate::query_parameters::UpdateServiceOptions,
        credentials: Option<DockerCredentials>,
    ) -> Result<ServiceUpdateResponse, Error> {
        let url = format!("/services/{service_name}/update");

        let req = self.build_request_with_registry_auth(
            &url,
            Builder::new()
                .method(Method::POST)
                .header(CONTENT_TYPE, "application/json"),
            Some(options),
            Docker::serialize_payload(Some(service_spec)),
            DockerCredentialsHeader::Auth(credentials),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Get Service Logs
    ///
    /// Get `stdout` and `stderr` logs from a service.
    ///
    /// # Arguments
    ///
    ///  - Service name or id as a string slice.
    ///  - Optional [Logs Options](crate::query_parameters::LogsOptions) struct.
    ///
    /// # Returns
    ///
    ///  - A Stream of [Log Output](LogOutput) results.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::LogsOptionsBuilder;
    ///
    /// let options = LogsOptionsBuilder::default()
    ///     .stdout(true)
    ///     .build();
    ///
    /// docker.service_logs("my-service", Some(options));
    /// ```
    pub fn service_logs(
        &self,
        service_id: &str,
        options: Option<impl Into<crate::query_parameters::LogsOptions>>,
    ) -> impl Stream<Item = Result<LogOutput, Error>> {
        let url = format!("/services/{service_id}/logs");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::GET),
            options.map(Into::into),
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_stream_string(req)
    }
}
