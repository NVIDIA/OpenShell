//! System API: interface for interacting with the Docker server and/or Registry.

use bytes::Bytes;
use futures_core::Stream;
use http::request::Builder;
use http_body_util::Full;
use hyper::Method;

use super::Docker;
use crate::docker::BodyType;
use crate::errors::Error;
use crate::models::*;

impl Docker {
    /// ---
    ///
    /// # Version
    ///
    /// Returns the version of Docker that is running and various information about the system that
    /// Docker is running on.
    ///
    /// # Returns
    ///
    ///  - [SystemVersion](crate::models::SystemVersion), wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// docker.version();
    /// ```
    pub async fn version(&self) -> Result<SystemVersion, Error> {
        let req = self.build_request(
            "/version",
            Builder::new().method(Method::GET),
            None::<String>,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Info
    ///
    /// Returns Docker client and server information that is running.
    ///
    /// # Returns
    ///
    ///  - [Info](SystemInfo), wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// docker.info();
    /// ```
    pub async fn info(&self) -> Result<SystemInfo, Error> {
        let req = self.build_request(
            "/info",
            Builder::new().method(Method::GET),
            None::<String>,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Ping
    ///
    /// This is a dummy endpoint you can use to test if the server is accessible.
    /// # Returns - A [String](std::string::String), wrapped in a Future. # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    ///
    /// docker.ping();
    /// ```
    pub async fn ping(&self) -> Result<String, Error> {
        let url = "/_ping";

        let req = self.build_request(
            url,
            Builder::new().method(Method::GET),
            None::<String>,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_string(req).await
    }

    /// ---
    ///
    /// # Events
    ///
    /// Stream real-time events from the server.
    ///
    /// # Returns
    ///
    ///  - [EventMessage](crate::models::EventMessage),
    ///    wrapped in a Stream.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bollard::query_parameters::EventsOptionsBuilder;
    /// use std::collections::HashMap;
    ///
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    ///
    /// let mut filters = HashMap::new();
    /// filters.insert("type", vec!["container"]);
    ///
    /// let options = EventsOptionsBuilder::default()
    ///     .since("1h")
    ///     .filters(&filters)
    ///     .build();
    ///
    /// docker.events(Some(options));
    /// ```
    pub fn events(
        &self,
        options: Option<crate::query_parameters::EventsOptions>,
    ) -> impl Stream<Item = Result<EventMessage, Error>> {
        let url = "/events";

        let req = self.build_request(
            url,
            Builder::new().method(Method::GET),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_stream(req)
    }

    /// ---
    ///
    /// # Get data usage information
    ///
    /// Show docker disk usage
    ///
    /// # Returns
    ///
    ///  - [System Data Usage
    ///    Response](SystemDataUsageResponse), wrapped in a
    ///    Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # use bollard::query_parameters::DataUsageOptions;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// docker.df(None::<DataUsageOptions>);
    /// ```
    pub async fn df(
        &self,
        options: Option<crate::query_parameters::DataUsageOptions>,
    ) -> Result<SystemDataUsageResponse, Error> {
        let url = "/system/df";

        let req = self.build_request(
            url,
            Builder::new().method(Method::GET),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_value(req).await
    }
}
