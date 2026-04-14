//! Network API: Networks are user-defined networks that containers can be attached to.

use bytes::Bytes;
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
    /// # Create Network
    ///
    /// Create a new network.
    ///
    /// # Arguments
    ///
    ///  - [NetworkCreateRequest](NetworkCreateRequest) struct.
    ///
    /// # Returns
    ///
    ///  - A [Network Create Response](NetworkCreateResponse) struct, wrapped in a
    ///    Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::models::NetworkCreateRequest;
    ///
    /// let config = NetworkCreateRequest {
    ///     name: String::from("certs"),
    ///     ..Default::default()
    /// };
    ///
    /// docker.create_network(config);
    /// ```
    pub async fn create_network(
        &self,
        config: NetworkCreateRequest,
    ) -> Result<NetworkCreateResponse, Error> {
        let url = "/networks/create";

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
    /// # Remove a Network
    ///
    /// # Arguments
    ///
    ///  - Network name as a string slice.
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
    /// docker.remove_network("my_network_name");
    /// ```
    pub async fn remove_network(&self, network_name: &str) -> Result<(), Error> {
        let url = format!("/networks/{network_name}");

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
    /// # Inspect a Network
    ///
    /// # Arguments
    ///
    ///  - Network name as a string slice.
    ///  - Optional [InspectNetworkOptions](crate::query_parameters::InspectNetworkOptions) struct.
    ///
    /// # Returns
    ///
    ///  - A [NetworkInspect](NetworkInspect) struct, wrapped in a
    ///    Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::InspectNetworkOptionsBuilder;
    ///
    /// let options = InspectNetworkOptionsBuilder::default()
    ///     .verbose(true)
    ///     .scope("global")
    ///     .build();
    ///
    /// docker.inspect_network("my_network_name", Some(options));
    /// ```
    pub async fn inspect_network(
        &self,
        network_name: &str,
        options: Option<crate::query_parameters::InspectNetworkOptions>,
    ) -> Result<NetworkInspect, Error> {
        let url = format!("/networks/{network_name}");

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
    /// # List Networks
    ///
    /// # Arguments
    ///
    ///  - Optional [ListNetworksOptions](crate::query_parameters::ListNetworksOptions) struct.
    ///
    /// # Returns
    ///
    ///  - A vector of [Network](Network) struct, wrapped in a
    ///    Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::ListNetworksOptionsBuilder;
    ///
    /// use std::collections::HashMap;
    ///
    /// let mut filters = HashMap::new();
    /// filters.insert("label", vec!["maintainer=some_maintainer"]);
    ///
    /// let options = ListNetworksOptionsBuilder::default()
    ///     .filters(&filters)
    ///     .build();
    ///
    /// docker.list_networks(Some(options));
    /// ```
    pub async fn list_networks(
        &self,
        options: Option<crate::query_parameters::ListNetworksOptions>,
    ) -> Result<Vec<Network>, Error> {
        let url = "/networks";

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
    /// # Connect Network
    ///
    /// # Arguments
    ///
    ///  - Network name as a string slice.
    ///  - A [NetworkConnectRequest](NetworkConnectRequest) struct.
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
    /// use bollard::models::{NetworkConnectRequest, EndpointSettings, EndpointIpamConfig};
    ///
    /// let config = NetworkConnectRequest {
    ///     container: String::from("3613f73ba0e4"),
    ///     endpoint_config: Some(EndpointSettings {
    ///         ipam_config: Some(EndpointIpamConfig {
    ///             ipv4_address: Some(String::from("172.24.56.89")),
    ///             ipv6_address: Some(String::from("2001:db8::5689")),
    ///             ..Default::default()
    ///         }),
    ///         ..Default::default()
    ///     }),
    /// };
    ///
    /// docker.connect_network("my_network_name", config);
    /// ```
    pub async fn connect_network(
        &self,
        network_name: &str,
        config: NetworkConnectRequest,
    ) -> Result<(), Error> {
        let url = format!("/networks/{network_name}/connect");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::POST),
            None::<String>,
            Docker::serialize_payload(Some(config)),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Disconnect Network
    ///
    /// # Arguments
    ///
    ///  - Network name as a string slice.
    ///  - A [NetworkDisconnectRequest](NetworkDisconnectRequest) struct.
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
    /// use bollard::models::NetworkDisconnectRequest;
    ///
    /// let config = NetworkDisconnectRequest {
    ///     container: String::from("3613f73ba0e4"),
    ///     force: Some(true),
    /// };
    ///
    /// docker.disconnect_network("my_network_name", config);
    /// ```
    pub async fn disconnect_network(
        &self,
        network_name: &str,
        config: NetworkDisconnectRequest,
    ) -> Result<(), Error> {
        let url = format!("/networks/{network_name}/disconnect");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::POST),
            None::<String>,
            Docker::serialize_payload(Some(config)),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Prune Networks
    ///
    /// Deletes networks which are unused.
    ///
    /// # Arguments
    ///
    ///  - Optional [PruneNetworksOptions](crate::query_parameters::PruneNetworksOptions) struct.
    ///
    /// # Returns
    ///
    ///  - A [Network Prune Response](NetworkPruneResponse) struct.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::PruneNetworksOptionsBuilder;
    ///
    /// use std::collections::HashMap;
    ///
    /// let mut filters = HashMap::new();
    /// filters.insert("label", vec!["maintainer=some_maintainer"]);
    ///
    /// let options = PruneNetworksOptionsBuilder::default()
    ///     .filters(&filters)
    ///     .build();
    ///
    /// docker.prune_networks(Some(options));
    /// ```
    pub async fn prune_networks(
        &self,
        options: Option<crate::query_parameters::PruneNetworksOptions>,
    ) -> Result<NetworkPruneResponse, Error> {
        let url = "/networks/prune";

        let req = self.build_request(
            url,
            Builder::new().method(Method::POST),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_value(req).await
    }
}
