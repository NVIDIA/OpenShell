//! Node API: Nodes are instances of the Engine participating in a swarm. Swarm mode must be enabled for these endpoints to work.

use bollard_stubs::models::{Node, NodeSpec};
use bytes::Bytes;
use http_body_util::Full;

use crate::{docker::BodyType, errors::Error, Docker};
use http::{request::Builder, Method};

impl Docker {
    /// ---
    ///
    /// # List Nodes
    ///
    /// # Arguments
    ///
    ///  - Optional [List Nodes Options](crate::query_parameters::ListNodesOptions) struct.
    ///
    /// # Returns
    ///
    ///  - A vector of [Node](Node) struct, wrapped in a
    ///    Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::ListNodesOptionsBuilder;
    ///
    /// use std::collections::HashMap;
    ///
    /// let mut filters = HashMap::new();
    /// filters.insert("node.label", vec!["my-node-label"]);
    ///
    /// let options = ListNodesOptionsBuilder::default()
    ///     .filters(&filters)
    ///     .build();
    ///
    /// docker.list_nodes(Some(options));
    /// ```
    pub async fn list_nodes(
        &self,
        options: Option<crate::query_parameters::ListNodesOptions>,
    ) -> Result<Vec<Node>, Error> {
        let url = "/nodes";

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
    /// # Inspect a Node
    ///
    /// # Arguments
    ///
    ///  - Node id or name as a string slice.
    ///
    /// # Returns
    ///
    ///  - A [Models](Node) struct, wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    ///
    /// docker.inspect_node("my_node_name");
    /// ```
    pub async fn inspect_node(&self, node_name: &str) -> Result<Node, Error> {
        let url = format!("/nodes/{node_name}");

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
    /// # Delete Node
    ///
    /// Delete a node.
    ///
    /// # Arguments
    ///
    /// - Node id or name as a string slice.
    /// - Optional [Delete Node Options](crate::query_parameters::DeleteNodeOptions) struct.
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
    /// use bollard::query_parameters::DeleteNodeOptionsBuilder;
    ///
    /// let options = DeleteNodeOptionsBuilder::default()
    ///     .force(true)
    ///     .build();
    ///
    /// docker.delete_node("my-node", Some(options));
    /// ```
    pub async fn delete_node(
        &self,
        node_name: &str,
        options: Option<crate::query_parameters::DeleteNodeOptions>,
    ) -> Result<(), Error> {
        let url = format!("/nodes/{node_name}");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::DELETE),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Update Node
    ///
    /// Update a node.
    ///
    /// # Arguments
    ///
    ///  - Node id as string slice.
    ///  - [Update Node Options](crate::query_parameters::UpdateNodeOptions) struct.
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
    /// use bollard::query_parameters::UpdateNodeOptionsBuilder;
    /// use bollard::models::{NodeSpec, NodeSpecAvailabilityEnum, NodeSpecRoleEnum};
    ///
    /// let spec = NodeSpec {
    ///     availability: Some(NodeSpecAvailabilityEnum::ACTIVE),
    ///     name: Some("my-new-node-name".to_string()),
    ///     role: Some(NodeSpecRoleEnum::MANAGER),
    ///     ..Default::default()
    /// };
    ///
    /// let options = UpdateNodeOptionsBuilder::default()
    ///     .version(2)
    ///     .build();
    ///
    /// docker.update_node("my-node-id", spec, options);
    /// ```
    pub async fn update_node(
        &self,
        node_id: &str,
        spec: NodeSpec,
        options: crate::query_parameters::UpdateNodeOptions,
    ) -> Result<(), Error> {
        let url = format!("/nodes/{node_id}/update");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::POST),
            Some(options),
            Docker::serialize_payload(Some(spec)),
        );

        self.process_into_unit(req).await
    }
}
