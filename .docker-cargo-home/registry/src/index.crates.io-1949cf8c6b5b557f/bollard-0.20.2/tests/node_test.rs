extern crate bollard;
extern crate hyper;
extern crate tokio;

use bollard::errors::Error;
use bollard::models::*;
use bollard::query_parameters::{ListNodesOptionsBuilder, UpdateNodeOptionsBuilder};
use bollard::Docker;

use tokio::runtime::Runtime;

use std::collections::HashMap;

#[macro_use]
pub mod common;
use crate::common::*;

async fn list_nodes_test(docker: Docker) -> Result<(), Error> {
    let mut filters = HashMap::new();
    filters.insert("role", vec!["manager"]);

    let options = ListNodesOptionsBuilder::default().filters(&filters).build();

    let nodes = docker.list_nodes(Some(options)).await?;
    assert_eq!(
        nodes.len(),
        1,
        "expected to test against a single node swarm"
    );
    assert_eq!(
        nodes[0].status.as_ref().and_then(|s| s.state),
        Some(NodeState::READY),
        "expected the node state to be ready"
    );
    assert_eq!(
        nodes[0].spec.as_ref().and_then(|s| s.role),
        Some(NodeSpecRoleEnum::MANAGER),
        "expected the node to be a manager"
    );
    Ok(())
}

async fn inspect_node_test(docker: Docker) -> Result<(), Error> {
    let mut filters = HashMap::new();
    filters.insert("role", vec!["manager"]);

    let options = ListNodesOptionsBuilder::default().filters(&filters).build();

    let nodes = docker.list_nodes(Some(options)).await?;
    assert_eq!(
        nodes.len(),
        1,
        "expected to test against a single node swarm"
    );

    let node = docker
        .inspect_node(nodes[0].id.as_deref().expect("node should have id"))
        .await?;
    assert_eq!(nodes[0], node, "returned node does not match");
    Ok(())
}

async fn update_node_test(docker: Docker) -> Result<(), Error> {
    let mut filters = HashMap::new();
    filters.insert("role", vec!["manager"]);

    let options = ListNodesOptionsBuilder::default().filters(&filters).build();

    let nodes = docker.list_nodes(Some(options)).await?;
    assert_eq!(
        nodes.len(),
        1,
        "expected to test against a single node swarm"
    );

    let id = nodes[0].id.as_deref().expect("node should have id");

    let version = nodes[0]
        .version
        .as_ref()
        .and_then(|v| v.index)
        .expect("node should have a version");

    let update_options = UpdateNodeOptionsBuilder::default()
        .version(version as i64)
        .build();

    docker
        .update_node(
            id,
            NodeSpec {
                availability: Some(NodeSpecAvailabilityEnum::ACTIVE),
                labels: Some(HashMap::from_iter([(
                    "test-label-name".to_string(),
                    "test-label-value".to_string(),
                )])),
                role: Some(NodeSpecRoleEnum::MANAGER),
                ..Default::default()
            },
            update_options,
        )
        .await?;

    let node = docker.inspect_node(id).await?;
    assert_eq!(
        node.spec
            .as_ref()
            .and_then(|s| s.labels.as_ref())
            .expect("node should have labels")
            .get("test-label-name")
            .map(|s| s.as_str()),
        Some("test-label-value"),
        "label is not the expected value"
    );
    Ok(())
}

#[test]
#[cfg(unix)]
fn integration_test_list_nodes() {
    connect_to_docker_and_run!(list_nodes_test);
}

#[test]
#[cfg(unix)]
fn integration_test_inspect_node() {
    connect_to_docker_and_run!(inspect_node_test);
}

#[test]
#[cfg(unix)]
fn integration_test_update_node() {
    connect_to_docker_and_run!(update_node_test);
}
