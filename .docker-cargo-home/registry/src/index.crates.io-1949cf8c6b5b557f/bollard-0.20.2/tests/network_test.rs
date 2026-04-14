extern crate bollard;
extern crate hyper;
extern crate tokio;

use bollard::errors::Error;
use bollard::models::*;
use bollard::query_parameters::{
    InspectNetworkOptionsBuilder, KillContainerOptions, ListNetworksOptionsBuilder,
    RemoveContainerOptions,
};
use bollard::Docker;

use tokio::runtime::Runtime;

use std::collections::HashMap;

#[macro_use]
pub mod common;
use crate::common::*;

async fn create_network_test(docker: Docker) -> Result<(), Error> {
    let ipam_config = IpamConfig {
        subnet: Some(String::from("10.10.10.0/24")),
        ..Default::default()
    };

    let create_network_request = NetworkCreateRequest {
        name: String::from("integration_test_create_network"),
        driver: Some(if cfg!(windows) {
            String::from("transparent")
        } else {
            String::from("bridge")
        }),
        ipam: Some(Ipam {
            config: Some(vec![ipam_config]),
            ..Default::default()
        }),
        ..Default::default()
    };

    let result = &docker.create_network(create_network_request).await?;

    let inspect_options = InspectNetworkOptionsBuilder::default()
        .verbose(true)
        .build();

    let result = &docker
        .inspect_network(
            <String as AsRef<str>>::as_ref(&result.id),
            Some(inspect_options),
        )
        .await?;

    assert!(result
        .ipam
        .as_ref()
        .unwrap()
        .config
        .as_ref()
        .unwrap()
        .iter()
        .take(1)
        .any(|i| &i.subnet.as_ref().unwrap()[..] == "10.10.10.0/24"));

    let _ = &docker
        .remove_network("integration_test_create_network")
        .await?;

    Ok(())
}

async fn list_networks_test(docker: Docker) -> Result<(), Error> {
    let ipam_config = IpamConfig {
        subnet: Some(String::from("10.10.10.0/24")),
        ..Default::default()
    };

    let mut create_network_labels = HashMap::new();
    create_network_labels.insert(
        String::from("maintainer"),
        String::from("bollard-maintainer"),
    );

    let create_network_request = NetworkCreateRequest {
        name: String::from("integration_test_list_network"),
        driver: Some(if cfg!(windows) {
            String::from("transparent")
        } else {
            String::from("bridge")
        }),
        ipam: Some(Ipam {
            config: Some(vec![ipam_config]),
            ..Default::default()
        }),
        labels: Some(create_network_labels),
        ..Default::default()
    };

    let mut list_networks_filters = HashMap::new();
    list_networks_filters.insert("label", vec!["maintainer=bollard-maintainer"]);

    let _ = &docker.create_network(create_network_request).await?;

    let list_options = ListNetworksOptionsBuilder::default()
        .filters(&list_networks_filters)
        .build();

    let results = &docker.list_networks(Some(list_options)).await?;

    let v = results.first().unwrap();

    assert!(v
        .ipam
        .as_ref()
        .unwrap()
        .config
        .as_ref()
        .unwrap()
        .iter()
        .any(|i| &i.subnet.as_ref().unwrap()[..] == "10.10.10.0/24"));

    let _ = &docker
        .remove_network("integration_test_list_network")
        .await?;

    Ok(())
}

async fn connect_network_test(docker: Docker) -> Result<(), Error> {
    let ipam_config = IpamConfig {
        subnet: Some(String::from("10.10.10.0/24")),
        ..Default::default()
    };

    let create_network_request = NetworkCreateRequest {
        name: String::from("integration_test_connect_network"),
        ipam: Some(Ipam {
            config: Some(vec![ipam_config]),
            ..Default::default()
        }),
        ..Default::default()
    };

    let connect_network_request = NetworkConnectRequest {
        container: String::from("integration_test_connect_network_test"),
        endpoint_config: Some(EndpointSettings {
            ipam_config: Some(EndpointIpamConfig {
                ipv4_address: Some(String::from("10.10.10.101")),
                ..Default::default()
            }),
            ..Default::default()
        }),
    };

    create_daemon(&docker, "integration_test_connect_network_test").await?;

    let result = &docker.create_network(create_network_request).await?;

    let _ = &docker
        .connect_network(
            <String as AsRef<str>>::as_ref(&result.id),
            connect_network_request,
        )
        .await?;

    let id = <String as AsRef<str>>::as_ref(&result.id);

    let inspect_options = InspectNetworkOptionsBuilder::default()
        .verbose(true)
        .build();

    let result = &docker.inspect_network(id, Some(inspect_options)).await?;

    assert!(result
        .containers
        .as_ref()
        .unwrap()
        .iter()
        .any(|(_, container)| container.ipv4_address == Some("10.10.10.101/24".into())));

    let disconnect_request = NetworkDisconnectRequest {
        container: String::from("integration_test_connect_network_test"),
        force: Some(true),
    };

    let _ = &docker.disconnect_network(id, disconnect_request).await?;

    let _ = &docker.remove_network(id).await?;

    let _ = &docker
        .kill_container(
            "integration_test_connect_network_test",
            None::<KillContainerOptions>,
        )
        .await?;

    let _ = &docker
        .remove_container(
            "integration_test_connect_network_test",
            None::<RemoveContainerOptions>,
        )
        .await?;

    Ok(())
}

async fn prune_networks_test(docker: Docker) -> Result<(), Error> {
    let create_network_request = NetworkCreateRequest {
        name: String::from("integration_test_prune_networks"),
        attachable: Some(true),
        driver: Some(if cfg!(windows) {
            String::from("transparent")
        } else {
            String::from("bridge")
        }),
        ..Default::default()
    };

    let mut list_networks_filters = HashMap::new();
    list_networks_filters.insert("scope", vec!["global"]);

    let _ = &docker.create_network(create_network_request).await?;

    let result = &docker.prune_networks(None).await?;

    assert_eq!(
        "integration_test_prune_networks",
        result.networks_deleted.as_ref().unwrap()[0]
    );

    let list_options = ListNetworksOptionsBuilder::default()
        .filters(&list_networks_filters)
        .build();

    let results = &docker.list_networks(Some(list_options)).await?;

    assert_eq!(0, results.len());

    Ok(())
}

#[test]
#[cfg(unix)]
// Hangs on Appveyor
fn integration_test_create_network() {
    connect_to_docker_and_run!(create_network_test);
}

#[test]
#[cfg(unix)]
// Hangs on Appveyor
fn integration_test_list_networks() {
    connect_to_docker_and_run!(list_networks_test);
}

#[test]
#[cfg(unix)]
// Not possible to test this on Appveyor...
fn integration_test_connect_network() {
    connect_to_docker_and_run!(connect_network_test);
}

#[test]
#[cfg(unix)]
// Hangs on Appveyor
fn integration_test_prune_networks() {
    connect_to_docker_and_run!(prune_networks_test);
}
