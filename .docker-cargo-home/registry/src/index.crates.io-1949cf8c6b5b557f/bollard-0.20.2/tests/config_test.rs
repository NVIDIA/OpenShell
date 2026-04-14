use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bollard::errors::Error;
use bollard::query_parameters::{ListConfigsOptionsBuilder, UpdateConfigOptionsBuilder};
use bollard::{config::*, Docker};

use tokio::runtime::Runtime;

#[macro_use]
mod common;
use crate::common::*;

async fn config_create_test(docker: Docker) -> Result<(), Error> {
    let mut labels = HashMap::new();
    labels.insert(
        String::from("config-label"),
        String::from("config-label-value"),
    );

    let spec = ConfigSpec {
        name: Some(String::from("config_create_test")),
        data: Some(STANDARD.encode("BOLLARD_CONFIG")),
        labels: Some(labels),
        ..Default::default()
    };
    let config_id = docker.create_config(spec.clone()).await?.id;

    let inspect_by_id = docker.inspect_config(&config_id).await?;
    let spec_by_id = inspect_by_id.spec.unwrap();
    assert_eq!(
        spec_by_id.name.as_ref().unwrap(),
        spec.name.as_ref().unwrap()
    );
    assert_eq!(
        spec_by_id.labels.as_ref().unwrap(),
        spec.labels.as_ref().unwrap()
    );

    let inspect_by_name = docker.inspect_config(spec.name.as_ref().unwrap()).await?;
    let spec_by_name = inspect_by_name.spec.unwrap();
    assert_eq!(
        spec_by_name.name.as_ref().unwrap(),
        spec.name.as_ref().unwrap()
    );
    assert_eq!(
        spec_by_name.labels.as_ref().unwrap(),
        spec.labels.as_ref().unwrap()
    );

    assert_eq!(
        inspect_by_id.id.as_ref().unwrap(),
        inspect_by_name.id.as_ref().unwrap()
    );

    docker.delete_config(&config_id).await?;

    match docker.inspect_config(&config_id).await {
        Ok(..) => panic!("Found deleted config"),
        Err(e) => match e {
            Error::DockerResponseServerError { status_code, .. } => {
                assert_eq!(status_code, 404);
            }
            _ => panic!("Unexpected error"),
        },
    }

    Ok(())
}

async fn config_list_test(docker: Docker) -> Result<(), Error> {
    let mut labels = HashMap::new();
    labels.insert(String::from("config-label"), String::from("filter-value"));

    let spec = ConfigSpec {
        name: Some(String::from("config_list_test")),
        data: Some(STANDARD.encode("BOLLARD_CONFIG")),
        labels: Some(labels),
        ..Default::default()
    };
    let config_id = docker.create_config(spec).await?.id;

    let mut filters: HashMap<String, Vec<String>> = HashMap::new();
    filters.insert(
        "label".to_string(),
        vec!["config-label=filter-value".to_string()],
    );

    let options = ListConfigsOptionsBuilder::default()
        .filters(&filters)
        .build();

    let mut configs = docker.list_configs(Some(options)).await?;

    assert_eq!(configs.len(), 1);
    assert_eq!(configs.pop().unwrap().id.unwrap(), config_id);

    docker.delete_config(&config_id).await?;

    Ok(())
}

async fn config_update_test(docker: Docker) -> Result<(), Error> {
    let spec = ConfigSpec {
        name: Some(String::from("config_update_test")),
        data: Some(STANDARD.encode("BOLLARD_CONFIG")),
        ..Default::default()
    };

    docker.create_config(spec).await?;

    let existing = docker.inspect_config("config_update_test").await?;
    let version = existing.version.unwrap().index.unwrap();
    let id = existing.id.unwrap();
    let mut spec = existing.spec.unwrap().clone();

    let mut labels = HashMap::new();
    labels.insert(String::from("config-label"), String::from("label-value"));
    spec.labels = Some(labels.clone());

    let options = UpdateConfigOptionsBuilder::default()
        .version(version as i64)
        .build();

    docker
        .update_config("config_update_test", spec, options)
        .await?;

    let inspected = docker.inspect_config(&id).await?;
    let inspected_spec = inspected.spec.as_ref().unwrap();
    assert_eq!(&labels, inspected_spec.labels.as_ref().unwrap());

    docker.delete_config(&id).await?;

    Ok(())
}

#[test]
#[cfg(unix)]
fn integration_test_create_config() {
    connect_to_docker_and_run!(config_create_test);
}

#[test]
#[cfg(unix)]
fn integration_test_list_configs() {
    connect_to_docker_and_run!(config_list_test);
}

#[test]
#[cfg(unix)]
fn integration_test_update_config() {
    connect_to_docker_and_run!(config_update_test);
}
