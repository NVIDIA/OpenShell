use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bollard::errors::Error;
use bollard::query_parameters::{ListSecretsOptionsBuilder, UpdateSecretOptionsBuilder};
use bollard::{models::*, Docker};

use tokio::runtime::Runtime;

#[macro_use]
mod common;
use crate::common::*;

async fn secret_create_test(docker: Docker) -> Result<(), Error> {
    let mut labels = HashMap::new();
    labels.insert(
        String::from("secret-label"),
        String::from("secert-label-value"),
    );

    let spec = SecretSpec {
        name: Some(String::from("secret_create_test")),
        data: Some(STANDARD.encode("BOLLARD")),
        labels: Some(labels),
        ..Default::default()
    };
    let secret_id = docker.create_secret(spec.clone()).await?.id;

    let inspect_by_id = docker.inspect_secret(&secret_id).await?;
    let spec_by_id = inspect_by_id.spec.unwrap();
    assert_eq!(
        spec_by_id.name.as_ref().unwrap(),
        spec.name.as_ref().unwrap()
    );
    assert_eq!(
        spec_by_id.labels.as_ref().unwrap(),
        spec.labels.as_ref().unwrap()
    );

    let inspect_by_name = docker.inspect_secret(spec.name.as_ref().unwrap()).await?;
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

    docker.delete_secret(&secret_id).await?;

    match docker.inspect_secret(&secret_id).await {
        Ok(..) => panic!("Found deleted secret"),
        Err(e) => match e {
            Error::DockerResponseServerError { status_code, .. } => {
                assert_eq!(status_code, 404);
            }
            _ => panic!("Unexpected error"),
        },
    }

    Ok(())
}

async fn secret_list_test(docker: Docker) -> Result<(), Error> {
    let mut labels = HashMap::new();
    labels.insert(String::from("secret-label"), String::from("filter-value"));

    let spec = SecretSpec {
        name: Some(String::from("secret_list_test")),
        data: Some(STANDARD.encode("BOLLARD")),
        labels: Some(labels),
        ..Default::default()
    };
    let secret_id = docker.create_secret(spec).await?.id;

    let mut filters = HashMap::new();
    filters.insert("label", vec!["secret-label=filter-value"]);

    let options = ListSecretsOptionsBuilder::default()
        .filters(&filters)
        .build();

    let mut secrets = docker.list_secrets(Some(options)).await?;

    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets.pop().unwrap().id.unwrap(), secret_id);

    docker.delete_secret(&secret_id).await?;

    Ok(())
}

async fn secret_update_test(docker: Docker) -> Result<(), Error> {
    let spec = SecretSpec {
        name: Some(String::from("secret_update_test")),
        data: Some(STANDARD.encode("BOLLARD")),
        ..Default::default()
    };

    docker.create_secret(spec).await?;

    let existing = docker.inspect_secret("secret_update_test").await?;
    let version = existing.version.unwrap().index.unwrap();
    let id = existing.id.unwrap();
    let mut spec = existing.spec.unwrap().clone();

    let mut labels = HashMap::new();
    labels.insert(String::from("secret-label"), String::from("label-value"));
    spec.labels = Some(labels.clone());

    let options = UpdateSecretOptionsBuilder::default()
        .version(version as i64)
        .build();

    docker
        .update_secret("secret_update_test", spec, options)
        .await?;

    let inspected = docker.inspect_secret(&id).await?;
    let inspected_spec = inspected.spec.as_ref().unwrap();
    assert_eq!(&labels, inspected_spec.labels.as_ref().unwrap());

    docker.delete_secret(&id).await?;

    Ok(())
}

#[test]
#[cfg(unix)]
fn integration_test_create_secret() {
    connect_to_docker_and_run!(secret_create_test);
}

#[test]
#[cfg(unix)]
fn integration_test_list_secrets() {
    connect_to_docker_and_run!(secret_list_test);
}

#[test]
#[cfg(unix)]
fn integration_test_update_secret() {
    connect_to_docker_and_run!(secret_update_test);
}
