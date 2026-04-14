use bollard::errors::Error;
use bollard::query_parameters::UpdateServiceOptionsBuilder;
use bollard::{service::*, Docker};

use futures_util::stream::StreamExt;
use tokio::runtime::Runtime;

#[macro_use]
mod common;
use crate::common::*;

async fn service_create_test(docker: Docker) -> Result<(), Error> {
    let image = if cfg!(windows) {
        format!("{}nanoserver/iis", registry_http_addr())
    } else {
        format!("{}fussybeaver/uhttpd", registry_http_addr())
    };
    let spec = ServiceSpec {
        name: Some(String::from("integration_test_create_service")),
        task_template: Some(TaskSpec {
            container_spec: Some(TaskSpecContainerSpec {
                image: Some(image),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    let response = docker.create_service(spec, None).await?;

    assert!(response.id.is_some());

    docker
        .delete_service("integration_test_create_service")
        .await?;

    Ok(())
}

async fn service_list_test(docker: Docker) -> Result<(), Error> {
    let image = if cfg!(windows) {
        format!("{}nanoserver/iis", registry_http_addr())
    } else {
        format!("{}fussybeaver/uhttpd", registry_http_addr())
    };
    let spec = ServiceSpec {
        name: Some(String::from("integration_test_list_services")),
        task_template: Some(TaskSpec {
            container_spec: Some(TaskSpecContainerSpec {
                image: Some(image),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    docker.create_service(spec, None).await?;

    let mut response = docker.list_services(None).await?;

    assert_eq!(response.len(), 1);
    assert_eq!(
        response.pop().unwrap().spec.unwrap().name.unwrap().as_str(),
        "integration_test_list_services"
    );

    docker
        .delete_service("integration_test_list_services")
        .await?;

    Ok(())
}

async fn service_update_test(docker: Docker) -> Result<(), Error> {
    let image = if cfg!(windows) {
        format!("{}nanoserver/iis", registry_http_addr())
    } else {
        format!("{}fussybeaver/uhttpd", registry_http_addr())
    };
    let spec = ServiceSpec {
        name: Some(String::from("integration_test_update_service")),
        task_template: Some(TaskSpec {
            container_spec: Some(TaskSpecContainerSpec {
                image: Some(image.clone()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    docker.create_service(spec, None).await?;

    let service_name = "integration_test_update_service";
    let current_version = docker.inspect_service(service_name, None).await?.version;
    let service = ServiceSpec {
        name: Some(String::from("integration_test_update_service")),
        task_template: Some(TaskSpec {
            container_spec: Some(TaskSpecContainerSpec {
                image: Some(image.clone()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        mode: Some(ServiceSpecMode {
            replicated: Some(ServiceSpecModeReplicated { replicas: Some(0) }),
            ..Default::default()
        }),
        ..Default::default()
    };
    let options = UpdateServiceOptionsBuilder::default()
        .version(current_version.unwrap().index.unwrap() as i32)
        .build();
    let credentials = None;

    docker
        .update_service(service_name, service, options, credentials)
        .await?;

    let mut response = docker.list_services(None).await?;

    assert_eq!(
        response
            .pop()
            .unwrap()
            .spec
            .unwrap()
            .mode
            .unwrap()
            .replicated
            .unwrap(),
        ServiceSpecModeReplicated { replicas: Some(0) }
    );

    docker
        .delete_service("integration_test_update_service")
        .await?;

    Ok(())
}

async fn service_rollback_test(docker: Docker) -> Result<(), Error> {
    let image = if cfg!(windows) {
        format!("{}nanoserver/iis", registry_http_addr())
    } else {
        format!("{}fussybeaver/uhttpd", registry_http_addr())
    };
    let spec = ServiceSpec {
        name: Some(String::from("integration_test_rollback_service")),
        task_template: Some(TaskSpec {
            container_spec: Some(TaskSpecContainerSpec {
                image: Some(image.clone()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    docker.create_service(spec, None).await?;

    let service_name = "integration_test_rollback_service";
    let current_version = docker
        .inspect_service(service_name, None)
        .await?
        .version
        .unwrap()
        .index
        .unwrap();
    let service = ServiceSpec {
        name: Some(String::from("integration_test_rollback_service")),
        task_template: Some(TaskSpec {
            container_spec: Some(TaskSpecContainerSpec {
                image: Some(image.clone()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        mode: Some(ServiceSpecMode {
            replicated: Some(ServiceSpecModeReplicated { replicas: Some(3) }),
            ..Default::default()
        }),
        ..Default::default()
    };
    let options = UpdateServiceOptionsBuilder::default()
        .version(current_version as i32)
        .build();
    let credentials = None;

    docker
        .update_service(service_name, service.clone(), options, credentials)
        .await?;
    let current_version = docker
        .inspect_service(service_name, None)
        .await?
        .version
        .unwrap()
        .index
        .unwrap();

    let options = UpdateServiceOptionsBuilder::default()
        .version(current_version as i32)
        .rollback("previous")
        .build();
    let credentials = None;

    docker
        .update_service(service_name, service.clone(), options, credentials)
        .await?;

    docker.inspect_service(service_name, None).await?;

    docker
        .delete_service("integration_test_rollback_service")
        .await?;

    Ok(())
}

async fn service_logs_test(docker: Docker) -> Result<(), Error> {
    use bollard::query_parameters::LogsOptions;

    let image = if cfg!(windows) {
        format!("{}nanoserver/iis", registry_http_addr())
    } else {
        format!("{}fussybeaver/uhttpd", registry_http_addr())
    };
    let spec = ServiceSpec {
        name: Some(String::from("integration_test_service_logs")),
        task_template: Some(TaskSpec {
            container_spec: Some(TaskSpecContainerSpec {
                image: Some(image),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    docker.create_service(spec, None).await?;

    let options = LogsOptions {
        stdout: true,
        stderr: true,
        ..Default::default()
    };

    let mut stream = docker.service_logs("integration_test_service_logs", Some(options));

    // Just verify we can call the API and get a stream
    // The stream may be empty if no logs yet, which is fine
    let _ = stream.next().await;

    docker
        .delete_service("integration_test_service_logs")
        .await?;

    Ok(())
}

#[test]
#[cfg(unix)]
fn integration_test_create_service() {
    connect_to_docker_and_run!(service_create_test);
}

#[test]
#[cfg(unix)]
fn integration_test_list_services() {
    connect_to_docker_and_run!(service_list_test);
}

#[test]
#[cfg(unix)]
fn integration_test_update_service() {
    connect_to_docker_and_run!(service_update_test);
}

#[test]
#[cfg(unix)]
fn integration_test_rollback_service() {
    connect_to_docker_and_run!(service_rollback_test);
}

#[test]
#[cfg(unix)]
fn integration_test_service_logs() {
    connect_to_docker_and_run!(service_logs_test);
}
