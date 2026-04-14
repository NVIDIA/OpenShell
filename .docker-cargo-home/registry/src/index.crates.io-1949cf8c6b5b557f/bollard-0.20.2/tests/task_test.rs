extern crate bollard;
extern crate hyper;
extern crate tokio;

use bollard::errors::Error;
use bollard::models::*;
use bollard::query_parameters::ListTasksOptionsBuilder;
use bollard::query_parameters::LogsOptions;
use bollard::Docker;

use futures_util::stream::StreamExt;
use tokio::runtime::Runtime;
use tokio::time::sleep;

use std::collections::HashMap;
use std::time::Duration;

#[macro_use]
pub mod common;
use crate::common::*;

async fn list_tasks_test(docker: Docker) -> Result<(), Error> {
    const SERVICE_NAME: &str = "integration_test_list_tasks";

    let image = if cfg!(windows) {
        format!("{}nanoserver/iis", registry_http_addr())
    } else {
        format!("{}fussybeaver/uhttpd", registry_http_addr())
    };
    let spec = ServiceSpec {
        name: Some(String::from(SERVICE_NAME)),
        mode: Some(ServiceSpecMode {
            replicated: Some(ServiceSpecModeReplicated { replicas: Some(1) }),
            ..Default::default()
        }),
        task_template: Some(TaskSpec {
            container_spec: Some(TaskSpecContainerSpec {
                image: Some(image),
                ..Default::default()
            }),
            restart_policy: Some(TaskSpecRestartPolicy {
                condition: Some(TaskSpecRestartPolicyConditionEnum::NONE),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    let response = docker.create_service(spec, None).await?;
    assert!(response.id.is_some());

    // Wait for a task to be created
    let mut tasks;
    loop {
        let options = ListTasksOptionsBuilder::default()
            .filters(&HashMap::from_iter([("service", vec![SERVICE_NAME])]))
            .build();
        tasks = docker.list_tasks(Some(options)).await?;

        if !tasks.is_empty() {
            break;
        }

        sleep(Duration::from_millis(100)).await;
    }

    assert_eq!(tasks.len(), 1, "expected one task");

    docker.delete_service(SERVICE_NAME).await?;
    Ok(())
}

async fn inspect_task_test(docker: Docker) -> Result<(), Error> {
    const SERVICE_NAME: &str = "integration_test_list_tasks";

    let image = if cfg!(windows) {
        format!("{}nanoserver/iis", registry_http_addr())
    } else {
        format!("{}fussybeaver/uhttpd", registry_http_addr())
    };
    let spec = ServiceSpec {
        name: Some(String::from(SERVICE_NAME)),
        mode: Some(ServiceSpecMode {
            replicated: Some(ServiceSpecModeReplicated { replicas: Some(1) }),
            ..Default::default()
        }),
        task_template: Some(TaskSpec {
            container_spec: Some(TaskSpecContainerSpec {
                image: Some(image),
                ..Default::default()
            }),
            restart_policy: Some(TaskSpecRestartPolicy {
                condition: Some(TaskSpecRestartPolicyConditionEnum::NONE),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    let response = docker.create_service(spec, None).await?;
    assert!(response.id.is_some());

    // The maximum amount of time we'll wait for Docker to start the task
    const MAX_WAIT_DURATION: Duration = Duration::from_secs(10);
    // The amount of time to sleep between attempts
    const SLEEP_DURATION: Duration = Duration::from_millis(100);

    // Wait for a task to be created
    let mut tasks;
    let mut attempt = 0;
    loop {
        if MAX_WAIT_DURATION.saturating_sub(SLEEP_DURATION * attempt) == Duration::ZERO {
            panic!("the Docker daemon took to long to start a task");
        }

        let options = ListTasksOptionsBuilder::default()
            .filters(&HashMap::from_iter([("service", vec![SERVICE_NAME])]))
            .build();
        tasks = docker.list_tasks(Some(options)).await?;

        if !tasks.is_empty() {
            break;
        }

        sleep(SLEEP_DURATION).await;
        attempt += 1;
    }

    assert_eq!(tasks.len(), 1, "expected one task");

    let task = docker
        .inspect_task(tasks[0].id.as_deref().expect("task should have id"))
        .await?;
    assert_eq!(tasks[0].id, task.id, "task identifiers are not the same");

    docker.delete_service(SERVICE_NAME).await?;
    Ok(())
}

async fn task_logs_test(docker: Docker) -> Result<(), Error> {
    const SERVICE_NAME: &str = "integration_test_task_logs";

    let image = if cfg!(windows) {
        format!("{}nanoserver/iis", registry_http_addr())
    } else {
        format!("{}fussybeaver/uhttpd", registry_http_addr())
    };
    let spec = ServiceSpec {
        name: Some(String::from(SERVICE_NAME)),
        mode: Some(ServiceSpecMode {
            replicated: Some(ServiceSpecModeReplicated { replicas: Some(1) }),
            ..Default::default()
        }),
        task_template: Some(TaskSpec {
            container_spec: Some(TaskSpecContainerSpec {
                image: Some(image),
                ..Default::default()
            }),
            restart_policy: Some(TaskSpecRestartPolicy {
                condition: Some(TaskSpecRestartPolicyConditionEnum::NONE),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    let response = docker.create_service(spec, None).await?;
    assert!(response.id.is_some());

    // Wait for a task to be created
    let mut tasks;
    loop {
        let options = ListTasksOptionsBuilder::default()
            .filters(&HashMap::from_iter([("service", vec![SERVICE_NAME])]))
            .build();
        tasks = docker.list_tasks(Some(options)).await?;

        if !tasks.is_empty() {
            break;
        }

        sleep(Duration::from_millis(100)).await;
    }

    assert_eq!(tasks.len(), 1, "expected one task");

    let task_id = tasks[0].id.as_deref().expect("task should have id");

    let options = LogsOptions {
        stdout: true,
        stderr: true,
        ..Default::default()
    };

    let mut stream = docker.task_logs(task_id, Some(options));

    // Just verify we can call the API and get a stream
    // The stream may be empty if no logs yet, which is fine
    let _ = stream.next().await;

    docker.delete_service(SERVICE_NAME).await?;
    Ok(())
}

#[test]
#[cfg(unix)]
fn integration_test_list_tasks() {
    connect_to_docker_and_run!(list_tasks_test);
}

#[test]
#[cfg(unix)]
fn integration_test_inspect_task() {
    connect_to_docker_and_run!(inspect_task_test);
}

#[test]
#[cfg(unix)]
fn integration_test_task_logs() {
    connect_to_docker_and_run!(task_logs_test);
}
