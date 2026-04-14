//! Fetch info of all running containers concurrently

use bollard::models::ContainerSummary;
use bollard::Docker;

use std::collections::HashMap;
use std::default::Default;

use futures_util::stream;
use futures_util::stream::StreamExt;

async fn conc(arg: (Docker, &ContainerSummary)) {
    let (docker, container) = arg;
    println!(
        "{:?}",
        docker
            .inspect_container(
                container.id.as_ref().unwrap(),
                None::<bollard::query_parameters::InspectContainerOptions>
            )
            .await
            .unwrap()
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    let docker = Docker::connect_with_socket_defaults().unwrap();

    let mut list_container_filters = HashMap::new();
    list_container_filters.insert(String::from("status"), vec![String::from("running")]);

    let containers = &docker
        .list_containers(Some(
            bollard::query_parameters::ListContainersOptionsBuilder::default()
                .all(true)
                .filters(&list_container_filters)
                .build(),
        ))
        .await?;

    let docker_stream = stream::repeat(docker);
    docker_stream
        .zip(stream::iter(containers))
        .for_each_concurrent(2, conc)
        .await;

    Ok(())
}
