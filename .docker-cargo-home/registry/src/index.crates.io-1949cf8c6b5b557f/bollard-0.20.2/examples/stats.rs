//! Stream stats for all running Docker containers asynchronously
use bollard::Docker;

use futures_util::stream::StreamExt;

use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let docker = Docker::connect_with_socket_defaults().unwrap();

    loop {
        let mut filter = HashMap::new();
        filter.insert(String::from("status"), vec![String::from("running")]);
        let containers = &docker
            .list_containers(Some(
                bollard::query_parameters::ListContainersOptionsBuilder::default()
                    .all(true)
                    .filters(&filter)
                    .build(),
            ))
            .await?;

        if containers.is_empty() {
            panic!("no running containers");
        } else {
            for container in containers {
                let container_id = container.id.as_ref().unwrap();
                let stream = &mut docker
                    .stats(
                        container_id,
                        Some(
                            bollard::query_parameters::StatsOptionsBuilder::default()
                                .stream(false)
                                .build(),
                        ),
                    )
                    .take(1);

                while let Some(Ok(stats)) = stream.next().await {
                    println!(
                        "{} - {:?}: {:?} {:?}",
                        container_id, &container.names, container.image, stats
                    );
                }
            }
        }
    }
}
