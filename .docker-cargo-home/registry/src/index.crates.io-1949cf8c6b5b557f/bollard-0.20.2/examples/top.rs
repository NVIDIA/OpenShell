//! Run top asynchronously across several docker containers
use bollard::models::*;
use bollard::Docker;

use std::collections::HashMap;
use std::default::Default;

use futures_util::future::TryFutureExt;
use futures_util::stream::FuturesUnordered;
use futures_util::stream::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    let docker = Docker::connect_with_socket_defaults().unwrap();

    let mut list_container_filters = HashMap::new();
    list_container_filters.insert(String::from("status"), vec![String::from("running")]);

    let containers = docker
        .list_containers(Some(
            bollard::query_parameters::ListContainersOptionsBuilder::default()
                .all(true)
                .filters(&list_container_filters)
                .build(),
        ))
        .await?;

    let mut futures = FuturesUnordered::new();
    let iter = containers.iter();

    for container in iter {
        if let Some(ref name) = container.id {
            futures.push(
                docker
                    .top_processes(
                        name,
                        Some(
                            bollard::query_parameters::TopOptionsBuilder::default()
                                .ps_args("aux")
                                .build(),
                        ),
                    )
                    .map_ok(move |result| (name.to_owned(), result)),
            )
        }
    }

    println!("                                                                \tPID\tUSER\tTIME\tCOMMAND");
    while let Some(Ok((
        name,
        ContainerTopResponse {
            processes: Some(p), ..
        },
    ))) = futures.next().await
    {
        if let Some(p) = p.first() {
            print!("{name}");
            for mut v in p.iter().cloned() {
                if v.len() > 30 {
                    v.truncate(30);
                }
                print!("\t{v}");
            }
            println!();
        }
    }

    Ok(())
}
