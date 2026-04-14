//! This example will spin up Zookeeper and two Kafka brokers asynchronously.

use bollard::models::*;
use bollard::Docker;

use futures_util::stream::select;
use futures_util::stream::StreamExt;
use futures_util::stream::TryStreamExt;

const KAFKA_IMAGE: &str = "confluentinc/cp-kafka:5.0.1";
const ZOOKEEPER_IMAGE: &str = "confluentinc/cp-zookeeper:5.0.1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    let docker = Docker::connect_with_socket_defaults().unwrap();

    let sd1 = docker.clone();
    let sd2 = docker.clone();

    let zookeeper_config = ContainerCreateBody {
        image: Some(String::from(ZOOKEEPER_IMAGE)),
        env: Some(vec![
            String::from("ZOOKEEPER_CLIENT_PORT=32181"),
            String::from("ZOOKEEPER_TICK_TIME=2000"),
            String::from("ZOOKEEPER_SYNC_LIMIT=2"),
        ]),
        ..Default::default()
    };

    let broker1_config = ContainerCreateBody {
        image: Some(String::from(KAFKA_IMAGE)),
        cmd: Some(vec![String::from("/etc/confluent/docker/run")]),
        env: Some(vec![
            String::from("KAFKA_ZOOKEEPER_CONNECT=localhost:32181"),
            String::from("KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://localhost:19092"),
            String::from("KAFKA_BROKER_ID=1"),
            String::from("KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1"),
        ]),
        host_config: Some(HostConfig {
            network_mode: Some(String::from("container:zookeeper")),
            ..Default::default()
        }),
        ..Default::default()
    };

    let broker2_config = ContainerCreateBody {
        image: Some(String::from(KAFKA_IMAGE)),
        cmd: Some(vec![String::from("/etc/confluent/docker/run")]),
        env: Some(vec![
            String::from("KAFKA_ZOOKEEPER_CONNECT=localhost:32181"),
            String::from("KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://localhost:29092"),
            String::from("KAFKA_BROKER_ID=2"),
            String::from("KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1"),
        ]),
        host_config: Some(HostConfig {
            network_mode: Some(String::from("container:zookeeper")),
            ..Default::default()
        }),
        ..Default::default()
    };

    let _ = &docker
        .create_image(
            Some(
                bollard::query_parameters::CreateImageOptionsBuilder::default()
                    .from_image(ZOOKEEPER_IMAGE)
                    .build(),
            ),
            None,
            None,
        )
        .try_collect::<Vec<_>>()
        .await?;

    let _ = &docker
        .create_container(
            Some(
                bollard::query_parameters::CreateContainerOptionsBuilder::default()
                    .name("zookeeper")
                    .build(),
            ),
            zookeeper_config,
        )
        .await?;

    let _ = &docker
        .start_container(
            "zookeeper",
            None::<bollard::query_parameters::StartContainerOptions>,
        )
        .await?;

    let _ = &docker
        .create_image(
            Some(
                bollard::query_parameters::CreateImageOptionsBuilder::default()
                    .from_image(KAFKA_IMAGE)
                    .build(),
            ),
            None,
            None,
        )
        .try_collect::<Vec<_>>()
        .await?;

    let _ = &docker
        .create_container(
            Some(
                bollard::query_parameters::CreateContainerOptionsBuilder::default()
                    .name("kafka1")
                    .build(),
            ),
            broker1_config,
        )
        .await?;

    let _ = &docker
        .start_container(
            "kafka1",
            None::<bollard::query_parameters::StartContainerOptions>,
        )
        .await?;

    let mut stream1 = sd1.logs(
        "kafka1",
        Some(
            bollard::query_parameters::LogsOptionsBuilder::default()
                .follow(true)
                .stdout(true)
                .stderr(false)
                .build(),
        ),
    );

    let _ = &docker
        .create_image(
            Some(
                bollard::query_parameters::CreateImageOptionsBuilder::default()
                    .from_image(KAFKA_IMAGE)
                    .build(),
            ),
            None,
            None,
        )
        .try_collect::<Vec<_>>()
        .await?;

    let _ = &docker
        .create_container(
            Some(
                bollard::query_parameters::CreateContainerOptionsBuilder::default()
                    .name("kafka2")
                    .build(),
            ),
            broker2_config,
        )
        .await?;

    let _ = &docker
        .start_container(
            "kafka2",
            None::<bollard::query_parameters::StartContainerOptions>,
        )
        .await?;

    let mut stream2 = sd2.logs(
        "kafka2",
        Some(
            bollard::query_parameters::LogsOptionsBuilder::default()
                .follow(true)
                .stdout(true)
                .stderr(false)
                .build(),
        ),
    );

    let mut stream = select(&mut stream1, &mut stream2);

    while let Some(msg) = stream.next().await {
        println!("Message: {msg:?}");
    }

    Ok(())
}
