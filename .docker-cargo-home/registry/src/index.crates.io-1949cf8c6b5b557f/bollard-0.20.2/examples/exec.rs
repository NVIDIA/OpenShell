//! This example will run a non-interactive command inside the container using `docker exec`

use bollard::models::ContainerCreateBody;
use bollard::Docker;

use futures_util::stream::StreamExt;
use futures_util::TryStreamExt;

const IMAGE: &str = "alpine:3";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    let docker = Docker::connect_with_socket_defaults().unwrap();

    docker
        .create_image(
            Some(
                bollard::query_parameters::CreateImageOptionsBuilder::default()
                    .from_image(IMAGE)
                    .build(),
            ),
            None,
            None,
        )
        .try_collect::<Vec<_>>()
        .await?;

    let alpine_config = ContainerCreateBody {
        image: Some(String::from(IMAGE)),
        tty: Some(true),
        ..Default::default()
    };

    let id = docker
        .create_container(
            None::<bollard::query_parameters::CreateContainerOptions>,
            alpine_config,
        )
        .await?
        .id;
    docker
        .start_container(
            &id,
            None::<bollard::query_parameters::StartContainerOptions>,
        )
        .await?;

    // non interactive
    let exec = docker
        .create_exec(
            &id,
            bollard::models::ExecConfig {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(
                    vec!["ls", "-l", "/"]
                        .into_iter()
                        .map(ToString::to_string)
                        .collect(),
                ),
                ..Default::default()
            },
        )
        .await?
        .id;
    if let bollard::exec::StartExecResults::Attached { mut output, .. } =
        docker.start_exec(&exec, None).await?
    {
        while let Some(Ok(msg)) = output.next().await {
            print!("{msg}");
        }
    } else {
        unreachable!();
    }

    docker
        .remove_container(
            &id,
            Some(
                bollard::query_parameters::RemoveContainerOptionsBuilder::default()
                    .force(true)
                    .build(),
            ),
        )
        .await?;

    Ok(())
}
