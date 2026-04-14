//! This example will run a interactive command inside the container using `docker exec`,
//! passing trough input and output into the tty running inside the container

use bollard::Docker;

use futures_util::{StreamExt, TryStreamExt};
use std::io::{stdout, Read, Write};
use std::time::Duration;
#[cfg(not(windows))]
use termion::raw::IntoRawMode;
#[cfg(not(windows))]
use termion::{async_stdin, terminal_size};
use tokio::io::AsyncWriteExt;
use tokio::task::spawn;
use tokio::time::sleep;

const IMAGE: &str = "alpine:3";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    let docker = Docker::connect_with_socket_defaults().unwrap();

    #[cfg(not(windows))]
    let tty_size = terminal_size()?;

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

    let alpine_config = bollard::models::ContainerCreateBody {
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

    let exec = docker
        .create_exec(
            &id,
            bollard::models::ExecConfig {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                attach_stdin: Some(true),
                tty: Some(true),
                cmd: Some(vec![String::from("sh")]),
                ..Default::default()
            },
        )
        .await?
        .id;
    #[cfg(not(windows))]
    if let bollard::exec::StartExecResults::Attached {
        mut output,
        mut input,
    } = docker.start_exec(&exec, None).await?
    {
        // pipe stdin into the docker exec stream input
        spawn(async move {
            #[allow(clippy::unbuffered_bytes)]
            let mut stdin = async_stdin().bytes();
            loop {
                if let Some(Ok(byte)) = stdin.next() {
                    input.write_all(&[byte]).await.ok();
                } else {
                    sleep(Duration::from_nanos(10)).await;
                }
            }
        });

        docker
            .resize_exec(
                &exec,
                bollard::query_parameters::ResizeExecOptionsBuilder::default()
                    .h(tty_size.1 as i32)
                    .w(tty_size.0 as i32)
                    .build(),
            )
            .await?;

        // set stdout in raw mode so we can do tty stuff
        let stdout = stdout();
        let mut stdout = stdout.lock().into_raw_mode()?;

        // pipe docker exec output into stdout
        while let Some(Ok(output)) = output.next().await {
            stdout.write_all(output.into_bytes().as_ref())?;
            stdout.flush()?;
        }
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
