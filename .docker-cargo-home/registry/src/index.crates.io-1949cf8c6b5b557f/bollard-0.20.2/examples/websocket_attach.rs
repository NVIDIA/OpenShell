//! Example demonstrating WebSocket container attach
//!
//! Run with: cargo run --features websocket --example websocket_attach
//!
//! NOTE: Docker's WebSocket attach endpoint (`/attach/ws`) uses `golang.org/x/net/websocket`
//! server-side, which has compatibility issues with standard RFC 6455 WebSocket implementations.
//! Data may not flow correctly on some Docker versions. For reliable container attach, use the
//! regular `attach_container()` method instead.

use bollard::container::AttachContainerResults;
use bollard::models::ContainerCreateBody;
use bollard::Docker;

use futures_util::{StreamExt, TryStreamExt};
use tokio::io::AsyncWriteExt;

const IMAGE: &str = "alpine:3";
const CONTAINER_NAME: &str = "websocket_attach_example";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    let docker = Docker::connect_with_local_defaults()?;

    // Pull image
    println!("Pulling {IMAGE}...");
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

    // Remove existing container if any
    let _ = docker
        .remove_container(
            CONTAINER_NAME,
            Some(
                bollard::query_parameters::RemoveContainerOptionsBuilder::default()
                    .force(true)
                    .build(),
            ),
        )
        .await;

    // Create and start container
    println!("Creating container...");
    let config = ContainerCreateBody {
        image: Some(String::from(IMAGE)),
        tty: Some(true),
        attach_stdin: Some(true),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        open_stdin: Some(true),
        cmd: Some(vec![String::from("/bin/sh")]),
        ..Default::default()
    };

    docker
        .create_container(
            Some(bollard::query_parameters::CreateContainerOptions {
                name: Some(String::from(CONTAINER_NAME)),
                ..Default::default()
            }),
            config,
        )
        .await?;

    println!("Starting container...");
    docker
        .start_container(
            CONTAINER_NAME,
            None::<bollard::query_parameters::StartContainerOptions>,
        )
        .await?;

    // Attach via WebSocket
    println!("Attaching via WebSocket...");
    let options = bollard::query_parameters::AttachContainerOptionsBuilder::default()
        .stdin(true)
        .stdout(true)
        .stderr(true)
        .stream(true)
        .build();

    let AttachContainerResults { output, mut input } = docker
        .attach_container_websocket(CONTAINER_NAME, Some(options))
        .await?;

    println!("WebSocket connection established!");
    println!("Note: Due to Docker server-side limitations, data may not flow correctly.\n");

    // Send a command
    println!("Sending: echo 'Hello from WebSocket!'");
    input.write_all(b"echo 'Hello from WebSocket!'\n").await?;
    input.flush().await?;

    // Read output with timeout
    println!("--- Container Output (3 second timeout) ---");
    let mut output = output;
    let output_result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let mut count = 0;
        while let Some(result) = output.next().await {
            match result {
                Ok(log) => {
                    print!("{}", log);
                    count += 1;
                    if count >= 5 {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Read error: {}", e);
                    break;
                }
            }
        }
        count
    })
    .await;

    match output_result {
        Ok(count) => println!("\nReceived {} output items", count),
        Err(_) => println!("\n(timeout - expected due to Docker WebSocket limitations)"),
    }
    println!("--- End Output ---\n");

    // Cleanup
    println!("Cleaning up...");
    let _ = docker
        .remove_container(
            CONTAINER_NAME,
            Some(
                bollard::query_parameters::RemoveContainerOptionsBuilder::default()
                    .force(true)
                    .build(),
            ),
        )
        .await;

    println!("Done!");
    Ok(())
}
