use bollard::models::CreateImageInfo;
/// Example of creating an image from scratch with a file system in a raw Tar (or tar.gz) archive.
/// Run with `cargo run --example image_from_scratch <path to archive>.tar.gz
/// This implementation streams the archive file piece by piece to the Docker daemon,
/// but does so inefficiently. For best results, use `tokio::fs` instead of `std::fs`.
use bollard::Docker;
use futures_util::stream::TryStreamExt;
use std::env::args;
use tokio::fs::File;
use tokio_util::io::ReaderStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    let arguments: Vec<String> = args().collect();
    if arguments.len() == 1 || arguments.len() > 2 {
        println!("Usage: image_from_scratch <path to tar archive>");
        return Ok(());
    }

    let file = File::open(&arguments[1])
        .await
        .expect("Could not find archive.");

    let stream = ReaderStream::new(file);

    let docker = Docker::connect_with_socket_defaults().unwrap();

    let options = bollard::query_parameters::CreateImageOptionsBuilder::default()
        .from_src("-") // from_src must be "-" when sending the archive in the request body
        .repo("bollard_image_scratch_example") // The name of the image in the docker daemon.
        .tag("1.0.0") // The tag of this particular image.
        .build();

    // Finally, call Docker::create_image with the options and the body
    let result: Vec<CreateImageInfo> = docker
        .create_image(Some(options), Some(bollard::body_try_stream(stream)), None)
        .try_collect()
        .await?;
    // If all went well, the ID of the new image will be printed
    dbg!(&result[0]);

    Ok(())
}
