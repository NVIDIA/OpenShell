//! Post a dockerfile
//!
//! tar cvf dockerfile.tar Dockerfile

use bollard::Docker;
use futures_util::{stream::StreamExt, TryStreamExt};

use http_body_util::Full;
use tokio::fs::File;
use tokio_util::codec::{BytesCodec, FramedRead};

use std::env::args;

#[tokio::main]
async fn main() {
    let docker = Docker::connect_with_socket_defaults().unwrap();

    let image_options = bollard::query_parameters::BuildImageOptionsBuilder::default()
        .dockerfile("Dockerfile")
        .t("rust-test")
        .rm(true)
        .build();

    let filename = &args().nth(1).expect("needs first argument");
    let archive = File::open(filename).await.expect("could not open file");
    let stream = FramedRead::new(archive, BytesCodec::new());
    let bytes = stream.try_concat().await.unwrap();

    let mut image_build_stream = docker.build_image(
        image_options,
        None,
        Some(http_body_util::Either::Left(Full::new(bytes.freeze()))),
    );

    while let Some(msg) = image_build_stream.next().await {
        println!("Message: {msg:?}");
    }
}
