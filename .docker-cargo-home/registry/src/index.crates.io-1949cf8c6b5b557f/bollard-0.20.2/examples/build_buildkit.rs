//! Builds a container with a bunch of extra options for testing
#![allow(unused_variables, unused_mut)]

#[cfg(feature = "buildkit_providerless")]
use bollard::models::BuildInfoAux;
use bollard::Docker;

#[cfg(feature = "buildkit_providerless")]
use futures_util::stream::StreamExt;
use http_body_util::Full;

use std::io::Write;

#[tokio::main]
async fn main() {
    let docker = Docker::connect_with_socket_defaults().unwrap();

    let dockerfile = String::from(
        "FROM alpine as builder1
RUN touch bollard.txt
FROM alpine as builder2
RUN --mount=type=bind,from=builder1,target=mnt cp mnt/bollard.txt buildkit-bollard.txt
ENTRYPOINT ls buildkit-bollard.txt
",
    );

    let mut header = tar::Header::new_gnu();
    header.set_path("Dockerfile").unwrap();
    header.set_size(dockerfile.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    let mut tar = tar::Builder::new(Vec::new());
    tar.append(&header, dockerfile.as_bytes()).unwrap();

    let uncompressed = tar.into_inner().unwrap();
    let mut c = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    c.write_all(&uncompressed).unwrap();
    let compressed = c.finish().unwrap();

    let id = "bollard-build-buildkit-example";
    let build_image_options = bollard::query_parameters::BuildImageOptionsBuilder::default()
        .t(id)
        .dockerfile("Dockerfile")
        .version(bollard::query_parameters::BuilderVersion::BuilderBuildKit)
        .pull("true");

    #[cfg(feature = "buildkit_providerless")]
    let build_image_options = build_image_options.session(id);

    let mut image_build_stream = docker.build_image(
        build_image_options.build(),
        None,
        Some(http_body_util::Either::Left(Full::new(compressed.into()))),
    );

    #[cfg(feature = "buildkit_providerless")]
    while let Some(Ok(bollard::models::BuildInfo {
        aux: Some(BuildInfoAux::BuildKit(inner)),
        ..
    })) = image_build_stream.next().await
    {
        println!("Response: {:?}", inner);
    }
}
