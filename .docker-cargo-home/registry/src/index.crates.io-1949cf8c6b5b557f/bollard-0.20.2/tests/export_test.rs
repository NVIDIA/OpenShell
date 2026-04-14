#![cfg(feature = "buildkit")]

use bollard::errors::Error;
use bollard::Docker;

use bollard::grpc::driver::docker_container::DockerContainerBuilder;
use tokio::runtime::Runtime;

use std::io::Write;

#[macro_use]
pub mod common;
use crate::common::*;

async fn export_buildkit_oci_test(docker: Docker) -> Result<(), Error> {
    let dockerfile = String::from(
        "FROM localhost:5000/alpine as builder1
        RUN touch bollard.txt
        FROM localhost:5000/alpine as builder2
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

    let frontend_opts = bollard::grpc::build::ImageBuildFrontendOptions::builder()
        .pull(true)
        .build();

    let dest_path = std::path::Path::new("/tmp/oci-image.tar");

    // cleanup - usually for local testing, the grpc handler will overwrite
    if dest_path.exists() {
        std::fs::remove_file(dest_path).unwrap();
    }
    assert!(!dest_path.exists());

    let output = bollard::grpc::export::ImageExporterOutputBuilder::new(
        "docker.io/library/bollard-oci-export-buildkit-example:latest",
    )
    .annotation("exporter", "Bollard")
    .dest(dest_path);

    let buildkit_builder = DockerContainerBuilder::new(&docker);
    let driver = buildkit_builder.bootstrap().await.unwrap();

    let load_input =
        bollard::grpc::build::ImageBuildLoadInput::Upload(bytes::Bytes::from(compressed));

    let credentials = bollard::auth::DockerCredentials {
        username: Some("bollard".to_string()),
        password: std::env::var("REGISTRY_PASSWORD").ok(),
        ..Default::default()
    };
    let mut creds_hsh = std::collections::HashMap::new();
    creds_hsh.insert("localhost:5000", credentials);

    let res = bollard::grpc::driver::Export::export(
        driver,
        bollard::grpc::driver::ImageExporterEnum::OCI(output),
        frontend_opts,
        load_input,
        Some(creds_hsh),
    )
    .await;

    assert!(res.is_ok());

    assert!(dest_path.exists());

    let oci_file = std::fs::File::open(dest_path)?;
    let mut oci_archive = tar::Archive::new(oci_file);

    let mut paths = vec![];

    let iter = oci_archive.entries()?;
    for entry in iter {
        let entry = entry?;
        let path = entry.path()?.display().to_string();
        paths.push(path);
    }

    println!("{:#?}", &paths);

    assert!(paths.contains(&String::from("blobs/")));
    assert!(paths.contains(&String::from("blobs/sha256/")));
    assert!(paths.contains(&String::from("index.json")));
    assert!(paths.contains(&String::from("oci-layout")));

    assert_eq!(paths.len(), 8);

    Ok(())
}

#[test]
#[cfg(feature = "buildkit_providerless")]
fn integration_test_export_buildkit_oci() {
    connect_to_docker_and_run!(export_buildkit_oci_test);
}
