//! Builds a container with a bunch of extra options for testing
#![allow(unused_variables, unused_mut, unused_imports)]

#[cfg(feature = "buildkit_providerless")]
use bollard::grpc::registry::ImageRegistryOutput;
use bollard::Docker;

#[cfg(feature = "buildkit_providerless")]
use bollard_buildkit_proto::moby::buildkit::v1::CacheOptionsEntry;

use std::io::Write;

#[tokio::main]
async fn main() {
    #[cfg(feature = "buildkit_providerless")]
    {
        let mut docker = Docker::connect_with_socket_defaults().unwrap();

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

        let name = "bollard-buildkit-with-cache-example";

        let registry_addr = if let Ok(addr) = std::env::var("REGISTRY_HTTP_ADDR") {
            addr
        } else {
            panic!("Please set the REGISTRY_HTTP_ADDR environment variable");
        };

        let mut cache_attrs = std::collections::HashMap::new();
        cache_attrs.insert(String::from("mode"), String::from("max"));
        cache_attrs.insert(
            String::from("ref"),
            format!("{}/buildkit_with_cache:build-cache", registry_addr),
        );
        let cache_from = CacheOptionsEntry {
            r#type: String::from("registry"),
            attrs: std::collections::HashMap::clone(&cache_attrs),
        };
        let cache_to = CacheOptionsEntry {
            r#type: String::from("registry"),
            attrs: cache_attrs,
        };
        let frontend_opts = bollard::grpc::build::ImageBuildFrontendOptions::builder()
            .cachefrom(&cache_from)
            .cacheto(&cache_to)
            .pull(true)
            .build();

        let output =
            ImageRegistryOutput::builder(&format!("{}/{}:latest", registry_addr, name)).consume();

        // let mut driver = bollard::grpc::driver::moby::Moby::new(&docker);
        let mut buildkit_builder =
            bollard::grpc::driver::docker_container::DockerContainerBuilder::new(&docker);
        buildkit_builder.env("JAEGER_TRACE=localhost:6831");
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

        bollard::grpc::driver::Image::registry(
            driver,
            output,
            frontend_opts,
            load_input,
            Some(creds_hsh),
        )
        .await
        .unwrap();
    }
}
