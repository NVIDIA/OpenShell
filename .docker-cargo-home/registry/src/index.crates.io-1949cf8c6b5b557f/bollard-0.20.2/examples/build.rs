//! Builds a container with a bunch of extra options for testing

use bollard::Docker;

use std::collections::HashMap;

use futures_util::stream::StreamExt;

#[tokio::main]
async fn main() {
    let docker = Docker::connect_with_socket_defaults().unwrap();

    let mut build_image_args = HashMap::new();
    build_image_args.insert("dummy", "value");

    let mut build_image_labels = HashMap::new();
    build_image_labels.insert("maintainer", "somemaintainer");

    let build_image_options = bollard::query_parameters::BuildImageOptionsBuilder::default()
        .dockerfile("Dockerfile")
        .t("bollard-build-example")
        .extrahosts("myhost:127.0.0.1")
        .remote("https://raw.githubusercontent.com/docker-library/openjdk/master/11/jdk/slim/Dockerfile")
        .q(false)
        .nocache(false)
        .pull("true")
        .rm(true)
        .forcerm(true)
        .memory(120000000)
        .memswap(500000)
        .cpushares(2)
        .cpusetcpus("0-3")
        .cpuperiod(2000)
        .cpuquota(1000)
        .buildargs(&build_image_args)
        .shmsize(1000000)
        .squash(false)
        .labels(&build_image_labels)
        .networkmode("host")
        .platform("linux/x86_64")
        .target("");

    #[cfg(feature = "buildkit_providerless")]
    let build_image_options =
        build_image_options.version(bollard::query_parameters::BuilderVersion::BuilderV1);

    let mut image_build_stream = docker.build_image(build_image_options.build(), None, None);

    while let Some(msg) = image_build_stream.next().await {
        println!("Message: {msg:?}");
    }
}
