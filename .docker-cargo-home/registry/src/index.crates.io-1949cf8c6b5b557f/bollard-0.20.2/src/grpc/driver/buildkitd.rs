use std::pin::Pin;

pub use bollard_buildkit_proto::moby::buildkit::v1::control_client::ControlClient;

use crate::grpc::driver::ImageBuildFrontendOptions;
use crate::grpc::driver::ImageBuildLoadInput;
use crate::grpc::driver::ImageExporterEnum;

use crate::grpc::registry::ImageRegistryOutput;
use crate::grpc::DockerCredentials;

use std::collections::HashMap;
pub use tonic::transport::Endpoint;
use tonic::{service::interceptor::InterceptedService, transport::Channel};

use crate::grpc::error::GrpcError;

use super::channel::BuildkitChannel;
use super::{Driver, DriverInterceptor, DriverTearDownHandler};

const DUPLEX_BUF_SIZE: usize = 8 * 1024;

/// BuildkitDaemon is a client for the buildkit daemon.
#[derive(Debug, Clone)]
pub struct BuildkitDaemon {
    uri: Endpoint,
}

impl BuildkitDaemon {
    /// Create a [`BuildkitDaemon`] driver instance.
    pub fn new(uri: Endpoint) -> Self {
        Self { uri }
    }
}

impl Driver for BuildkitDaemon {
    async fn grpc_handle(
        self,
        session_id: &str,
        services: Vec<super::GrpcServer>,
    ) -> Result<ControlClient<InterceptedService<Channel, DriverInterceptor>>, GrpcError> {
        let channel = self.uri.connect().await?;
        let channel = BuildkitChannel::new(channel);

        channel.grpc_handle(session_id, services).await
    }

    fn get_tear_down_handler(&self) -> Box<dyn DriverTearDownHandler> {
        Box::new(BuildkitDaemonTearDownHandler {})
    }
}

struct BuildkitDaemonTearDownHandler {}

impl DriverTearDownHandler for BuildkitDaemonTearDownHandler {
    fn tear_down(&self) -> Pin<Box<dyn futures_core::Future<Output = Result<(), GrpcError>>>> {
        Box::pin(futures_util::future::ok(()))
    }
}

impl super::Build for BuildkitDaemon {
    async fn docker_build(
        self,
        name: &str,
        frontend_opts: ImageBuildFrontendOptions,
        load_input: ImageBuildLoadInput,
        credentials: Option<HashMap<&str, DockerCredentials>>,
    ) -> Result<(), GrpcError> {
        let mut exporter_attrs = HashMap::new();
        exporter_attrs.insert(String::from("type"), String::from("docker"));
        exporter_attrs.insert(String::from("name"), String::from(name));
        super::solve(
            self,
            "moby",
            exporter_attrs,
            None,
            frontend_opts,
            load_input,
            credentials,
        )
        .await
    }
}

impl super::Export for BuildkitDaemon {
    async fn export(
        self,
        exporter_request: ImageExporterEnum,
        frontend_opts: ImageBuildFrontendOptions,
        load_input: ImageBuildLoadInput,
        credentials: Option<HashMap<&str, DockerCredentials>>,
    ) -> Result<(), GrpcError> {
        let (exporter, exporter_attrs, path) = match exporter_request {
            ImageExporterEnum::OCI(request) => ("oci", request.output.into_map(), request.path),
            ImageExporterEnum::Docker(request) => {
                ("docker", request.output.into_map(), request.path)
            }
        };
        super::solve(
            self,
            exporter,
            exporter_attrs,
            Some(path),
            frontend_opts,
            load_input,
            credentials,
        )
        .await
    }
}

impl super::Image for BuildkitDaemon {
    async fn registry(
        self,
        output: ImageRegistryOutput,
        frontend_opts: ImageBuildFrontendOptions,
        load_input: ImageBuildLoadInput,
        credentials: Option<HashMap<&str, DockerCredentials>>,
    ) -> Result<(), GrpcError> {
        let exporter = "image";
        let exporter_attrs = output.into_map();
        super::solve(
            self,
            exporter,
            exporter_attrs,
            None,
            frontend_opts,
            load_input,
            credentials,
        )
        .await
    }
}
