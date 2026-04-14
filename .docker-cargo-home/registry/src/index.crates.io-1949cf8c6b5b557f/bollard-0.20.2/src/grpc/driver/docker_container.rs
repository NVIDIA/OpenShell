#![cfg(feature = "buildkit_providerless")]

use std::{
    collections::HashMap,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bollard_buildkit_proto::moby::buildkit::v1::control_client::ControlClient;
use bollard_stubs::models::{
    ContainerCreateBody, ExecInspectResponse, HostConfig, Mount, MountTypeEnum,
    SystemInfoCgroupDriverEnum,
};
use bytes::BytesMut;
use futures_core::Future;
use futures_util::{StreamExt, TryFutureExt, TryStreamExt};
use http::{
    header::{CONNECTION, UPGRADE},
    request::Builder,
    Method,
};
use log::{debug, info};
use tonic::transport::Endpoint;
use tonic::{codegen::InterceptedService, transport::Channel};
use tower_service::Service;

use crate::{
    auth::DockerCredentials,
    exec::{CreateExecOptions, StartExecOptions, StartExecResults},
    grpc::{
        build::{ImageBuildFrontendOptions, ImageBuildLoadInput},
        error::GrpcError,
    },
    grpc::{io::GrpcFramedTransport, registry::ImageRegistryOutput, GrpcServer},
    Docker,
};

use super::{channel::BuildkitChannel, DriverInterceptor, ImageExporterEnum};

/// The default `Buildkit` image to use for the [`DockerContainer] driver.
pub const DEFAULT_IMAGE: &str = "moby/buildkit:master";
const DEFAULT_STATE_DIR: &str = "/var/lib/buildkit";
const DUPLEX_BUF_SIZE: usize = 8 * 1024;

impl Service<tonic::transport::Uri> for DockerContainer {
    type Response = GrpcFramedTransport;
    type Error = GrpcError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: tonic::transport::Uri) -> Self::Future {
        let client = Docker::clone(&self.docker);
        let name = String::clone(&self.name);

        let fut = async move {
            let exec_id = client
                .create_exec(
                    &name,
                    CreateExecOptions {
                        attach_stdin: Some(true),
                        attach_stdout: Some(true),
                        attach_stderr: Some(true),
                        cmd: Some(vec!["buildctl", "dial-stdio"]),
                        ..Default::default()
                    },
                )
                .await?
                .id;

            let url = format!("/exec/{exec_id}/start");
            let capacity = 8 * 1024;

            let req = client.build_request(
                &url,
                Builder::new()
                    .method(Method::POST)
                    .header(CONNECTION, "Upgrade")
                    .header(UPGRADE, "tcp"),
                None::<String>,
                Docker::serialize_payload(Some(StartExecOptions {
                    output_capacity: Some(capacity),
                    ..Default::default()
                })),
            );

            client.process_upgraded(req).await.map(|(read, write)| {
                let output = Box::pin(read);
                let input = Box::pin(write);
                GrpcFramedTransport::new(output, input, capacity)
            })
        };

        Box::pin(fut.map_err(From::from))
    }
}

/// Builder used to create a driver, needed to communicate with `Buildkit`, such as with the
/// [`crate::grpc::driver::Export::export`] or [`crate::grpc::driver::Image::registry`]
/// functionality.
///
/// <div class="warning">
///  Warning: Buildkit features in Bollard are currently in Developer Preview and are intended strictly for feedback purposes only.
/// </div>
///
/// ## Examples
///
/// ```rust,no_run
/// use bollard::grpc::driver::docker_container::DockerContainerBuilder;
/// use bollard::Docker;
///
/// // Use a connection function
/// // let docker = Docker::connect_...;
/// # let docker = Docker::connect_with_local_defaults().unwrap();
///
/// let builder = DockerContainerBuilder::new(&docker);
///
/// ```
///
#[derive(Debug)]
pub struct DockerContainerBuilder {
    inner: DockerContainer,
}

impl DockerContainerBuilder {
    /// Construct a new `DockerContainerBuilder` to build a [`DockerContainer`].
    /// The docker context is torn down after solving a build.
    ///
    /// # Arguments
    ///
    ///  - A reference to the docker client
    pub fn new(docker: &Docker) -> Self {
        Self {
            inner: DockerContainer {
                name: format!("bollard_buildkit_{}", crate::grpc::new_id()),
                docker: Docker::clone(docker),
                session_id: String::from(&crate::grpc::new_id()),
                net_mode: None,
                image: None,
                cgroup_parent: None,
                env: vec![],
                args: vec![],
                tear_down: true,
            },
        }
    }

    /// Consume this builder to construct a [`DockerContainer`]
    pub async fn bootstrap(mut self) -> Result<DockerContainer, GrpcError> {
        debug!("booting buildkit");

        if self.inner.net_mode.is_none() {
            self.network("host");
        }

        if let Err(crate::errors::Error::DockerResponseServerError {
            status_code: 404,
            message: _,
        }) = self
            .inner
            .docker
            .inspect_container(
                &self.inner.name,
                None::<bollard_stubs::query_parameters::InspectContainerOptions>,
            )
            .await
        {
            self.inner.create().await?
        };

        debug!("starting container {}", &self.inner.name);

        self.inner.start().await?;
        self.inner.wait().await?;

        Ok(self.inner)
    }

    /// The network mode to apply to the `Buildkit` docker container.
    pub fn network(&mut self, net: &str) -> &mut DockerContainerBuilder {
        if net == "host" {
            self.inner
                .args
                .push(String::from("--allow-insecure-entitlement=network.host"));
        }

        self.inner.net_mode = Some(net.to_string());
        self
    }

    /// The image to use when spinning up a `Buildkit` container. The default is [`DEFAULT_IMAGE`]
    pub fn image(&mut self, image: &str) -> &mut DockerContainerBuilder {
        self.inner.image = Some(String::from(image));
        self
    }

    /// The cgroup to attach to - by default all `Buildkit` containers are placed under the same
    /// cgroup so that limits are applied across the whole host
    pub fn cgroup_parent(&mut self, cgroup_parent: &str) -> &mut DockerContainerBuilder {
        self.inner.cgroup_parent = Some(String::from(cgroup_parent));
        self
    }

    /// Set an env variable for the `Buildkit` container.
    pub fn env(&mut self, env: &str) -> &mut DockerContainerBuilder {
        self.inner.env.push(String::from(env));
        self
    }

    /// Set a additional run command arguments to the `Buildkit` docker execution.
    pub fn arg(&mut self, arg: &str) -> &mut DockerContainerBuilder {
        self.inner.args.push(String::from(arg));
        self
    }
}

/// DockerContainer plumbing to communicate with `Buildkit` using an execution pipe.
/// Underneath, the `buildkit` CLI will open a stdin/stdout pipe, which we can hook into to call
/// further GRPC methods.
///
/// Construct a `DockerContainer` using a [`DockerContainerBuilder`].
///
///
#[derive(Debug)]
pub struct DockerContainer {
    name: String,
    docker: Docker,
    session_id: String,
    net_mode: Option<String>,
    image: Option<String>,
    cgroup_parent: Option<String>,
    env: Vec<String>,
    args: Vec<String>,
    tear_down: bool,
}

impl super::Driver for DockerContainer {
    async fn grpc_handle(
        self,
        session_id: &str,
        services: Vec<GrpcServer>,
    ) -> Result<ControlClient<InterceptedService<Channel, DriverInterceptor>>, GrpcError> {
        let channel = Endpoint::try_from("http://[::]:50051")?
            .connect_with_connector(self)
            .await?;

        let channel = BuildkitChannel::new(channel);

        channel.grpc_handle(session_id, services).await
    }

    fn get_tear_down_handler(&self) -> Box<dyn super::DriverTearDownHandler> {
        if self.tear_down {
            Box::new(DockerContainerTearDownHandler {
                name: String::from(&self.name),
                docker: Docker::clone(&self.docker),
            })
        } else {
            Box::new(NoopTearDownHandler {})
        }
    }
}

impl DockerContainer {
    /// Identifies the docker container name that runs `Buildkit`. This should be unique if you
    /// intend to run multiple instances building in parallel on the same host.
    pub fn name(&self) -> &str {
        &self.name
    }

    async fn create(&self) -> Result<(), GrpcError> {
        let image_name = if let Some(image) = &self.image {
            image
        } else {
            DEFAULT_IMAGE
        };

        debug!("pulling image {}", &image_name);

        // TODO: registry auth

        let create_image_options =
            bollard_stubs::query_parameters::CreateImageOptionsBuilder::default()
                .from_image(image_name)
                .build();

        self.docker
            .create_image(Some(create_image_options), None, None)
            .try_collect::<Vec<_>>()
            .await?;

        debug!("creating container {}", &self.name);

        let container_options =
            bollard_stubs::query_parameters::CreateContainerOptionsBuilder::default()
                .name(&self.name)
                .build();

        let info = self.docker.info().await?;
        let cgroup_parent = match &info.cgroup_driver {
            Some(SystemInfoCgroupDriverEnum::CGROUPFS) =>
            // place all buildkit containers into this cgroup
            {
                Some(if let Some(cgroup_parent) = &self.cgroup_parent {
                    String::clone(cgroup_parent)
                } else {
                    String::from("/docker/buildx")
                })
            }
            _ => None,
        };

        let network_mode = self.net_mode.clone();

        let userns_mode = if let Some(security_options) = &info.security_options {
            if security_options.iter().any(|f| f == "userns") {
                Some(String::from("host"))
            } else {
                None
            }
        } else {
            None
        };

        let host_config = HostConfig {
            privileged: Some(true),
            mounts: Some(vec![Mount {
                typ: Some(MountTypeEnum::VOLUME),
                source: Some(format!("{}_state", &self.name)),
                target: Some(String::from(DEFAULT_STATE_DIR)),
                ..Default::default()
            }]),
            init: Some(true),
            network_mode,
            cgroup_parent,
            userns_mode,
            ..Default::default()
        };

        let container_config = ContainerCreateBody {
            image: Some(String::from(image_name)),
            env: Some(Vec::clone(&self.env)),
            host_config: Some(host_config),
            cmd: Some(Vec::clone(&self.args)),
            ..Default::default()
        };

        self.docker
            .create_container(Some(container_options), container_config)
            .await?;

        self.start().await?;

        self.wait().await?;

        Ok(())
    }

    async fn start(&self) -> Result<(), GrpcError> {
        self.docker
            .start_container(
                &self.name,
                None::<crate::query_parameters::StartContainerOptions>,
            )
            .await?;

        Ok(())
    }

    async fn wait(&self) -> Result<(), GrpcError> {
        let mut attempts = 1;
        let mut stdout = BytesMut::new();
        loop {
            let exec = self
                .docker
                .create_exec(
                    &self.name,
                    CreateExecOptions {
                        attach_stdout: Some(true),
                        attach_stderr: Some(true),
                        cmd: Some(vec!["buildctl", "debug", "workers"]),
                        ..Default::default()
                    },
                )
                .await?
                .id;

            if let StartExecResults::Attached {
                mut output,
                input: _,
            } = self.docker.start_exec(&exec, None).await?
            {
                while let Some(Ok(output)) = output.next().await {
                    stdout.extend_from_slice(output.into_bytes().as_ref());
                }
            };

            let inspect: ExecInspectResponse = self.docker.inspect_exec(&exec).await?;

            match inspect {
                ExecInspectResponse {
                    exit_code: Some(0), ..
                } => return Ok(()),
                ExecInspectResponse {
                    exit_code: Some(status_code),
                    ..
                } if attempts > 15 => {
                    info!("{}", std::str::from_utf8(stdout.as_ref())?);
                    return Err(crate::errors::Error::DockerContainerWaitError {
                        error: String::from(std::str::from_utf8(stdout.as_ref())?),
                        code: status_code,
                    }
                    .into());
                }
                _ => {
                    tokio::time::sleep(Duration::from_millis(attempts * 120)).await;
                    attempts += 1;
                }
            }
        }
    }
}

struct DockerContainerTearDownHandler {
    name: String,
    docker: Docker,
}

impl super::DriverTearDownHandler for DockerContainerTearDownHandler {
    fn tear_down<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<(), GrpcError>> + 'a>> {
        Box::pin(async {
            self.docker
                .kill_container(
                    &self.name,
                    None::<bollard_stubs::query_parameters::KillContainerOptions>,
                )
                .map_err(GrpcError::from)
                .await
        })
    }
}

struct NoopTearDownHandler {}

impl super::DriverTearDownHandler for NoopTearDownHandler {
    fn tear_down(&self) -> Pin<Box<dyn futures_core::Future<Output = Result<(), GrpcError>>>> {
        Box::pin(futures_util::future::ok(()))
    }
}

impl super::Export for DockerContainer {
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

impl super::Image for DockerContainer {
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
