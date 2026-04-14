#![cfg(feature = "buildkit_providerless")]

use std::collections::HashMap;
use std::pin::Pin;

use bollard_buildkit_proto::{health, moby::buildkit::v1::control_client::ControlClient};
use bytes::Bytes;
use http::{request::Builder, Method};
use http_body_util::Full;
use log::error;
use log::trace;
use tonic::codegen::InterceptedService;
use tonic::transport::{Channel, Endpoint};

use crate::auth::DockerCredentials;
use crate::docker::BodyType;
use crate::grpc::build::{ImageBuildFrontendOptions, ImageBuildLoadInput};
use crate::{
    grpc::error::GrpcError,
    grpc::{io::GrpcTransport, GrpcClient, GrpcServer, HealthServerImpl},
    Docker,
};

use super::{Driver, DriverInterceptor};

/// The Moby driver handles a GRPC connection with an upgraded `/session` and `/grpc` endpoints in
/// Docker itself.
#[derive(Debug)]
pub struct Moby {
    pub(crate) docker: Docker,
}

impl Moby {
    /// Create a [`Moby`] driver instance.
    pub fn new(docker: &Docker) -> Self {
        Self {
            docker: Docker::clone(docker),
        }
    }
}

impl Driver for Moby {
    async fn grpc_handle(
        self,
        session_id: &str,
        services: Vec<GrpcServer>,
    ) -> Result<ControlClient<InterceptedService<Channel, DriverInterceptor>>, GrpcError> {
        let grpc_client = GrpcClient {
            client: self.docker.clone(),
            session_id: String::from(session_id),
        };

        let channel = Endpoint::try_from("http://[::]:50051")?
            .connect_with_connector(grpc_client)
            .await?;

        let metadata_grpc_method: Vec<String> = services.iter().flat_map(|s| s.names()).collect();

        let interceptor = DriverInterceptor {
            session_id: String::from(session_id),
            metadata_grpc_method: metadata_grpc_method.clone(),
        };
        let control_client = ControlClient::with_interceptor(channel, interceptor);

        let url = "/session";

        let opt: Option<serde_json::Value> = None;

        let mut builder = Builder::new()
            .method(Method::POST)
            .header("Connection", "Upgrade")
            .header("Upgrade", "h2c")
            .header("X-Docker-Expose-Session-Uuid", session_id);

        for method in metadata_grpc_method {
            builder = builder.header("X-Docker-Expose-Session-Grpc-Method", method)
        }

        let req = self.docker.build_request(
            url,
            builder,
            opt,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        let (read, write) = self.docker.process_upgraded(req).await?;

        let output = Box::pin(read);
        let input = Box::pin(write);
        let transport = GrpcTransport {
            read: output,
            write: input,
        };

        tokio::spawn(async {
            let health = health::health_server::HealthServer::new(HealthServerImpl::new());
            let mut builder = tonic::transport::Server::builder();
            let mut router = builder.add_service(health);
            for service in services {
                router = service.append(router);
            }
            trace!("router: {:#?}", router);
            if let Err(e) = router
                .serve_with_incoming(futures_util::stream::iter(vec![Ok::<
                    _,
                    tonic::transport::Error,
                >(
                    transport
                )]))
                .await
            {
                error!("Failed to serve grpc connection: {}", e)
            }
        });

        Ok(control_client)
    }

    fn get_tear_down_handler(&self) -> Box<dyn super::DriverTearDownHandler> {
        Box::new(MobyTearDownHandler {})
    }
}

struct MobyTearDownHandler {}

impl super::DriverTearDownHandler for MobyTearDownHandler {
    fn tear_down(&self) -> Pin<Box<dyn futures_core::Future<Output = Result<(), GrpcError>>>> {
        Box::pin(futures_util::future::ok(()))
    }
}

impl super::Build for Moby {
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
