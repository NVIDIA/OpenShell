#![cfg(feature = "buildkit_providerless")]

use std::pin::Pin;

use bollard_buildkit_proto::{
    health::health_server::HealthServer, moby::buildkit::v1::control_client::ControlClient,
};
use futures_core::Future;
use futures_util::TryStreamExt;
use log::{error, trace};

use tonic::transport::Channel;

use crate::grpc::{
    io::{into_async_read::IntoAsyncRead, reader_stream::ReaderStream, GrpcTransport},
    HealthServerImpl,
};

use super::DriverInterceptor;

const DUPLEX_BUF_SIZE: usize = 8 * 1024;

#[derive(Debug, Clone)]
/// The Buildkit Channel driver opens uses an existing [`tonic::transport::Channel`] to communicate
/// with the Buildkit Daemon.
pub struct BuildkitChannel {
    channel: Channel,
}

impl BuildkitChannel {
    /// Create a [`BuildkitChannel`] driver instance.
    pub fn new(channel: Channel) -> Self {
        Self { channel }
    }
}

impl super::Driver for BuildkitChannel {
    async fn grpc_handle(
        self,
        session_id: &str,
        services: Vec<crate::grpc::GrpcServer>,
    ) -> Result<
        bollard_buildkit_proto::moby::buildkit::v1::control_client::ControlClient<
            tonic::service::interceptor::InterceptedService<Channel, super::DriverInterceptor>,
        >,
        crate::grpc::error::GrpcError,
    > {
        let metadata_grpc_method: Vec<String> = services.iter().flat_map(|s| s.names()).collect();

        let interceptor = DriverInterceptor {
            session_id: String::from(session_id),
            metadata_grpc_method,
        };

        let mut control_client = ControlClient::with_interceptor(self.channel, interceptor);

        let (asyncwriter, asyncreader) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        let streamreader = ReaderStream::new(asyncreader);
        let stream = control_client.session(streamreader).await?;
        let stream = stream.into_inner().map_err(std::io::Error::other);

        let asyncreader = IntoAsyncRead::new(stream);
        let transport = GrpcTransport {
            read: Box::pin(asyncreader),
            write: Box::pin(asyncwriter),
        };

        tokio::spawn(async {
            let health = HealthServer::new(HealthServerImpl::new());
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
        // Teardown is handled by the caller
        Box::new(NoOpDriverTearDownHandler)
    }
}

#[derive(Debug, Clone, Copy)]
struct NoOpDriverTearDownHandler;

impl super::DriverTearDownHandler for NoOpDriverTearDownHandler {
    fn tear_down<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<(), crate::grpc::error::GrpcError>> + 'a>> {
        Box::pin(async { Ok(()) })
    }
}
