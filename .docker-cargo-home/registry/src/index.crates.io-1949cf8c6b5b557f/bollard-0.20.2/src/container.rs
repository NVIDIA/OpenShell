//! Container API: run docker containers and manage their lifecycle

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use futures_core::Stream;
use futures_util::{StreamExt, TryStreamExt};
use http::header::{CONNECTION, CONTENT_TYPE, UPGRADE};
use http::request::Builder;
use http_body_util::Full;
use hyper::{body::Bytes, Method};
use serde::Serialize;
use serde_derive::Deserialize;
use std::cmp::Eq;
use std::collections::HashMap;
use std::hash::Hash;
use tokio::io::AsyncWrite;
use tokio_util::codec::FramedRead;

use std::fmt;
use std::pin::Pin;

use super::Docker;
use crate::docker::BodyType;
use crate::errors::Error;
use crate::models::*;
#[cfg(feature = "websocket")]
use crate::read::websocket::{WebSocketReader, WebSocketWriter};
use crate::read::NewlineLogOutputDecoder;

/// Path Stat Response from HEAD request to container/{id}/archive
#[derive(Debug, Deserialize)]
pub struct PathStatResponse {
    /// Name of the file
    #[serde(rename = "name")]
    pub name: String,

    /// File size
    #[serde(rename = "size")]
    pub size: i64,

    /// os file Mode
    #[serde(rename = "mode")]
    pub file_mode: u32,

    /// last modification time
    #[serde(rename = "mtime")]
    pub modification_time: Option<String>,

    /// link target
    #[serde(rename = "linkTarget")]
    pub link_target: String,
}

/// This container's networking configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(missing_docs)]
pub struct NetworkingConfig<T: Into<String> + Hash + Eq> {
    pub endpoints_config: HashMap<T, EndpointSettings>,
}

impl<T> From<NetworkingConfig<T>> for crate::models::NetworkingConfig
where
    T: Into<String> + Hash + Eq,
{
    fn from(config: NetworkingConfig<T>) -> Self {
        crate::models::NetworkingConfig {
            endpoints_config: Some(
                config
                    .endpoints_config
                    .into_iter()
                    .map(|(k, v)| (k.into(), v))
                    .collect(),
            ),
        }
    }
}

/// Results type for the [Attach Container API](Docker::attach_container())
pub struct AttachContainerResults {
    /// [Log Output](LogOutput) enum, wrapped in a Stream.
    pub output: Pin<Box<dyn Stream<Item = Result<LogOutput, Error>> + Send>>,
    /// Byte writer to container
    pub input: Pin<Box<dyn AsyncWrite + Send>>,
}

impl fmt::Debug for AttachContainerResults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AttachContainerResults")
    }
}

/// Result type for the [Logs API](Docker::logs())
#[derive(Debug, Clone, PartialEq)]
#[allow(missing_docs)]
pub enum LogOutput {
    StdErr { message: Bytes },
    StdOut { message: Bytes },
    StdIn { message: Bytes },
    Console { message: Bytes },
}

impl fmt::Display for LogOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match &self {
            LogOutput::StdErr { message } => message,
            LogOutput::StdOut { message } => message,
            LogOutput::StdIn { message } => message,
            LogOutput::Console { message } => message,
        };
        write!(f, "{}", String::from_utf8_lossy(message))
    }
}

impl AsRef<[u8]> for LogOutput {
    fn as_ref(&self) -> &[u8] {
        match self {
            LogOutput::StdErr { message } => message.as_ref(),
            LogOutput::StdOut { message } => message.as_ref(),
            LogOutput::StdIn { message } => message.as_ref(),
            LogOutput::Console { message } => message.as_ref(),
        }
    }
}

impl LogOutput {
    /// Get the raw bytes of the output
    pub fn into_bytes(self) -> Bytes {
        match self {
            LogOutput::StdErr { message } => message,
            LogOutput::StdOut { message } => message,
            LogOutput::StdIn { message } => message,
            LogOutput::Console { message } => message,
        }
    }
}

/// Parameters used in the [Create Checkpoint API](Docker::create_checkpoint())
///
/// ## Examples
///
/// ```rust
/// use bollard::container::CreateCheckpointOptions;
///
/// CreateCheckpointOptions {
///     checkpoint_id: String::from("my-checkpoint"),
///     checkpoint_dir: None,
///     exit: true,
/// };
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct CreateCheckpointOptions {
    /// The checkpoint identifier.
    #[serde(rename = "CheckpointID")]
    pub checkpoint_id: String,
    /// Custom checkpoint storage directory.
    #[serde(rename = "CheckpointDir")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_dir: Option<String>,
    /// Stop the container after creating the checkpoint.
    #[serde(rename = "Exit")]
    pub exit: bool,
}

/// Parameters used in the [List Checkpoints API](Docker::list_checkpoints())
///
/// ## Examples
///
/// ```rust
/// use bollard::container::ListCheckpointsOptions;
///
/// ListCheckpointsOptions {
///     checkpoint_dir: Some(String::from("/custom/checkpoint/dir")),
/// };
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ListCheckpointsOptions {
    /// Custom checkpoint storage directory.
    #[serde(rename = "dir")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_dir: Option<String>,
}

/// Parameters used in the [Delete Checkpoint API](Docker::delete_checkpoint())
///
/// ## Examples
///
/// ```rust
/// use bollard::container::DeleteCheckpointOptions;
///
/// DeleteCheckpointOptions {
///     checkpoint_dir: Some(String::from("/custom/checkpoint/dir")),
/// };
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct DeleteCheckpointOptions {
    /// Custom checkpoint storage directory.
    #[serde(rename = "dir")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_dir: Option<String>,
}

/// Checkpoint summary returned by [List Checkpoints API](Docker::list_checkpoints())
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Checkpoint {
    /// Name of the checkpoint.
    #[serde(rename = "Name")]
    pub name: String,
}

impl Docker {
    /// ---
    ///
    /// # List Containers
    ///
    /// Returns a list of containers.
    ///
    /// # Arguments
    ///
    ///  - Optional [ListContainersOptions](crate::query_parameters::ListContainersOptions) struct.
    ///
    /// # Returns
    ///
    ///  - Vector of [ContainerSummary](ContainerSummary), wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::ListContainersOptionsBuilder;
    ///
    /// use std::collections::HashMap;
    ///
    /// let mut filters = HashMap::new();
    /// filters.insert("health".to_string(), vec!["unhealthy".to_string()]);
    ///
    /// let options = ListContainersOptionsBuilder::default()
    ///     .all(true)
    ///     .filters(&filters)
    ///     .build();
    ///
    /// docker.list_containers(Some(options));
    /// ```
    pub async fn list_containers(
        &self,
        options: Option<crate::query_parameters::ListContainersOptions>,
    ) -> Result<Vec<ContainerSummary>, Error> {
        let url = "/containers/json";

        let req = self.build_request(
            url,
            Builder::new().method(Method::GET),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Create Container
    ///
    /// Prepares a container for a subsequent start operation.
    ///
    /// # Arguments
    ///
    ///  - Optional [Create Container Options](crate::query_parameters::CreateContainerOptions) struct.
    ///  - Container [ContainerCreateBody](crate::models::ContainerCreateBody) struct.
    ///
    /// # Returns
    ///
    ///  - [ContainerCreateResponse](ContainerCreateResponse), wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::CreateContainerOptionsBuilder;
    /// use bollard::models::ContainerCreateBody;
    ///
    /// let options = CreateContainerOptionsBuilder::default()
    ///     .name("my-new-container")
    ///     .build();
    ///
    /// let config = ContainerCreateBody {
    ///     image: Some("hello-world".to_string()),
    ///     cmd: Some(vec!["/hello".to_string()]),
    ///     ..Default::default()
    /// };
    ///
    /// docker.create_container(Some(options), config);
    /// ```
    pub async fn create_container(
        &self,
        options: Option<crate::query_parameters::CreateContainerOptions>,
        config: ContainerCreateBody,
    ) -> Result<ContainerCreateResponse, Error> {
        let url = "/containers/create";
        let req = self.build_request(
            url,
            Builder::new().method(Method::POST),
            options,
            Docker::serialize_payload(Some(config)),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Start Container
    ///
    /// Starts a container, after preparing it with the [Create Container
    /// API](struct.Docker.html#method.create_container).
    ///
    /// # Arguments
    ///
    ///  - Container name as a string slice.
    ///  - Optional [Start Container Options](crate::query_parameters::StartContainerOptions) struct.
    ///
    /// # Returns
    ///
    ///  - unit type `()`, wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    ///
    /// docker.start_container("hello-world", None);
    /// ```
    pub async fn start_container(
        &self,
        container_name: &str,
        options: Option<crate::query_parameters::StartContainerOptions>,
    ) -> Result<(), Error> {
        let url = format!("/containers/{container_name}/start");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::POST),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Stop Container
    ///
    /// Stops a container.
    ///
    /// # Arguments
    ///
    /// - Container name as string slice.
    /// - Optional [Stop Container Options](crate::query_parameters::StopContainerOptions) struct.
    ///
    /// # Returns
    ///
    ///  - unit type `()`, wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::StopContainerOptionsBuilder;
    ///
    /// let options = StopContainerOptionsBuilder::default()
    ///     .t(30)
    ///     .build();
    ///
    /// docker.stop_container("hello-world", Some(options));
    /// ```
    pub async fn stop_container(
        &self,
        container_name: &str,
        options: Option<crate::query_parameters::StopContainerOptions>,
    ) -> Result<(), Error> {
        let url = format!("/containers/{container_name}/stop");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::POST),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Remove Container
    ///
    /// Remove a container.
    ///
    /// # Arguments
    ///
    /// - Container name as a string slice.
    /// - Optional [Remove Container Options](crate::query_parameters::RemoveContainerOptions) struct.
    ///
    /// # Returns
    ///
    ///  - unit type `()`, wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::RemoveContainerOptionsBuilder;
    ///
    /// let options = RemoveContainerOptionsBuilder::default()
    ///     .force(true)
    ///     .build();
    ///
    /// docker.remove_container("hello-world", Some(options));
    /// ```
    pub async fn remove_container(
        &self,
        container_name: &str,
        options: Option<crate::query_parameters::RemoveContainerOptions>,
    ) -> Result<(), Error> {
        let url = format!("/containers/{container_name}");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::DELETE),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Wait Container
    ///
    /// Wait for a container to stop. This is a non-blocking operation, the resulting stream will
    /// end when the container stops.
    ///
    /// # Arguments
    ///
    /// - Container name as string slice.
    /// - Optional [Wait Container Options](crate::query_parameters::WaitContainerOptions) struct.
    ///
    /// # Returns
    ///
    ///  - [ContainerWaitResponse](ContainerWaitResponse), wrapped in a
    ///    Stream.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::WaitContainerOptionsBuilder;
    ///
    /// let options = WaitContainerOptionsBuilder::default()
    ///     .condition("not-running")
    ///     .build();
    ///
    /// docker.wait_container("hello-world", Some(options));
    /// ```
    pub fn wait_container(
        &self,
        container_name: &str,
        options: Option<crate::query_parameters::WaitContainerOptions>,
    ) -> impl Stream<Item = Result<ContainerWaitResponse, Error>> {
        let url = format!("/containers/{container_name}/wait");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::POST),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_stream(req).map(|res| match res {
            Ok(ContainerWaitResponse {
                status_code: code,
                error:
                    Some(ContainerWaitExitError {
                        message: Some(error),
                    }),
            }) if code > 0 => Err(Error::DockerContainerWaitError { error, code }),
            Ok(ContainerWaitResponse {
                status_code: code,
                error: None,
            }) if code > 0 => Err(Error::DockerContainerWaitError {
                error: String::new(),
                code,
            }),
            v => v,
        })
    }

    /// ---
    ///
    /// # Attach Container
    ///
    /// Attach to a container to read its output or send it input. You can attach to the
    /// same container multiple times and you can reattach to containers that have been detached.
    ///
    /// # Arguments
    ///
    /// - Container name as string slice.
    /// - Optional [Attach Container Options](crate::query_parameters::AttachContainerOptions) struct.
    ///
    /// # Returns
    ///
    ///  - [AttachContainerResults](AttachContainerResults) wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::AttachContainerOptionsBuilder;
    ///
    /// let options = AttachContainerOptionsBuilder::default()
    ///     .stdin(true)
    ///     .stdout(true)
    ///     .stderr(true)
    ///     .stream(true)
    ///     .logs(true)
    ///     .detach_keys("ctrl-c")
    ///     .build();
    ///
    /// docker.attach_container("hello-world", Some(options));
    /// ```
    pub async fn attach_container(
        &self,
        container_name: &str,
        options: Option<crate::query_parameters::AttachContainerOptions>,
    ) -> Result<AttachContainerResults, Error> {
        let url = format!("/containers/{container_name}/attach");

        let req = self.build_request(
            &url,
            Builder::new()
                .method(Method::POST)
                .header(CONNECTION, "Upgrade")
                .header(UPGRADE, "tcp"),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        let (read, write) = self.process_upgraded(req).await?;
        let log = FramedRead::new(read, NewlineLogOutputDecoder::new(true)).map_err(|e| e.into());

        Ok(AttachContainerResults {
            output: Box::pin(log),
            input: Box::pin(write),
        })
    }

    /// ---
    ///
    /// # Attach Container via WebSocket
    ///
    /// Attach to a container using the WebSocket protocol. This uses the Docker Engine API
    /// endpoint `GET /containers/{id}/attach/ws`.
    ///
    /// This is an alternative to [attach_container](Docker::attach_container()) that uses
    /// WebSocket for communication, which can be useful for browser-based terminals and
    /// other WebSocket-native clients.
    ///
    /// # Known Limitations
    ///
    /// Docker's WebSocket attach endpoint uses `golang.org/x/net/websocket` server-side,
    /// which has compatibility issues with standard RFC 6455 WebSocket implementations.
    /// Data flow may be unreliable on some Docker versions. For production use, prefer
    /// [attach_container](Docker::attach_container()) which uses HTTP upgrade to TCP.
    ///
    /// # Arguments
    ///
    /// - Container name as a string slice.
    /// - Optional [Attach Container Options](crate::query_parameters::AttachContainerOptions) struct.
    ///
    /// # Returns
    ///
    /// - [AttachContainerResults](AttachContainerResults) wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::AttachContainerOptionsBuilder;
    ///
    /// let options = AttachContainerOptionsBuilder::default()
    ///     .stdin(true)
    ///     .stdout(true)
    ///     .stderr(true)
    ///     .stream(true)
    ///     .logs(true)
    ///     .detach_keys("ctrl-c")
    ///     .build();
    ///
    /// # async {
    /// docker.attach_container_websocket("hello-world", Some(options)).await;
    /// # };
    /// ```
    #[cfg(all(feature = "websocket", unix))]
    pub async fn attach_container_websocket(
        &self,
        container_name: &str,
        options: Option<crate::query_parameters::AttachContainerOptions>,
    ) -> Result<AttachContainerResults, Error> {
        let path = format!("/containers/{container_name}/attach/ws");

        let ws_stream = self.process_websocket(&path, options).await?;
        let (write, read) = futures_util::StreamExt::split(ws_stream);

        let ws_reader = WebSocketReader::new(read);
        let log =
            FramedRead::new(ws_reader, NewlineLogOutputDecoder::new(true)).map_err(|e| e.into());

        let ws_writer = WebSocketWriter::new(write);

        Ok(AttachContainerResults {
            output: Box::pin(log),
            input: Box::pin(ws_writer),
        })
    }

    /// Attach to a container using the WebSocket protocol over TCP.
    ///
    /// See [attach_container_websocket](Docker::attach_container_websocket()) for details.
    #[cfg(all(feature = "websocket", not(unix)))]
    pub async fn attach_container_websocket(
        &self,
        container_name: &str,
        options: Option<crate::query_parameters::AttachContainerOptions>,
    ) -> Result<AttachContainerResults, Error> {
        let path = format!("/containers/{container_name}/attach/ws");

        let ws_stream = self.process_websocket(&path, options).await?;
        let (write, read) = futures_util::StreamExt::split(ws_stream);

        let ws_reader = WebSocketReader::new(read);
        let log =
            FramedRead::new(ws_reader, NewlineLogOutputDecoder::new(true)).map_err(|e| e.into());

        let ws_writer = WebSocketWriter::new(write);

        Ok(AttachContainerResults {
            output: Box::pin(log),
            input: Box::pin(ws_writer),
        })
    }

    /// ---
    ///
    /// # Resize container tty
    ///
    /// Resize the container's TTY.
    ///
    /// # Arguments
    ///
    /// - Container name as string slice.
    /// - [Resize Container Tty Options](crate::query_parameters::ResizeContainerTTYOptions) struct.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::ResizeContainerTTYOptionsBuilder;
    ///
    /// let options = ResizeContainerTTYOptionsBuilder::default()
    ///     .w(50)
    ///     .h(20)
    ///     .build();
    ///
    /// docker.resize_container_tty("hello-world", options);
    /// ```
    pub async fn resize_container_tty(
        &self,
        container_name: &str,
        options: crate::query_parameters::ResizeContainerTTYOptions,
    ) -> Result<(), Error> {
        let url = format!("/containers/{container_name}/resize");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::POST),
            Some(options),
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Restart Container
    ///
    /// Restart a container.
    ///
    /// # Arguments
    ///
    ///  - Container name as string slice.
    ///  - Optional [Restart Container Options](crate::query_parameters::RestartContainerOptions) struct.
    ///
    /// # Returns
    ///
    ///  - unit type `()`, wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::RestartContainerOptionsBuilder;
    ///
    /// let options = RestartContainerOptionsBuilder::default()
    ///     .t(30)
    ///     .build();
    ///
    /// docker.restart_container("postgres", Some(options));
    /// ```
    pub async fn restart_container(
        &self,
        container_name: &str,
        options: Option<crate::query_parameters::RestartContainerOptions>,
    ) -> Result<(), Error> {
        let url = format!("/containers/{container_name}/restart");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::POST),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Inspect Container
    ///
    /// Inspect a container.
    ///
    /// # Arguments
    ///
    ///  - Container name as a string slice.
    ///  - Optional [Inspect Container Options](crate::query_parameters::InspectContainerOptions) struct.
    ///
    /// # Returns
    ///
    ///  - [ContainerInspectResponse](ContainerInspectResponse), wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::InspectContainerOptionsBuilder;
    ///
    /// let options = InspectContainerOptionsBuilder::default()
    ///     .size(false)
    ///     .build();
    ///
    /// docker.inspect_container("hello-world", Some(options));
    /// ```
    pub async fn inspect_container(
        &self,
        container_name: &str,
        options: Option<crate::query_parameters::InspectContainerOptions>,
    ) -> Result<ContainerInspectResponse, Error> {
        let url = format!("/containers/{container_name}/json");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::GET),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Get Archive information From Container
    ///
    /// Get information on an archive of a resource in the filesystem of container id.
    ///
    /// # Arguments
    ///
    ///  - Container name as a string slice.
    ///  - [ContainerArchiveInfoOptions](crate::query_parameters::ContainerArchiveInfoOptions) struct.
    ///
    /// # Returns
    ///
    ///  - [PathStatResponse](PathStatResponse), wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::ContainerArchiveInfoOptionsBuilder;
    ///
    /// let options = ContainerArchiveInfoOptionsBuilder::default().path("/example").build();
    ///
    /// docker.get_container_archive_info("my-container", Some(options));
    /// ```
    pub async fn get_container_archive_info(
        &self,
        container_name: &str,
        options: Option<crate::query_parameters::ContainerArchiveInfoOptions>,
    ) -> Result<PathStatResponse, Error> {
        let url = format!("/containers/{container_name}/archive");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::HEAD),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        let container_path_stat_header = "X-Docker-Container-Path-Stat";

        let response = self.process_request(req).await?;

        // Grab the header from the response
        let container_path_stat = response
            .headers()
            .get(container_path_stat_header)
            .ok_or(Error::HttpHeaderNotFoundError(
                container_path_stat_header.to_owned(),
            ))?
            .to_str()?;

        let decoded_response = BASE64_STANDARD.decode(container_path_stat)?;

        let path_stat: PathStatResponse = serde_json::from_slice(&decoded_response)?;

        Ok(path_stat)
    }

    /// ---
    ///
    /// # Top Processes
    ///
    /// List processes running inside a container.
    ///
    /// # Arguments
    ///
    ///  - Container name as string slice.
    ///  - Optional [Top Options](crate::query_parameters::TopOptions) struct.
    ///
    /// # Returns
    ///
    ///  - [ContainerTopResponse](ContainerTopResponse), wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::TopOptionsBuilder;
    ///
    /// let options = TopOptionsBuilder::default()
    ///     .ps_args("aux")
    ///     .build();
    ///
    /// docker.top_processes("fussybeaver/uhttpd", Some(options));
    /// ```
    pub async fn top_processes(
        &self,
        container_name: &str,
        options: Option<crate::query_parameters::TopOptions>,
    ) -> Result<ContainerTopResponse, Error> {
        let url = format!("/containers/{container_name}/top");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::GET),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Logs
    ///
    /// Get container logs.
    ///
    /// # Arguments
    ///
    ///  - Container name as string slice.
    ///  - Optional [Logs Options](crate::query_parameters::LogsOptions) struct.
    ///
    /// # Returns
    ///
    ///  - [Log Output](LogOutput) enum, wrapped in a
    ///    Stream.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::LogsOptionsBuilder;
    ///
    /// let options = LogsOptionsBuilder::default()
    ///     .stdout(true)
    ///     .build();
    ///
    /// docker.logs("hello-world", Some(options));
    /// ```
    pub fn logs(
        &self,
        container_name: &str,
        options: Option<crate::query_parameters::LogsOptions>,
    ) -> impl Stream<Item = Result<LogOutput, Error>> {
        let url = format!("/containers/{container_name}/logs");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::GET),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_stream_string(req)
    }

    /// ---
    ///
    /// # Container Changes
    ///
    /// Get changes on a container's filesystem.
    ///
    /// # Arguments
    ///
    ///  - Container name as string slice.
    ///
    /// # Returns
    ///
    ///  - An Option of Vector of [File System Change](FilesystemChange) structs, wrapped in a
    ///    Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    ///
    /// docker.container_changes("hello-world");
    /// ```
    pub async fn container_changes(
        &self,
        container_name: &str,
    ) -> Result<Option<Vec<FilesystemChange>>, Error> {
        let url = format!("/containers/{container_name}/changes");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::GET),
            None::<String>,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Stats
    ///
    /// Get container stats based on resource usage.
    ///
    /// # Arguments
    ///
    /// - Container name as string slice.
    /// - Optional [Stats Options](crate::query_parameters::StatsOptions) struct.
    ///
    /// # Returns
    ///
    ///  - [ContainerStatsResponse](crate::models::ContainerStatsResponse) struct, wrapped in a
    ///    Stream.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::StatsOptionsBuilder;
    ///
    /// let options = StatsOptionsBuilder::default()
    ///     .stream(false)
    ///     .one_shot(true)
    ///     .build();
    ///
    /// docker.stats("hello-world", Some(options));
    /// ```
    pub fn stats(
        &self,
        container_name: &str,
        options: Option<crate::query_parameters::StatsOptions>,
    ) -> impl Stream<Item = Result<ContainerStatsResponse, Error>> {
        let url = format!("/containers/{container_name}/stats");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::GET),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_stream(req)
    }

    /// ---
    ///
    /// # Kill Container
    ///
    /// Kill a container.
    ///
    /// # Arguments
    ///
    /// - Container name as string slice.
    /// - Optional [Kill Container Options](crate::query_parameters::KillContainerOptions) struct.
    ///
    /// # Returns
    ///
    ///  - unit type `()`, wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::KillContainerOptionsBuilder;
    ///
    /// let options = KillContainerOptionsBuilder::default()
    ///     .signal("SIGINT")
    ///     .build();
    ///
    /// docker.kill_container("postgres", Some(options));
    /// ```
    pub async fn kill_container(
        &self,
        container_name: &str,
        options: Option<crate::query_parameters::KillContainerOptions>,
    ) -> Result<(), Error> {
        let url = format!("/containers/{container_name}/kill");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::POST),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Update Container
    ///
    /// Update a container.
    ///
    /// # Arguments
    ///
    ///  - Container name as string slice.
    ///  - [ContainerUpdateBody](crate::models::ContainerUpdateBody) struct.
    ///
    /// # Returns
    ///
    ///  - unit type `()`, wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::models::ContainerUpdateBody;
    ///
    /// let config = ContainerUpdateBody {
    ///     memory: Some(314572800),
    ///     memory_swap: Some(314572800),
    ///     ..Default::default()
    /// };
    ///
    /// docker.update_container("postgres", config);
    /// ```
    pub async fn update_container(
        &self,
        container_name: &str,
        config: ContainerUpdateBody,
    ) -> Result<(), Error> {
        let url = format!("/containers/{container_name}/update");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::POST),
            None::<String>,
            Docker::serialize_payload(Some(config)),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Rename Container
    ///
    /// Rename a container.
    ///
    /// # Arguments
    ///
    ///  - Container name as string slice.
    ///  - [Rename Container Options](crate::query_parameters::RenameContainerOptions) struct
    ///
    /// # Returns
    ///
    ///  - unit type `()`, wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::RenameContainerOptionsBuilder;
    ///
    /// let options = RenameContainerOptionsBuilder::default()
    ///     .name("my_new_container_name")
    ///     .build();
    ///
    /// docker.rename_container("hello-world", options);
    /// ```
    pub async fn rename_container(
        &self,
        container_name: &str,
        options: crate::query_parameters::RenameContainerOptions,
    ) -> Result<(), Error> {
        let url = format!("/containers/{container_name}/rename");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::POST),
            Some(options),
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Pause Container
    ///
    /// Use the cgroups freezer to suspend all processes in a container.
    ///
    /// # Arguments
    ///
    ///  - Container name as a string slice.
    ///
    /// # Returns
    ///
    ///  - unit type `()`, wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    ///
    /// docker.pause_container("postgres");
    /// ```
    pub async fn pause_container(&self, container_name: &str) -> Result<(), Error> {
        let url = format!("/containers/{container_name}/pause");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::POST),
            None::<String>,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Unpause Container
    ///
    /// Resume a container which has been paused.
    ///
    /// # Arguments
    ///
    ///  - Container name as a string slice.
    ///
    /// # Returns
    ///
    ///  - unit type `()`, wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    ///
    /// docker.unpause_container("postgres");
    /// ```
    pub async fn unpause_container(&self, container_name: &str) -> Result<(), Error> {
        let url = format!("/containers/{container_name}/unpause");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::POST),
            None::<String>,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Prune Containers
    ///
    /// Delete stopped containers.
    ///
    /// # Arguments
    ///
    ///  - Optional [Prune Containers Options](crate::query_parameters::PruneContainersOptions) struct.
    ///
    /// # Returns
    ///
    ///  - [Container Prune Response](ContainerPruneResponse) struct, wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::PruneContainersOptionsBuilder;
    ///
    /// use std::collections::HashMap;
    ///
    /// let mut filters = HashMap::new();
    /// filters.insert("until".to_string(), vec!["10m".to_string()]);
    ///
    /// let options = PruneContainersOptionsBuilder::default()
    ///     .filters(&filters)
    ///     .build();
    ///
    /// docker.prune_containers(Some(options));
    /// ```
    pub async fn prune_containers(
        &self,
        options: Option<crate::query_parameters::PruneContainersOptions>,
    ) -> Result<ContainerPruneResponse, Error> {
        let url = "/containers/prune";

        let req = self.build_request(
            url,
            Builder::new().method(Method::POST),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Stream Upload To Container
    ///
    /// Stream an upload of a tar archive to be extracted to a path in the filesystem of container
    /// id.
    ///
    /// # Arguments
    ///
    ///  - Optional [Upload To Container Options](crate::query_parameters::UploadToContainerOptions) struct.
    ///
    /// # Returns
    ///
    ///  - unit type `()`, wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use bollard::Docker;
    /// use bollard::query_parameters::UploadToContainerOptionsBuilder;
    /// use futures_util::{StreamExt, TryFutureExt};
    /// use tokio::fs::File;
    /// use tokio_util::io::ReaderStream;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// let options = UploadToContainerOptionsBuilder::default()
    ///     .path("/opt")
    ///     .build();
    ///
    /// let file = File::open("tarball.tar.gz")
    ///     .map_ok(ReaderStream::new)
    ///     .try_flatten_stream()
    ///     .map(|x|x.expect("failed to stream file"));
    ///
    /// docker
    ///     .upload_to_container_streaming("my-container", Some(options), file)
    ///     .await
    ///     .expect("upload failed");
    /// # }
    /// ```
    #[inline(always)]
    #[deprecated(
        since = "0.19.0",
        note = "This method is refactored into upload_to_container"
    )]
    pub async fn upload_to_container_streaming(
        &self,
        container_name: &str,
        options: Option<crate::query_parameters::UploadToContainerOptions>,
        tar: impl Stream<Item = Bytes> + Send + 'static,
    ) -> Result<(), Error> {
        self.upload_to_container(container_name, options, crate::body_stream(tar))
            .await
    }

    /// ---
    ///
    /// # Upload To Container
    ///
    /// Upload a tar archive to be extracted to a path in the filesystem of container id.
    ///
    /// # Arguments
    ///
    ///  - Optional [Upload To Container Options](crate::query_parameters::UploadToContainerOptions) struct.
    ///
    /// # Returns
    ///
    ///  - unit type `()`, wrapped in a Future.
    ///
    /// # Examples
    ///
    /// Uploading a tarball
    ///
    /// ```rust,no_run
    /// # use bollard::Docker;
    /// use bollard::query_parameters::UploadToContainerOptionsBuilder;
    /// use bollard::body_full;
    /// use std::fs::File;
    /// use std::io::Read;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// let options = UploadToContainerOptionsBuilder::default()
    ///     .path("/opt")
    ///     .build();
    ///
    /// let mut file = File::open("tarball.tar.gz").unwrap();
    /// let mut contents = Vec::new();
    /// file.read_to_end(&mut contents).unwrap();
    ///
    /// docker
    ///     .upload_to_container("my-container", Some(options), body_full(contents.into()))
    ///     .await
    ///     .expect("upload failed");
    /// # }
    /// ```
    /// Uploading a stream
    ///
    /// ```rust,no_run
    /// # use bollard::Docker;
    /// use bollard::query_parameters::UploadToContainerOptionsBuilder;
    /// use bollard::body_try_stream;
    /// use futures_util::{StreamExt, TryFutureExt};
    /// use tokio::fs::File;
    /// use tokio_util::io::ReaderStream;
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// let options = UploadToContainerOptionsBuilder::default()
    ///     .path("/opt")
    ///     .build();
    ///
    /// let file = File::open("tarball.tar.gz")
    ///     .map_ok(ReaderStream::new)
    ///     .try_flatten_stream();
    ///
    /// docker
    ///     .upload_to_container("my-container", Some(options), body_try_stream(file))
    ///     .await
    ///     .expect("upload failed");
    /// # }
    /// ```
    pub async fn upload_to_container(
        &self,
        container_name: &str,
        options: Option<crate::query_parameters::UploadToContainerOptions>,
        tar: BodyType,
    ) -> Result<(), Error> {
        let url = format!("/containers/{container_name}/archive");

        let req = self.build_request(
            &url,
            Builder::new()
                .method(Method::PUT)
                .header(CONTENT_TYPE, "application/x-tar"),
            options,
            Ok(tar),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Download From Container
    ///
    /// Get a tar archive of a resource in the filesystem of container id.
    ///
    /// # Arguments
    ///
    ///  - [Download From Container Options](crate::query_parameters::DownloadFromContainerOptions) struct.
    ///
    /// # Returns
    ///
    ///  - Tar archive compressed with one of the following algorithms: identity (no compression),
    ///    gzip, bzip2, xz. [Hyper Body](hyper::body::Body).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::DownloadFromContainerOptionsBuilder;
    ///
    /// let options = DownloadFromContainerOptionsBuilder::default()
    ///     .path("/opt")
    ///     .build();
    ///
    /// docker.download_from_container("my-container", Some(options));
    /// ```
    pub fn download_from_container(
        &self,
        container_name: &str,
        options: Option<crate::query_parameters::DownloadFromContainerOptions>,
    ) -> impl Stream<Item = Result<Bytes, Error>> {
        let url = format!("/containers/{container_name}/archive");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::GET),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_body(req)
    }

    /// ---
    ///
    /// # Export Container
    ///
    /// Get a tarball containing the filesystem contents of a container.
    ///
    /// See the [Docker API documentation](https://docs.docker.com/reference/api/engine/version/v1.52/#operation/ContainerExport)
    /// for more information.
    /// # Arguments
    /// - The `container_name` string referring to an individual container
    ///
    /// # Returns
    ///  - An uncompressed TAR archive
    pub fn export_container(
        &self,
        container_name: &str,
    ) -> impl Stream<Item = Result<Bytes, Error>> {
        let url = format!("/containers/{container_name}/export");
        let req = self.build_request(
            &url,
            Builder::new()
                .method(Method::GET)
                .header(CONTENT_TYPE, "application/json"),
            None::<String>,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );
        self.process_into_body(req)
    }

    /// ---
    ///
    /// # Create Checkpoint
    ///
    /// Create a checkpoint from a running container.
    ///
    /// This is an **experimental feature** that requires:
    /// - Docker daemon with experimental features enabled
    /// - CRIU installed on the host (Linux only)
    ///
    /// # Arguments
    ///
    ///  - Container name as a string slice.
    ///  - [CreateCheckpointOptions](CreateCheckpointOptions) struct.
    ///
    /// # Returns
    ///
    ///  - unit type `()`, wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::container::CreateCheckpointOptions;
    ///
    /// let options = CreateCheckpointOptions {
    ///     checkpoint_id: String::from("my-checkpoint"),
    ///     exit: true,
    ///     ..Default::default()
    /// };
    ///
    /// docker.create_checkpoint("my-container", options);
    /// ```
    pub async fn create_checkpoint(
        &self,
        container_name: &str,
        options: CreateCheckpointOptions,
    ) -> Result<(), Error> {
        let url = format!("/containers/{container_name}/checkpoints");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::POST),
            None::<String>,
            Docker::serialize_payload(Some(options)),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # List Checkpoints
    ///
    /// List checkpoints for a container.
    ///
    /// See [create_checkpoint](Docker::create_checkpoint) for experimental feature requirements.
    ///
    /// # Arguments
    ///
    ///  - Container name as a string slice.
    ///  - Optional [ListCheckpointsOptions](ListCheckpointsOptions) struct.
    ///
    /// # Returns
    ///
    ///  - Vector of [Checkpoint](Checkpoint) structs, wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::container::ListCheckpointsOptions;
    ///
    /// docker.list_checkpoints("my-container", None::<ListCheckpointsOptions>);
    /// ```
    pub async fn list_checkpoints(
        &self,
        container_name: &str,
        options: Option<ListCheckpointsOptions>,
    ) -> Result<Vec<Checkpoint>, Error> {
        let url = format!("/containers/{container_name}/checkpoints");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::GET),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        // Docker returns null instead of [] when no checkpoints exist
        let result: Option<Vec<Checkpoint>> = self.process_into_value(req).await?;
        Ok(result.unwrap_or_default())
    }

    /// ---
    ///
    /// # Delete Checkpoint
    ///
    /// Delete a checkpoint from a container.
    ///
    /// See [create_checkpoint](Docker::create_checkpoint) for experimental feature requirements.
    ///
    /// # Arguments
    ///
    ///  - Container name as a string slice.
    ///  - Checkpoint ID as a string slice.
    ///  - Optional [DeleteCheckpointOptions](DeleteCheckpointOptions) struct.
    ///
    /// # Returns
    ///
    ///  - unit type `()`, wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::container::DeleteCheckpointOptions;
    ///
    /// docker.delete_checkpoint("my-container", "my-checkpoint", None::<DeleteCheckpointOptions>);
    /// ```
    pub async fn delete_checkpoint(
        &self,
        container_name: &str,
        checkpoint_id: &str,
        options: Option<DeleteCheckpointOptions>,
    ) -> Result<(), Error> {
        let url = format!("/containers/{container_name}/checkpoints/{checkpoint_id}");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::DELETE),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_unit(req).await
    }
}

#[cfg(not(windows))]
#[cfg(test)]
mod tests {

    use futures_util::TryStreamExt;
    use yup_hyper_mock::HostToReplyConnector;

    use crate::models::ContainerCreateBody;
    use crate::query_parameters::{CreateContainerOptions, WaitContainerOptions};
    use crate::{Docker, API_DEFAULT_VERSION};

    #[tokio::test]
    async fn test_container_wait_with_error() {
        let mut connector = HostToReplyConnector::default();
        connector.m.insert(
            String::from("http://127.0.0.1"),
            "HTTP/1.1 200 OK\r\nServer:mock1\r\nContent-Type:application/json\r\n\r\n{\"Error\":null,\"StatusCode\":1}".to_string(),
        );

        let docker =
            Docker::connect_with_mock(connector, "127.0.0.1".to_string(), 5, API_DEFAULT_VERSION)
                .unwrap();

        let result = &docker
            .wait_container("wait_container_test", None::<WaitContainerOptions>)
            .try_collect::<Vec<_>>()
            .await;

        assert!(matches!(
            result,
            Err(crate::errors::Error::DockerContainerWaitError { code: _, error: _ })
        ));
    }

    #[tokio::test]
    async fn test_output_non_json_error() {
        let mut connector = HostToReplyConnector::default();
        connector.m.insert(
            String::from("http://127.0.0.1"),
            "HTTP/1.1 200 OK\r\nServer:mock1\r\nContent-Type:plain/text\r\n\r\nthis is not json"
                .to_string(),
        );
        let docker =
            Docker::connect_with_mock(connector, "127.0.0.1".to_string(), 5, API_DEFAULT_VERSION)
                .unwrap();

        let host_config = bollard_stubs::models::HostConfig {
            mounts: Some(vec![bollard_stubs::models::Mount {
                target: Some(String::from("/tmp")),
                source: Some(String::from("./tmp")),
                typ: Some(bollard_stubs::models::MountTypeEnum::BIND),
                consistency: Some(String::from("default")),
                ..Default::default()
            }]),
            ..Default::default()
        };

        let result = &docker
            .create_container(
                Some(CreateContainerOptions {
                    name: Some("mount_volume_container_failure_test".to_string()),
                    ..Default::default()
                }),
                ContainerCreateBody {
                    image: Some("some_image".to_string()),
                    host_config: Some(host_config),
                    ..Default::default()
                },
            )
            .await;

        println!("{result:#?}");

        assert!(matches!(
            result,
            Err(crate::errors::Error::JsonDataError {
                message: _,
                column: 2,
                ..
            })
        ));
    }
}
