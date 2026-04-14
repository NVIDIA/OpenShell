//! [![crates.io](https://img.shields.io/crates/v/bollard.svg)](https://crates.io/crates/bollard)
//! [![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
//! [![circle-ci](https://circleci.com/gh/fussybeaver/bollard/tree/master.svg?style=svg)](https://circleci.com/gh/fussybeaver/bollard/tree/master)
//! [![appveyor](https://ci.appveyor.com/api/projects/status/n5khebyfae0u1sbv/branch/master?svg=true)](https://ci.appveyor.com/project/fussybeaver/boondock)
//! [![docs](https://docs.rs/bollard/badge.svg)](https://docs.rs/bollard/)
//!
//! # Bollard: an asynchronous rust client library for the docker API
//!
//! Bollard leverages the latest [Hyper](https://github.com/hyperium/hyper) and
//! [Tokio](https://github.com/tokio-rs/tokio) improvements for an asynchronous API containing
//! futures, streams and the async/await paradigm.
//!
//! This library features Windows support through [Named
//! Pipes](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes) and HTTPS support through optional
//! [Rustls](https://github.com/rustls/rustls) bindings. Serialization types for interfacing with
//! [Docker](https://github.com/moby/moby) and [Buildkit](https://github.com/moby/buildkit) are
//! generated through OpenAPI, protobuf and upstream documentation.
//!
//! # Install
//!
//! Add the following to your `Cargo.toml` file
//!
//! ```nocompile
//! [dependencies]
//! bollard = "*"
//! ```
//!
//! # API
//! ## Documentation
//!
//! [API docs](https://docs.rs/bollard/).
//!
//! ## Feature flags
//!
//! ### Quick Start
//!
//! | Use Case | Cargo.toml |
//! |----------|------------|
//! | Local Docker (Unix/Windows) | `bollard = "*"` _(defaults work)_ |
//! | Remote Docker over HTTPS | `bollard = { version = "*", features = ["ssl"] }` |
//! | SSH tunnel to remote Docker | `bollard = { version = "*", features = ["ssh"] }` |
//! | BuildKit image builds | `bollard = { version = "*", features = ["buildkit", "chrono"] }` |
//! | WebSocket container attach | `bollard = { version = "*", features = ["websocket"] }` |
//! | Minimal binary size | `bollard = { version = "*", default-features = false, features = ["pipe"] }` |
//!
//! ### Default Features
//!
//! Enabled by default:
//! - `http` - TCP connections to remote Docker (`DOCKER_HOST=tcp://...`)
//! - `pipe` - Unix sockets (`/var/run/docker.sock`) and Windows named pipes
//!
//! ### Transport Features
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `http` | HTTP/TCP connector for remote Docker |
//! | `pipe` | Unix socket / Windows named pipe for local Docker |
//! | `ssh` | SSH tunnel connector |
//!
//! ### TLS/SSL Features
//!
//! Choose **one** crypto provider:
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `ssl` | [Rustls](https://github.com/rustls/rustls) with [ring](https://github.com/briansmith/ring) provider (recommended) |
//! | `aws-lc-rs` | [Rustls](https://github.com/rustls/rustls) with [aws-lc-rs](https://github.com/aws/aws-lc-rs) provider (FIPS-compliant) |
//! | `ssl_providerless` | [Rustls](https://github.com/rustls/rustls) without crypto provider (bring your own [`CryptoProvider`](https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html)) |
//! | `webpki` | Use Mozilla's root certificates instead of OS native certs |
//!
//! ### DateTime Features
//!
//! For timestamp support in events and logs, choose **one**:
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `chrono` | [Chrono](https://github.com/chronotope/chrono) date/time types |
//! | `time` | [Time 0.3](https://github.com/time-rs/time) date/time types |
//!
//! **Note:** `chrono` and `time` are mutually exclusive.
//!
//! ### BuildKit Features
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `buildkit` | Full [BuildKit](https://github.com/moby/buildkit) support (includes `ssl`) |
//! | `buildkit_providerless` | BuildKit without bundled crypto provider |
//!
//! **Note:** BuildKit requires either `chrono` or `time` feature to be enabled for timestamp handling.
//!
//! ### WebSocket Features
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `websocket` | WebSocket support for [`attach_container_websocket`](Docker::attach_container_websocket) using [tokio-tungstenite](https://github.com/snapview/tokio-tungstenite) |
//!
//! ### Development Features
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `json_data_content` | Include raw JSON payload in deserialization errors |
//!
//! ## Version
//!
//! The [Docker API](https://docs.docker.com/reference/api/engine/version/v1.52/) used by Bollard is using the latest
//! `1.52` documentation schema published by the [moby](https://github.com/moby/moby) project to
//! generate its serialization interface.
//!
//! This library also supports [version
//! negotiation](https://docs.rs/bollard/latest/bollard/struct.Docker.html#method.negotiate_version),
//! to allow downgrading to an older API version.
//!
//! # Usage
//!
//! ## Connecting with the docker daemon
//!
//! Connect to the docker server according to your architecture and security remit.
//!
//! ### Socket
//!
//! The client will connect to the standard unix socket location `/var/run/docker.sock` or Windows
//! named pipe location `//./pipe/docker_engine`.
//!
//! ```rust
//! use bollard::Docker;
//! #[cfg(unix)]
//! Docker::connect_with_socket_defaults();
//! ```
//!
//! Use the `Docker::connect_with_socket` method API to parameterise this interface.
//!
//! ### Local
//!
//! The client will connect to the OS specific handler it is compiled for.
//!
//! This is a convenience for localhost environment that should run on multiple
//! operating systems.
//!
//! ```rust
//! use bollard::Docker;
//! Docker::connect_with_local_defaults();
//! ```
//!
//! Use the `Docker::connect_with_local` method API to parameterise this interface.
//!
//! ### HTTP
//!
//! The client will connect to the location pointed to by `DOCKER_HOST` environment variable, or
//! `localhost:2375` if missing.
//!
//! ```rust
//! use bollard::Docker;
//! Docker::connect_with_http_defaults();
//! ```
//!
//! Use the `Docker::connect_with_http` method API to parameterise the interface.
//!
//! ### SSL via Rustls
//!
//! The client will connect to the location pointed to by `DOCKER_HOST` environment variable, or
//! `localhost:2375` if missing.
//!
//! The location pointed to by the `DOCKER_CERT_PATH` environment variable is searched for
//! certificates - `key.pem` for the private key, `cert.pem` for the server certificate and
//! `ca.pem` for the certificate authority chain.
//!
//! ```rust
//! use bollard::Docker;
//! #[cfg(feature = "ssl")]
//! Docker::connect_with_ssl_defaults();
//! ```
//!
//! Use the `Docker::connect_with_ssl` method API to parameterise the interface.
//!
//! ## Examples
//!
//! Note: all these examples need a [Tokio
//! Runtime](https://tokio.rs/).
//!
//! ### Version
//!
//! First, check that the API is working with your server:
//!
//! ```rust,no_run
//! use bollard::Docker;
//!
//! use futures_util::future::FutureExt;
//!
//! // Use a connection function described above
//! // let docker = Docker::connect_...;
//! # let docker = Docker::connect_with_local_defaults().unwrap();
//!
//! async move {
//!     let version = docker.version().await.unwrap();
//!     println!("{:?}", version);
//! };
//! ```
//!
//! ### Listing images
//!
//! To list docker images available on the Docker server:
//!
//! ```rust,no_run
//! use bollard::Docker;
//! use bollard::query_parameters::ListImagesOptionsBuilder;
//!
//! use futures_util::future::FutureExt;
//!
//! // Use a connection function described above
//! // let docker = Docker::connect_...;
//! # let docker = Docker::connect_with_local_defaults().unwrap();
//!
//! async move {
//!     let options = ListImagesOptionsBuilder::default()
//!         .all(true)
//!         .build();
//!     let images = &docker.list_images(Some(options)).await.unwrap();
//!
//!     for image in images {
//!         println!("-> {:?}", image);
//!     }
//! };
//! ```
//!
//! ## Streaming Stats
//!
//! To receive a stream of stats for a running container.
//!
//! ```rust,no_run
//! use bollard::Docker;
//! use bollard::query_parameters::StatsOptionsBuilder;
//!
//! use futures_util::stream::TryStreamExt;
//!
//! use std::default::Default;
//!
//! // Use a connection function described above
//! // let docker = Docker::connect_...;
//! # let docker = Docker::connect_with_local_defaults().unwrap();
//!
//! async move {
//!     let stats = &docker.stats("postgres", Some(
//!       StatsOptionsBuilder::default().stream(true).build()
//!     )).try_collect::<Vec<_>>().await.unwrap();
//!
//!     for stat in stats {
//!         println!("{} - mem total: {:?} | mem usage: {:?}",
//!             stat.name.as_ref().unwrap(),
//!             stat.memory_stats.as_ref().unwrap().max_usage,
//!             stat.memory_stats.as_ref().unwrap().usage);
//!     }
//! };
//! ```
//!
//! # Examples
//!
//! Further examples are available in the [examples
//! folder](https://github.com/fussybeaver/bollard/tree/master/examples), or the [integration/unit
//! tests](https://github.com/fussybeaver/bollard/tree/master/tests).
//!
//! # Development
//!
//! Contributions are welcome, please observe the following.
//!
//! ## Building the proto models
//!
//! Serialization models for the buildkit feature are generated through the [Tonic
//! library](https://github.com/hyperium/tonic/). To generate these files, use the
//! following in the `codegen/proto` folder:
//!
//! ```bash
//! cargo run --bin gen --features build
//! ```
//!
//! ## Building the swagger models
//!
//! Serialization models are generated through the [Swagger
//! library](https://github.com/swagger-api/swagger-codegen/). To generate these files, use the
//! following in the `codegen/swagger` folder:
//!
//! ```bash
//! mvn -D org.slf4j.simpleLogger.defaultLogLevel=error compiler:compile generate-resources
//! ```
//!
//! # Integration tests
//!
//! Running the integration tests by default requires a running docker registry, with images tagged
//! and pushed there. To disable this behaviour, set the `DISABLE_REGISTRY` environment variable.
//!
//! ```bash
//! docker run -d --restart always --name registry -p 5000:5000 registry:2
//! docker pull hello-world:linux
//! docker pull fussybeaver/uhttpd
//! docker pull alpine
//! docker tag hello-world:linux localhost:5000/hello-world:linux
//! docker tag fussybeaver/uhttpd localhost:5000/fussybeaver/uhttpd
//! docker tag alpine localhost:5000/alpine
//! docker push localhost:5000/hello-world:linux
//! docker push localhost:5000/fussybeaver/uhttpd
//! docker push localhost:5000/alpine
//! docker swarm init
//! REGISTRY_HTTP_ADDR=localhost:5000 cargo test -- --test-threads 1
//! ```
#![deny(
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    //unstable_features,
    unused_import_braces,
)]
#![allow(
    clippy::upper_case_acronyms,
    clippy::derive_partial_eq_without_eq,
    async_fn_in_trait
)]
#![warn(rust_2018_idioms)]

// declare modules
pub mod auth;
pub mod config;
pub mod container;
mod docker;
pub mod errors;
pub mod exec;
pub mod image;
pub mod network;
pub mod node;
pub mod plugin;
mod read;
pub mod secret;
pub mod service;
#[cfg(feature = "ssh")]
mod ssh;
pub mod swarm;
pub mod system;
pub mod task;
mod uri;
pub mod volume;

pub mod grpc;

// publicly re-export
pub use crate::docker::{
    body_full, body_stream, body_try_stream, BollardRequest, ClientVersion, Docker,
    API_DEFAULT_VERSION,
};

/// Re-exported request body and response types from `bollard-stubs`.
///
/// Use these types directly from `bollard::models` instead of adding `bollard-stubs`
/// as a dependency. This ensures version compatibility and simplifies your dependencies.
///
/// # Example
///
/// ```rust,no_run
/// use bollard::Docker;
/// use bollard::models::ContainerCreateBody;
/// use bollard::query_parameters::CreateContainerOptionsBuilder;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let docker = Docker::connect_with_socket_defaults()?;
///
/// let config = ContainerCreateBody {
///     image: Some("alpine:latest".to_string()),
///     ..Default::default()
/// };
///
/// let options = CreateContainerOptionsBuilder::default()
///     .name("my_container")
///     .build();
///
/// docker.create_container(Some(options), config).await?;
/// # Ok(())
/// # }
/// ```
pub use bollard_stubs::models;

/// Re-exported query parameter types from `bollard-stubs`.
///
/// Use these types directly from `bollard::query_parameters` instead of adding
/// `bollard-stubs` as a dependency. Each API method has a corresponding options
/// builder (e.g., `CreateContainerOptionsBuilder`, `ListImagesOptionsBuilder`).
///
/// # Example
///
/// ```rust,no_run
/// use bollard::Docker;
/// use bollard::query_parameters::ListContainersOptionsBuilder;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let docker = Docker::connect_with_socket_defaults()?;
///
/// let options = ListContainersOptionsBuilder::default()
///     .all(true)
///     .build();
///
/// let containers = docker.list_containers(Some(options)).await?;
/// # Ok(())
/// # }
/// ```
pub use bollard_stubs::query_parameters;

#[cfg(feature = "buildkit_providerless")]
pub use bollard_buildkit_proto::fsutil;

#[cfg(feature = "buildkit_providerless")]
pub use bollard_buildkit_proto::health;

#[cfg(feature = "buildkit_providerless")]
pub use bollard_buildkit_proto::moby;
