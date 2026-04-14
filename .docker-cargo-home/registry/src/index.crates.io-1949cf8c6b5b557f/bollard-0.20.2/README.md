[![crates.io](https://img.shields.io/crates/v/bollard.svg)](https://crates.io/crates/bollard)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![circle-ci](https://circleci.com/gh/fussybeaver/bollard/tree/master.svg?style=svg)](https://circleci.com/gh/fussybeaver/bollard/tree/master)
[![appveyor](https://ci.appveyor.com/api/projects/status/n5khebyfae0u1sbv/branch/master?svg=true)](https://ci.appveyor.com/project/fussybeaver/boondock)
[![docs](https://docs.rs/bollard/badge.svg)](https://docs.rs/bollard/)

## Bollard: an asynchronous rust client library for the docker API

Bollard leverages the latest [Hyper](https://github.com/hyperium/hyper) and
[Tokio](https://github.com/tokio-rs/tokio) improvements for an asynchronous API containing
futures, streams and the async/await paradigm.

This library features Windows support through [Named
Pipes](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes) and HTTPS support through optional
[Rustls](https://github.com/rustls/rustls) bindings. Serialization types for interfacing with
[Docker](https://github.com/moby/moby) and [Buildkit](https://github.com/moby/buildkit) are
generated through OpenAPI, protobuf and upstream documentation.

## Install

Add the following to your `Cargo.toml` file

```nocompile
[dependencies]
bollard = "*"
```

## API
### Documentation

[API docs](https://docs.rs/bollard/).

### Feature flags

#### Quick Start

| Use Case | Cargo.toml |
|----------|------------|
| Local Docker (Unix/Windows) | `bollard = "*"` _(defaults work)_ |
| Remote Docker over HTTPS | `bollard = { version = "*", features = ["ssl"] }` |
| SSH tunnel to remote Docker | `bollard = { version = "*", features = ["ssh"] }` |
| BuildKit image builds | `bollard = { version = "*", features = ["buildkit", "chrono"] }` |
| WebSocket container attach | `bollard = { version = "*", features = ["websocket"] }` |
| Minimal binary size | `bollard = { version = "*", default-features = false, features = ["pipe"] }` |

#### Default Features

Enabled by default:
- `http` - TCP connections to remote Docker (`DOCKER_HOST=tcp://...`)
- `pipe` - Unix sockets (`/var/run/docker.sock`) and Windows named pipes

#### Transport Features

| Feature | Description |
|---------|-------------|
| `http` | HTTP/TCP connector for remote Docker |
| `pipe` | Unix socket / Windows named pipe for local Docker |
| `ssh` | SSH tunnel connector (requires `ssh` feature) |

#### TLS/SSL Features

Choose **one** crypto provider:

| Feature | Description |
|---------|-------------|
| `ssl` | [Rustls](https://github.com/rustls/rustls) with [ring](https://github.com/briansmith/ring) provider (recommended) |
| `aws-lc-rs` | [Rustls](https://github.com/rustls/rustls) with [aws-lc-rs](https://github.com/aws/aws-lc-rs) provider (FIPS-compliant) |
| `ssl_providerless` | [Rustls](https://github.com/rustls/rustls) without crypto provider (bring your own [CryptoProvider](https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html)) |
| `webpki` | Use Mozilla's root certificates instead of OS native certs |

#### DateTime Features

For timestamp support in events and logs, choose **one**:

| Feature | Description |
|---------|-------------|
| `chrono` | [Chrono](https://github.com/chronotope/chrono) date/time types |
| `time` | [Time 0.3](https://github.com/time-rs/time) date/time types |

**Note:** `chrono` and `time` are mutually exclusive.

#### BuildKit Features

| Feature | Description |
|---------|-------------|
| `buildkit` | Full [BuildKit](https://github.com/moby/buildkit) support (includes `ssl`) |
| `buildkit_providerless` | BuildKit without bundled crypto provider |

**Note:** BuildKit requires either `chrono` or `time` feature to be enabled for timestamp handling. Example:
```toml
bollard = { version = "*", features = ["buildkit", "chrono"] }
```

#### WebSocket Features

| Feature | Description |
|---------|-------------|
| `websocket` | WebSocket support for container attach using [tokio-tungstenite](https://github.com/snapview/tokio-tungstenite) |

#### Development Features

| Feature | Description |
|---------|-------------|
| `json_data_content` | Include raw JSON payload in deserialization errors |

### Version

The [Docker API](https://docs.docker.com/reference/api/engine/version/v1.52/) used by Bollard is using the latest
`1.52` documentation schema published by the [moby](https://github.com/moby/moby) project to
generate its serialization interface.

This library also supports [version
negotiation](https://docs.rs/bollard/latest/bollard/struct.Docker.html#method.negotiate_version),
to allow downgrading to an older API version.

## Usage

### Connecting with the docker daemon

Connect to the docker server according to your architecture and security remit.

#### Socket

The client will connect to the standard unix socket location `/var/run/docker.sock` or Windows
named pipe location `//./pipe/docker_engine`.

```rust
use bollard::Docker;
#[cfg(unix)]
Docker::connect_with_socket_defaults();
```

Use the `Docker::connect_with_socket` method API to parameterise this interface.

#### Local

The client will connect to the OS specific handler it is compiled for.

This is a convenience for localhost environment that should run on multiple
operating systems.

```rust
use bollard::Docker;
Docker::connect_with_local_defaults();
```

Use the `Docker::connect_with_local` method API to parameterise this interface.

#### HTTP

The client will connect to the location pointed to by `DOCKER_HOST` environment variable, or
`localhost:2375` if missing.

```rust
use bollard::Docker;
Docker::connect_with_http_defaults();
```

Use the `Docker::connect_with_http` method API to parameterise the interface.

#### SSL via Rustls

The client will connect to the location pointed to by `DOCKER_HOST` environment variable, or
`localhost:2375` if missing.

The location pointed to by the `DOCKER_CERT_PATH` environment variable is searched for
certificates - `key.pem` for the private key, `cert.pem` for the server certificate and
`ca.pem` for the certificate authority chain.

```rust
use bollard::Docker;
#[cfg(feature = "ssl")]
Docker::connect_with_ssl_defaults();
```

Use the `Docker::connect_with_ssl` method API to parameterise the interface.

### Examples

Note: all these examples need a [Tokio
Runtime](https://tokio.rs/).

#### Version

First, check that the API is working with your server:

```rust
use bollard::Docker;

use futures_util::future::FutureExt;

// Use a connection function described above
// let docker = Docker::connect_...;

async move {
    let version = docker.version().await.unwrap();
    println!("{:?}", version);
};
```

#### Listing images

To list docker images available on the Docker server:

```rust
use bollard::Docker;
use bollard::image::ListImagesOptions;

use futures_util::future::FutureExt;

use std::default::Default;

// Use a connection function described above
// let docker = Docker::connect_...;

async move {
    let images = &docker.list_images(Some(ListImagesOptions::<String> {
        all: true,
        ..Default::default()
    })).await.unwrap();

    for image in images {
        println!("-> {:?}", image);
    }
};
```

### Streaming Stats

To receive a stream of stats for a running container.

```rust
use bollard::Docker;
use bollard::query_parameters::StatsOptionsBuilder;

use futures_util::stream::TryStreamExt;

use std::default::Default;

// Use a connection function described above
// let docker = Docker::connect_...;

async move {
    let stats = &docker.stats("postgres", Some(
      StatsOptionsBuilder::default().stream(true).build()
    )).try_collect::<Vec<_>>().await.unwrap();

    for stat in stats {
        println!("{} - mem total: {:?} | mem usage: {:?}",
            stat.name.as_ref().unwrap(),
            stat.memory_stats.as_ref().unwrap().max_usage,
            stat.memory_stats.as_ref().unwrap().usage);
    }
};
```

## Examples

Further examples are available in the [examples
folder](https://github.com/fussybeaver/bollard/tree/master/examples), or the [integration/unit
tests](https://github.com/fussybeaver/bollard/tree/master/tests).

## Development

Contributions are welcome, please observe the following.

### Building the proto models

Serialization models for the buildkit feature are generated through the [Tonic
library](https://github.com/hyperium/tonic/). To generate these files, use the
following in the `codegen/proto` folder:

```bash
cargo run --bin gen --features build
```

### Building the swagger models

Serialization models are generated through the [Swagger
library](https://github.com/swagger-api/swagger-codegen/). To generate these files, use the
following in the `codegen/swagger` folder:

```bash
mvn -D org.slf4j.simpleLogger.defaultLogLevel=error compiler:compile generate-resources
```

## Integration tests

Running the integration tests by default requires a running docker registry, with images tagged
and pushed there. To disable this behaviour, set the `DISABLE_REGISTRY` environment variable.

```bash
docker run -d --restart always --name registry -p 5000:5000 registry:2
docker pull hello-world:linux
docker pull fussybeaver/uhttpd
docker pull alpine
docker tag hello-world:linux localhost:5000/hello-world:linux
docker tag fussybeaver/uhttpd localhost:5000/fussybeaver/uhttpd
docker tag alpine localhost:5000/alpine
docker push localhost:5000/hello-world:linux
docker push localhost:5000/fussybeaver/uhttpd
docker push localhost:5000/alpine
docker swarm init
REGISTRY_HTTP_ADDR=localhost:5000 cargo test -- --test-threads 1
```

License: Apache-2.0
