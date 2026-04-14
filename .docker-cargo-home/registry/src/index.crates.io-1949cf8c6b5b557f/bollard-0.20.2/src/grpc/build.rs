pub use bollard_buildkit_proto::fsutil;
pub use bollard_buildkit_proto::health;
pub use bollard_buildkit_proto::moby;
use bollard_buildkit_proto::moby::buildkit::v1::CacheOptionsEntry;

use std::collections::HashMap;
use std::fmt::Display;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;

use bytes::Bytes;

/// Parameters available for passing frontend options to buildkit when initiating a Solve GRPC
/// request, f.e. used in associated methods within the [GRPC module](module@crate::grpc)
///
/// ## Examples
///
/// ```rust
/// use bollard::grpc::build::ImageBuildFrontendOptions;
///
/// ImageBuildFrontendOptions::builder().pull(true).build();
///
/// ```
///
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ImageBuildFrontendOptions {
    //pub(crate) cgroupparent: Option<String>,
    //pub(crate) multiplatform: bool,
    //pub(crate) attests: HashMap<String, String>,
    pub(crate) cacheto: Vec<CacheOptionsEntry>,
    pub(crate) cachefrom: Vec<CacheOptionsEntry>,
    pub(crate) image_resolve_mode: bool,
    pub(crate) target: Option<String>,
    pub(crate) nocache: bool,
    pub(crate) buildargs: HashMap<String, String>,
    pub(crate) labels: HashMap<String, String>,
    pub(crate) platforms: Vec<ImageBuildPlatform>,
    pub(crate) force_network_mode: ImageBuildNetworkMode,
    pub(crate) extrahosts: Vec<ImageBuildHostIp>,
    pub(crate) shmsize: u64,
    pub(crate) secrets: HashMap<String, SecretSource>,
    pub(crate) ssh: bool,
    pub(crate) named_contexts: HashMap<String, NamedContext>,
    pub(crate) dockerfile: Option<PathBuf>,
    //pub(crate) ulimit: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
/// Specifies how secrets are populated into the buildkit build without persisting into the final image.
pub enum SecretSource {
    /// Sets the secret source as a local file, must be associated with appropriate Dockerfile
    /// instruction: `RUN mount=type=secret,id=foo,target=/location/to/file`
    File(std::path::PathBuf),
    /// Sets the secret source as an environment variable, must be associated with appropriate
    /// Dockerfile instruction: `RUN mount=type=secret,id=foo,env=MY_ENV_VAR`
    Env(String),
}

#[derive(Debug, Clone, PartialEq)]
/// A list of hostnames/IP mappings to add to the container's `/etc/hosts` file.
pub struct ImageBuildHostIp {
    /// The hosname mapping component of a hostname/IP mapping
    pub host: String,
    /// The IP mapping component of a hostname/IP mapping
    pub ip: IpAddr,
}

impl Display for ImageBuildHostIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}={}", self.host, self.ip)
    }
}

#[derive(Default, Debug, Clone, PartialEq)]
#[non_exhaustive]
/// Network mode to use for this container. Supported standard values are: `bridge`, `host`,
/// `none`, and `container:<name|id>`. Any other value is taken as a custom network's name to which
/// this container should connect to.
pub enum ImageBuildNetworkMode {
    /// Bridge mode networking
    #[default]
    Bridge,
    /// Host mode networking
    Host,
    /// No networking mode
    None,
    /// Container mode networking, with container name as `name`
    Container(String),
}

impl Display for ImageBuildNetworkMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageBuildNetworkMode::Bridge => write!(f, "default"),
            ImageBuildNetworkMode::Host => write!(f, "host"),
            ImageBuildNetworkMode::None => write!(f, "none"),
            ImageBuildNetworkMode::Container(name) => write!(f, "container:{name}"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
/// Describes the platform which the image in the manifest runs on, as defined in the [OCI Image Index Specification](https://github.com/opencontainers/image-spec/blob/v1.0.1/image-index.md).
pub struct ImageBuildPlatform {
    /// The CPU architecture, for example `amd64` or `ppc64`.
    pub architecture: String,
    /// The operating system, for example `linux` or `windows`.
    pub os: String,
    /// Optional field specifying a variant of the CPU, for example `v7` to specify ARMv7 when architecture is `arm`.
    pub variant: Option<String>,
}

impl Display for ImageBuildPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = Path::new(&self.os).join(Path::new(&self.architecture));
        if let Some(variant) = &self.variant {
            write!(f, "{}", prefix.join(Path::new(&variant)).display())
        } else {
            write!(f, "{}", prefix.display())
        }
    }
}

#[derive(Default, Debug, Copy, Clone, PartialEq)]
#[non_exhaustive]
/// Compression type for the exported image tar file
pub enum ImageBuildOutputCompression {
    /// Emit the tar file uncompressed
    Uncompressed,
    /// Emit the tar file GZIP compressed
    #[default]
    Gzip,
    /// Emit the tar file as a stargz snapshot
    Estargz,
    /// Emit the tar file with lossless Zstandard compression
    Zstd,
}

impl Display for ImageBuildOutputCompression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageBuildOutputCompression::Uncompressed => write!(f, "uncompressed"),
            ImageBuildOutputCompression::Gzip => write!(f, "gzip"),
            ImageBuildOutputCompression::Estargz => write!(f, "estargz"),
            ImageBuildOutputCompression::Zstd => write!(f, "zstd"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
/// An additional build context. Can be used to override a named stage in the Dockerfile.
pub struct NamedContext {
    /// Container image (with `docker-image://` prefix), Git, or HTTP URL.
    pub path: String,
}

pub(crate) struct ImageBuildFrontendOptionsIngest {
    pub cache_to: Vec<CacheOptionsEntry>,
    pub cache_from: Vec<CacheOptionsEntry>,
    pub frontend_attrs: HashMap<String, String>,
    pub secret_sources: HashMap<String, SecretSource>,
    pub ssh: bool,
}

impl ImageBuildFrontendOptions {
    /// Construct a builder for the `ImageBuildFrontendOptions`
    pub fn builder() -> ImageBuildFrontendOptionsBuilder {
        ImageBuildFrontendOptionsBuilder::new()
    }

    pub(crate) fn consume(self) -> ImageBuildFrontendOptionsIngest {
        let mut attrs = HashMap::new();

        if let Some(dockerfile) = self.dockerfile {
            attrs.insert(
                String::from("filename"),
                dockerfile.to_string_lossy().to_string(),
            );
        }

        if self.image_resolve_mode {
            attrs.insert(String::from("image-resolve-mode"), String::from("pull"));
        } else {
            attrs.insert(String::from("image-resolve-mode"), String::from("default"));
        }

        if let Some(target) = self.target {
            attrs.insert(String::from("target"), target);
        }

        if self.nocache {
            attrs.insert(String::from("no-cache"), String::new());
        }

        if !self.buildargs.is_empty() {
            for (key, value) in self.buildargs {
                attrs.insert(format!("build-arg:{}", key), value);
            }
        }

        if !self.labels.is_empty() {
            for (key, value) in self.labels {
                attrs.insert(format!("label:{}", key), value);
            }
        }

        if !self.platforms.is_empty() {
            attrs.insert(
                String::from("platform"),
                self.platforms
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }

        match self.force_network_mode {
            ImageBuildNetworkMode::Host => {
                attrs.insert(String::from("force-network-mode"), String::from("host"));
            }
            ImageBuildNetworkMode::None => {
                attrs.insert(String::from("force-network-mode"), String::from("none"));
            }
            _ => (),
        }

        if !self.extrahosts.is_empty() {
            attrs.insert(
                String::from("add-hosts"),
                self.extrahosts
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }

        if self.shmsize > 0 {
            attrs.insert(String::from("shm-size"), self.shmsize.to_string());
        }

        if !self.named_contexts.is_empty() {
            attrs.insert(
                String::from("frontend.caps"),
                String::from("moby.buildkit.frontend.contexts+forward"),
            );
            for (name, context) in self.named_contexts {
                attrs.insert(format!("context:{name}"), context.path);
            }
        }

        ImageBuildFrontendOptionsIngest {
            cache_to: self.cacheto,
            cache_from: self.cachefrom,
            frontend_attrs: attrs,
            secret_sources: self.secrets,
            ssh: self.ssh,
        }
    }
}

/// Builder for the associated [`ImageBuildFrontendOptions`] type
///
/// ## Examples
///
/// ```rust
/// use bollard::grpc::build::ImageBuildFrontendOptionsBuilder;
///
/// ImageBuildFrontendOptionsBuilder::new().pull(true).build();
///
/// ```
///
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ImageBuildFrontendOptionsBuilder {
    inner: ImageBuildFrontendOptions,
}

impl ImageBuildFrontendOptionsBuilder {
    /// Construct a new builder
    pub fn new() -> Self {
        Self {
            inner: ImageBuildFrontendOptions {
                ..Default::default()
            },
        }
    }

    /// Path within the build context to the `Dockerfile`.
    pub fn dockerfile(mut self, path: &Path) -> Self {
        self.inner.dockerfile = Some(path.to_path_buf());
        self
    }

    /// Image to add towards for build cache resolution.
    pub fn cacheto(mut self, value: &CacheOptionsEntry) -> Self {
        self.inner.cacheto.push(value.to_owned());
        self
    }

    /// Image to pull towards for build cache resolution.
    pub fn cachefrom(mut self, value: &CacheOptionsEntry) -> Self {
        self.inner.cachefrom.push(value.to_owned());
        self
    }

    /// Attempt to pull the image even if an older image exists locally.
    pub fn pull(mut self, pull: bool) -> Self {
        self.inner.image_resolve_mode = pull;
        self
    }

    /// A name and optional tag to apply to the image in the `name:tag` format. If you omit the tag
    /// the default `latest` value is assumed. You can provide several `t` parameters.
    pub fn target(mut self, target: &str) -> Self {
        self.inner.target = Some(String::from(target));
        self
    }

    /// Do not use the cache when building the image.
    pub fn nocache(mut self, nocache: bool) -> Self {
        self.inner.nocache = nocache;
        self
    }

    /// Add string pair for build-time variables. Users pass these values at build-time.
    /// Docker uses the buildargs as the environment context for commands run via the `Dockerfile`
    /// RUN instruction, or for variable expansion in other `Dockerfile` instructions.
    pub fn buildarg(mut self, key: &str, value: &str) -> Self {
        self.inner
            .buildargs
            .insert(String::from(key), String::from(value));
        self
    }

    /// Append arbitrary key/value label to set on the image.
    pub fn label(mut self, key: &str, value: &str) -> Self {
        self.inner
            .labels
            .insert(String::from(key), String::from(value));
        self
    }

    /// Platform in the format [`ImageBuildPlatform`]
    pub fn platforms(mut self, value: &ImageBuildPlatform) -> Self {
        self.inner.platforms.push(value.to_owned());
        self
    }

    /// Sets the networking mode for the run commands during build. Supported standard values are:
    /// `bridge`, `host`, `none`, and `container:<name|id>`.
    pub fn force_network_mode(mut self, value: &ImageBuildNetworkMode) -> Self {
        value.clone_into(&mut self.inner.force_network_mode);
        self
    }

    /// Extra hosts to add to `/etc/hosts`.
    pub fn extrahost(mut self, value: &ImageBuildHostIp) -> Self {
        self.inner.extrahosts.push(value.to_owned());
        self
    }

    /// Size of `/dev/shm` in bytes. The size must be greater than 0. If omitted the system uses 64MB.
    pub fn shmsize(mut self, value: u64) -> Self {
        self.inner.shmsize = value;
        self
    }

    /// Set source of a single secret as part of the build, either a file or environment variable.
    pub fn set_secret(mut self, key: &str, value: &SecretSource) -> Self {
        self.inner
            .secrets
            .insert(String::from(key), value.to_owned());
        self
    }

    /// Enable sshforward to ssh agent.
    pub fn enable_ssh(mut self, value: bool) -> Self {
        self.inner.ssh = value;
        self
    }

    /// Add a named build context.
    pub fn named_context(mut self, key: &str, value: NamedContext) -> Self {
        self.inner.named_contexts.insert(String::from(key), value);
        self
    }

    /// Consume the builder and emit an [`ImageBuildFrontendOptions`]
    pub fn build(self) -> ImageBuildFrontendOptions {
        self.inner
    }
}

#[derive(Debug, PartialEq)]
#[non_exhaustive]
/// Dockerfile seed implementation to export OCI images as part of the
/// [`crate::grpc::driver::Export::export`] Docker/buildkit functionality.
///
/// Accepts a compressed Dockerfile as Bytes
///
/// ## Examples
///
/// ```rust
///     # use std::io::Write;
///
///     let dockerfile = String::from(
///         "FROM alpine as builder1
///         RUN touch bollard.txt
///         FROM alpine as builder2
///         RUN --mount=type=bind,from=builder1,target=mnt cp mnt/bollard.txt buildkit-bollard.txt
///         ENTRYPOINT ls buildkit-bollard.txt
///         ",
///     );
///     let mut header = tar::Header::new_gnu();
///     header.set_path("Dockerfile").unwrap();
///     # header.set_size(dockerfile.len() as u64);
///     # header.set_mode(0o755);
///     # header.set_cksum();
///     let mut tar = tar::Builder::new(Vec::new());
///     tar.append(&header, dockerfile.as_bytes()).unwrap();
///     let uncompressed = tar.into_inner().unwrap();
///     let mut c = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
///     c.write_all(&uncompressed).unwrap();
///     let compressed = c.finish().unwrap();
///
///     bollard::grpc::build::ImageBuildLoadInput::Upload(bytes::Bytes::from(compressed));
///
/// ```
///
pub enum ImageBuildLoadInput {
    /// Seed the exporter with a tarball containing the Dockerfile to build
    Upload(Bytes),
}

#[cfg(test)]
mod tests {
    use super::ImageBuildPlatform;

    #[test]
    fn test_imagebuildplatform_display() {
        let platform = ImageBuildPlatform {
            architecture: String::from("amd64"),
            os: String::from("linux"),
            variant: None,
        };
        assert_eq!(platform.to_string(), "linux/amd64");
    }

    #[test]
    fn test_imagebuildplatform_display_with_variant() {
        let platform = ImageBuildPlatform {
            architecture: String::from("arm64"),
            os: String::from("linux"),
            variant: Some(String::from("v8")),
        };
        assert_eq!(platform.to_string(), "linux/arm64/v8");
    }
}
