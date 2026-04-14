#![cfg(feature = "buildkit_providerless")]

pub use bollard_buildkit_proto::fsutil;
pub use bollard_buildkit_proto::health;
pub use bollard_buildkit_proto::moby;

use std::collections::HashMap;
use std::fmt::Display;
use std::path::Path;

use super::build::ImageBuildOutputCompression;

/// Parameters available for passing exporter output options to buildkit when exporting images
/// using a Solve GRPC request, f.e. used in associated [GRPC export methods](module@crate::grpc::export)
///
/// ## Examples
///
/// ```rust
/// use bollard::grpc::build::ImageBuildFrontendOptions;
///
/// let frontend_options = ImageBuildFrontendOptions::builder().pull(true).build();
///
/// ```
///
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ImageExporterOutput {
    pub(crate) name: String,
    pub(crate) compression: ImageBuildOutputCompression,
    pub(crate) compression_level: Option<u8>,
    pub(crate) force_compression: bool,
    pub(crate) oci_mediatypes: bool,
    pub(crate) annotation: HashMap<String, String>,
}

#[derive(Default, Debug, Copy, Clone, PartialEq)]
#[non_exhaustive]
/// Compression type for the exported image tar file
pub enum ImageExporterOCIOutputCompression {
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

impl Display for ImageExporterOCIOutputCompression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageExporterOCIOutputCompression::Uncompressed => write!(f, "uncompressed"),
            ImageExporterOCIOutputCompression::Gzip => write!(f, "gzip"),
            ImageExporterOCIOutputCompression::Estargz => write!(f, "estargz"),
            ImageExporterOCIOutputCompression::Zstd => write!(f, "zstd"),
        }
    }
}

/// Request struct to parameterise export images as part of the
/// [`crate::grpc::driver::Export::export`] Docker/buildkit functionality.
///
/// Constructed through the [`ImageExporterOutputBuilder`] type.
///
/// ## Examples
///
/// ```rust
/// use bollard::grpc::export::ImageExporterOutput;
/// use std::path::Path;
///
/// ImageExporterOutput::builder("docker.io/library/my-image:latest")
///     .dest(&Path::new("/tmp/oci.tar"));
///
/// ```
///
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ImageExporterRequest {
    pub(crate) output: ImageExporterOutput,
    pub(crate) path: std::path::PathBuf,
}

impl ImageExporterOutput {
    /// Constructs a [`ImageExporterOutputBuilder`], the `name` parameter denotes the output
    /// image target, e.g. "docker.io/library/my-image:latest".
    pub fn builder(name: &str) -> ImageExporterOutputBuilder {
        ImageExporterOutputBuilder::new(name)
    }

    fn new(name: &str) -> Self {
        Self {
            name: String::from(name),
            ..Default::default()
        }
    }

    pub(crate) fn into_map(self) -> HashMap<String, String> {
        let mut attrs = HashMap::new();

        attrs.insert(String::from("name"), self.name);
        attrs.insert(String::from("compression"), self.compression.to_string());

        if let Some(compression_level) = self.compression_level {
            attrs.insert(
                String::from("compression-level"),
                compression_level.to_string(),
            );
        }

        attrs.insert(
            String::from("force-compression"),
            self.force_compression.to_string(),
        );
        attrs.insert(
            String::from("oci-mediatypes"),
            self.oci_mediatypes.to_string(),
        );

        for (key, value) in self.annotation {
            attrs.insert(format!("annotation.{}", key), value);
        }

        attrs
    }
}

/// Builder used to parameterise export OCI images as part of the
/// [`crate::grpc::driver::Export::export`] Docker/buildkit functionality.
///
/// ## Examples
///
/// ```rust
/// use bollard::grpc::export::ImageExporterOutputBuilder;
/// use std::path::Path;
///
/// ImageExporterOutputBuilder::new("docker.io/library/my-image:latest")
///     .dest(&Path::new("/tmp/oci.tar"));
///
/// ```
///
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ImageExporterOutputBuilder {
    inner: ImageExporterOutput,
}

impl ImageExporterOutputBuilder {
    /// Constructs the builder given an image name, e.g. "docker.io/library/my-image:latest"
    pub fn new(name: &str) -> Self {
        Self {
            inner: ImageExporterOutput {
                name: String::from(name),
                ..Default::default()
            },
        }
    }

    /// Compression type, see [buildkit compression
    /// docs](https://docs.docker.com/build/exporters/#compression)
    pub fn compression(mut self, compression: &ImageBuildOutputCompression) -> Self {
        compression.clone_into(&mut self.inner.compression);
        self
    }

    /// Compression level, see [buildkit compression
    /// docs](https://docs.docker.com/build/exporters/#compression)
    pub fn compression_level(mut self, compression_level: u8) -> Self {
        self.inner.compression_level = Some(compression_level);
        self
    }

    /// Forcefully apply compression, see [buildkit compression
    /// docs](https://docs.docker.com/build/exporters/#compression)
    pub fn force_compression(mut self, force_compression: bool) -> Self {
        self.inner.force_compression = force_compression;
        self
    }

    /// Use OCI media types in exporter manifests. Defaults to `true` for `type=oci`, and `false`
    /// for `type=docker`. See [buildkit OCI media types
    /// docs](https://docs.docker.com/build/exporters/#oci-media-types)
    pub fn oci_mediatypes(mut self, oci_mediatypes: bool) -> Self {
        self.inner.oci_mediatypes = oci_mediatypes;
        self
    }

    /// Attach an annotation with the respective `key` and `value` to the built image, see
    /// [buildkit annotations
    /// docs](https://docs.docker.com/build/exporters/oci-docker/#annotations)
    pub fn annotation(mut self, key: &str, value: &str) -> Self {
        self.inner
            .annotation
            .insert(String::from(key), String::from(value));
        self
    }

    /// Consume this builder to create an [`ImageExporterRequest`] for the
    /// [`crate::grpc::driver::Export::export`] method
    pub fn dest(self, path: &Path) -> ImageExporterRequest {
        ImageExporterRequest {
            output: self.inner,
            path: path.to_owned(),
        }
    }
}
