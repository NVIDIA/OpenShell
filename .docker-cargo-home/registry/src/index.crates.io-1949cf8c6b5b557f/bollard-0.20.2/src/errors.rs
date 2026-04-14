//! Errors for this module.

#[cfg(feature = "ssl_providerless")]
use std::path::PathBuf;

/// Generic Docker errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Error emitted during client instantiation when the `DOCKER_CERT_PATH` environment variable
    /// is invalid.
    #[cfg(feature = "ssl_providerless")]
    #[error("Could not find home directory")]
    NoHomePathError,
    /// Generic error when reading a certificate from the filesystem
    #[cfg(feature = "ssl_providerless")]
    #[error("Cannot open/read certificate with path: {path}")]
    CertPathError {
        /// Path for the failing certificate file
        path: PathBuf,
    },
    /// Error emitted when multiple keys are found in a certificate file
    #[cfg(feature = "ssl_providerless")]
    #[error("Found multiple keys ({count}), expected one: {path}")]
    CertMultipleKeys {
        /// Number of keys found in the certificate file
        count: usize,
        /// Path for the failing certificate file
        path: PathBuf,
    },
    /// Parse error for RSA encrypted keys
    #[cfg(feature = "ssl_providerless")]
    #[error("Could not parse key: {path}")]
    CertParseError {
        /// Path for the failing certificate file
        path: PathBuf,
    },
    /// Error emitted when the client is unable to parse a native pki cert for SSL
    #[cfg(feature = "ssl_providerless")]
    #[error("Could not parse a pki native cert")]
    NoNativeCertsError {
        /// The original error emitted.
        #[from]
        err: rustls::Error,
    },
    /// Error emitted when the client is unable to load native certs for SSL
    #[cfg(feature = "ssl_providerless")]
    #[error("Could not load native certs")]
    LoadNativeCertsErrors {
        /// The original errors emitted.
        errors: Vec<rustls_native_certs::Error>,
    },
    /// Generic error emitted by the docker server.
    #[error("Docker responded with status code {status_code}: {message}")]
    DockerResponseServerError {
        /// Status code returned by the docker server.
        status_code: u16,
        /// Message returned by the docker server.
        message: String,
    },
    /// Error facilitating debugging failed JSON parsing.
    #[error("Failed to deserialize JSON: {message}")]
    JsonDataError {
        /// Short section of the json close to the error.
        message: String,
        /// Entire JSON payload. This field is toggled with the **json_data_content** feature cargo flag.
        #[cfg(feature = "json_data_content")]
        contents: String,
        /// Character sequence at error location.
        column: usize,
    },
    /// Error emitted when the docker is requested to build with buildkit without a session id
    #[error("Failed to parse API version")]
    APIVersionParseError {},
    /// Error emitted when a request times out.
    #[error("Timeout error")]
    RequestTimeoutError,
    /// Error emitted mid-stream as part of a successful docker operation
    #[error("Docker stream error: {error}")]
    DockerStreamError {
        /// error string emitted by the Stream
        error: String,
    },
    /// Error emitted as part of a container wait response
    #[error("Docker container wait error: {error}")]
    DockerContainerWaitError {
        /// error string returned from container wait call
        error: String,
        /// error code returned from container wait call
        code: i64,
    },
    /// Error emitted when a session is not provided to the buildkit engine
    #[error("Buildkit requires a unique session")]
    MissingSessionBuildkitError {},
    /// Error emitted when a session is not provided to the buildkit engine
    #[error("Buildkit requires a builder version set")]
    MissingVersionBuildkitError {},
    /// Error emitted when JSON fails to serialize.
    #[error(transparent)]
    JsonSerdeError {
        /// The original error emitted by serde.
        #[from]
        err: serde_json::Error,
    },
    /// Error emitted when log output generates an I/O error.
    #[error(transparent)]
    StrParseError {
        /// The original error emitted.
        #[from]
        err: std::str::Utf8Error,
    },
    /// Error emitted from an I/O error.
    #[error(transparent)]
    IOError {
        /// The original error emitted.
        #[from]
        err: std::io::Error,
    },
    /// Error emitted from a formatting error.
    #[error(transparent)]
    StrFmtError {
        /// The original error emitted.
        #[from]
        err: std::fmt::Error,
    },
    /// Error emitted from an HTTP error.
    #[error(transparent)]
    HttpClientError {
        /// The original error emitted.
        #[from]
        err: http::Error,
    },
    /// Error emitted from an HTTP error.
    #[error(transparent)]
    HyperResponseError {
        /// The original error emitted.
        #[from]
        err: hyper::Error,
    },
    /// Error emitted when serde fails to urlencod a struct of options
    #[error("Unable to URLEncode: {}", err)]
    URLEncodedError {
        /// The original error emitted.
        #[from]
        err: serde_urlencoded::ser::Error,
    },
    /// Error encountered when parsing a URL
    #[error("Unable to parse URL: {}", err)]
    URLParseError {
        /// The original error emitted.
        #[from]
        err: url::ParseError,
    },
    /// Error emitted when encoding a URI
    #[error("Unable to parse URI: {}", err)]
    InvalidURIError {
        /// The original error emitted.
        #[from]
        err: http::uri::InvalidUri,
    },
    /// Error emitted when encoding a URIParts
    #[error("Unable to parse URIParts: {}", err)]
    InvalidURIPartsError {
        /// The original error emitted.
        #[from]
        err: http::uri::InvalidUriParts,
    },
    /// Error that is never emitted
    #[cfg(any(feature = "http", feature = "ssh", feature = "pipe"))]
    #[error("Error in the hyper legacy client: {}", err)]
    HyperLegacyError {
        /// The original error emitted.
        #[from]
        err: hyper_util::client::legacy::Error,
    },
    /// Error emitted when connecting to a URI with an unsupported scheme
    #[error("URI scheme is not supported: {uri}")]
    UnsupportedURISchemeError {
        /// The URI that was attempted to be connected to
        uri: String,
    },
    /// Error emitted when the Docker socket file is not found at the expected location.
    #[error("Socket not found: {0}")]
    SocketNotFoundError(String),

    /// Error emitted when a WebSocket connection fails.
    #[cfg(feature = "websocket")]
    #[error("WebSocket error: {err}")]
    WebSocketError {
        /// The underlying WebSocket error.
        err: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Error emitted when an expected header is not found in the HTTP response.
    #[error("HTTP header not found: {0}")]
    HttpHeaderNotFoundError(String),

    /// Error encountered when getting a string slice from a HTTP header
    #[error("Str from header failed: {}", err)]
    HttpHeaderToStrError {
        /// The original error emitted.
        #[from]
        err: http::header::ToStrError,
    },

    /// Error emitted when failing to decode a base64 string
    #[error("Base64 decode failed: {}", err)]
    Base64DecodeError {
        /// The original error emitted.
        #[from]
        err: base64::DecodeError,
    },
}
