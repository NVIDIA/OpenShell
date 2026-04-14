//! Method, error and parameter types for the  endpoint.
#![allow(
    clippy::all,
    deprecated
)]

use serde::{Serialize, Deserialize};
use serde_repr::Serialize_repr;

use std::collections::HashMap;
use std::hash::Hash;

pub(crate) fn serialize_as_json<T, S>(t: &T, s: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: serde::Serializer,
{
    s.serialize_str(
        &serde_json::to_string(t).map_err(|e| serde::ser::Error::custom(format!("{e}")))?,
    )
}

pub(crate) fn serialize_join_newlines<S>(t: &[String], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_str(&t.join("\n"))
}

#[cfg(feature = "buildkit")]
/// The exporter to use (see [Docker Docs](https://docs.docker.com/reference/cli/docker/buildx/build/#output))
#[derive(Debug, Clone, PartialEq)]
pub enum ImageBuildOutput
{
    /// The local export type writes all result files to a directory on the client.
    /// The new files will be owned by the current user.
    /// On multi-platform builds, all results will be put in subdirectories by their platform.
    /// It takes the destination directory as a first argument.
    Tar(String),
    /// The tar export type writes all result files as a single tarball on the client.
    /// On multi-platform builds all results will be put in subdirectories by their platform.
    /// It takes the destination directory as a first argument.
    ///
    /// **Notice**: The implementation of the underlying `fsutil` protocol is not complete.
    /// Therefore, special files, permissions, etc. are ignored or not handled correctly.
    Local(String),
}

#[cfg(feature = "buildkit")]
impl Serialize for ImageBuildOutput
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            ImageBuildOutput::Tar(_) => serializer.serialize_str(r#"[{"type": "tar"}]"#),
            ImageBuildOutput::Local(_) => serializer.serialize_str(r#"[{"type": "local"}]"#),
        }
    }
}

/// Builder Version to use
#[derive(Clone, Copy, Debug, PartialEq, Serialize_repr)]
#[repr(u8)]
#[derive(Default)]
pub enum BuilderVersion {
    /// BuilderV1 is the first generation builder in docker daemon
    #[default]
    BuilderV1 = 1,
    /// BuilderBuildKit is builder based on moby/buildkit project
    BuilderBuildKit = 2,
}


/// Builder for the `ConfigList` API query parameter.
///
/// List configs.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::ListConfigsOptionsBuilder;
///
/// let params = ListConfigsOptionsBuilder::new()
/// //  .filters(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ListConfigsOptionsBuilder {
    inner: ListConfigsOptions,
}

impl ListConfigsOptionsBuilder {
    /// Construct a builder of query parameters for ListConfigsOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// A JSON encoded value of the filters (a `map[string][]string`) to
    /// process on the configs list.
    /// 
    /// Available filters:
    /// 
    /// - `id=<config id>`
    /// - `label=<key> or label=<key>=value`
    /// - `name=<config name>`
    /// - `names=<config name>`
    pub fn filters(mut self, filters: &HashMap<impl Into<String> + Clone, Vec<impl Into<String> + Clone>>) -> Self {
        let mut inner_filters = HashMap::new();
        for (key, value) in filters {
            inner_filters.insert(
                Into::<String>::into(key.clone()),
                value
                    .into_iter()
                    .map(|v| Into::<String>::into(v.clone()))
                    .collect(),
            );
        }
        self.inner.filters = Some(inner_filters);
        self
    }

    /// Consume this builder and use the `ListConfigsOptions` as parameter to the
    /// `ConfigList` API
    pub fn build(self) -> ListConfigsOptions {
        self.inner
    }
}

/// Internal struct used in the `ConfigList` API
/// 
/// Use a [ListConfigsOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ListConfigsOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_as_json")]
    pub filters: Option<HashMap<String, Vec<String>>>, 
}

impl Default for ListConfigsOptions
{
    fn default() -> Self {
        Self {
            filters: None,
        }
    }
}

/// Builder for the `ConfigUpdate` API query parameter.
///
/// Update a Config.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::UpdateConfigOptionsBuilder;
///
/// let params = UpdateConfigOptionsBuilder::new()
/// //  .version(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct UpdateConfigOptionsBuilder {
    inner: UpdateConfigOptions,
}

impl UpdateConfigOptionsBuilder {
    /// Construct a builder of query parameters for UpdateConfigOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// The version number of the config object being updated. This is
    /// required to avoid conflicting writes.
    pub fn version(mut self, version: i64) -> Self {
        self.inner.version = version;
        self
    }

    /// Consume this builder and use the `UpdateConfigOptions` as parameter to the
    /// `ConfigUpdate` API
    pub fn build(self) -> UpdateConfigOptions {
        self.inner
    }
}

/// Internal struct used in the `ConfigUpdate` API
/// 
/// Use a [UpdateConfigOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UpdateConfigOptions
{ 
    pub version: i64, 
}

impl Default for UpdateConfigOptions
{
    fn default() -> Self {
        Self {
            version: Default::default(),
        }
    }
}




/// Builder for the `ContainerArchive` API query parameter.
///
/// Get an archive of a filesystem resource in a container.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::DownloadFromContainerOptionsBuilder;
///
/// let params = DownloadFromContainerOptionsBuilder::new()
/// //  .path(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct DownloadFromContainerOptionsBuilder {
    inner: DownloadFromContainerOptions,
}

impl DownloadFromContainerOptionsBuilder {
    /// Construct a builder of query parameters for DownloadFromContainerOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resource in the container’s filesystem to archive.
    pub fn path(mut self, path: &str) -> Self {
        self.inner.path = path.into();
        self
    }

    /// Consume this builder and use the `DownloadFromContainerOptions` as parameter to the
    /// `ContainerArchive` API
    pub fn build(self) -> DownloadFromContainerOptions {
        self.inner
    }
}

/// Internal struct used in the `ContainerArchive` API
/// 
/// Use a [DownloadFromContainerOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DownloadFromContainerOptions
{ 
    pub path: String, 
}

impl Default for DownloadFromContainerOptions
{
    fn default() -> Self {
        Self {
            path: Default::default(),
        }
    }
}

/// Builder for the `ContainerArchiveInfo` API query parameter.
///
/// Get information about files in a container.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::ContainerArchiveInfoOptionsBuilder;
///
/// let params = ContainerArchiveInfoOptionsBuilder::new()
/// //  .path(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ContainerArchiveInfoOptionsBuilder {
    inner: ContainerArchiveInfoOptions,
}

impl ContainerArchiveInfoOptionsBuilder {
    /// Construct a builder of query parameters for ContainerArchiveInfoOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resource in the container’s filesystem to archive.
    pub fn path(mut self, path: &str) -> Self {
        self.inner.path = path.into();
        self
    }

    /// Consume this builder and use the `ContainerArchiveInfoOptions` as parameter to the
    /// `ContainerArchiveInfo` API
    pub fn build(self) -> ContainerArchiveInfoOptions {
        self.inner
    }
}

/// Internal struct used in the `ContainerArchiveInfo` API
/// 
/// Use a [ContainerArchiveInfoOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ContainerArchiveInfoOptions
{ 
    pub path: String, 
}

impl Default for ContainerArchiveInfoOptions
{
    fn default() -> Self {
        Self {
            path: Default::default(),
        }
    }
}

/// Builder for the `ContainerAttach` API query parameter.
///
/// Attach to a container.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::AttachContainerOptionsBuilder;
///
/// let params = AttachContainerOptionsBuilder::new()
/// //  .detach_keys(/* ... */)
/// //  .logs(/* ... */)
/// //  .stream(/* ... */)
/// //  .stdin(/* ... */)
/// //  .stdout(/* ... */)
/// //  .stderr(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AttachContainerOptionsBuilder {
    inner: AttachContainerOptions,
}

impl AttachContainerOptionsBuilder {
    /// Construct a builder of query parameters for AttachContainerOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the key sequence for detaching a container.Format is a single
    /// character `[a-Z]` or `ctrl-<value>` where `<value>` is one of: `a-z`,
    /// `@`, `^`, `[`, `,` or `_`.
    pub fn detach_keys(mut self, detach_keys: &str) -> Self {
        self.inner.detach_keys = Some(detach_keys.into());
        self
    }

    /// Replay previous logs from the container.
    /// 
    /// This is useful for attaching to a container that has started and you
    /// want to output everything since the container started.
    /// 
    /// If `stream` is also enabled, once all the previous output has been
    /// returned, it will seamlessly transition into streaming current
    /// output.
    pub fn logs(mut self, logs: bool) -> Self {
        self.inner.logs = logs;
        self
    }

    /// Stream attached streams from the time the request was made onwards.
    pub fn stream(mut self, stream: bool) -> Self {
        self.inner.stream = stream;
        self
    }

    /// Attach to `stdin`
    pub fn stdin(mut self, stdin: bool) -> Self {
        self.inner.stdin = stdin;
        self
    }

    /// Attach to `stdout`
    pub fn stdout(mut self, stdout: bool) -> Self {
        self.inner.stdout = stdout;
        self
    }

    /// Attach to `stderr`
    pub fn stderr(mut self, stderr: bool) -> Self {
        self.inner.stderr = stderr;
        self
    }

    /// Consume this builder and use the `AttachContainerOptions` as parameter to the
    /// `ContainerAttach` API
    pub fn build(self) -> AttachContainerOptions {
        self.inner
    }
}

/// Internal struct used in the `ContainerAttach` API
/// 
/// Use a [AttachContainerOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AttachContainerOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "detachKeys")]
    pub detach_keys: Option<String>, 
    pub logs: bool, 
    pub stream: bool, 
    pub stdin: bool, 
    pub stdout: bool, 
    pub stderr: bool, 
}

impl Default for AttachContainerOptions
{
    fn default() -> Self {
        Self {
            detach_keys: None,
            logs: false,
            stream: false,
            stdin: false,
            stdout: false,
            stderr: false,
        }
    }
}

/// Builder for the `ContainerAttachWebsocket` API query parameter.
///
/// Attach to a container via a websocket.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::AttachContainerWebsocketOptionsBuilder;
///
/// let params = AttachContainerWebsocketOptionsBuilder::new()
/// //  .detach_keys(/* ... */)
/// //  .logs(/* ... */)
/// //  .stream(/* ... */)
/// //  .stdin(/* ... */)
/// //  .stdout(/* ... */)
/// //  .stderr(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AttachContainerWebsocketOptionsBuilder {
    inner: AttachContainerWebsocketOptions,
}

impl AttachContainerWebsocketOptionsBuilder {
    /// Construct a builder of query parameters for AttachContainerWebsocketOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the key sequence for detaching a container.Format is a single
    /// character `[a-Z]` or `ctrl-<value>` where `<value>` is one of: `a-z`,
    /// `@`, `^`, `[`, `,`, or `_`.
    pub fn detach_keys(mut self, detach_keys: &str) -> Self {
        self.inner.detach_keys = Some(detach_keys.into());
        self
    }

    /// Return logs
    pub fn logs(mut self, logs: bool) -> Self {
        self.inner.logs = logs;
        self
    }

    /// Return stream
    pub fn stream(mut self, stream: bool) -> Self {
        self.inner.stream = stream;
        self
    }

    /// Attach to `stdin`
    pub fn stdin(mut self, stdin: bool) -> Self {
        self.inner.stdin = stdin;
        self
    }

    /// Attach to `stdout`
    pub fn stdout(mut self, stdout: bool) -> Self {
        self.inner.stdout = stdout;
        self
    }

    /// Attach to `stderr`
    pub fn stderr(mut self, stderr: bool) -> Self {
        self.inner.stderr = stderr;
        self
    }

    /// Consume this builder and use the `AttachContainerWebsocketOptions` as parameter to the
    /// `ContainerAttachWebsocket` API
    pub fn build(self) -> AttachContainerWebsocketOptions {
        self.inner
    }
}

/// Internal struct used in the `ContainerAttachWebsocket` API
/// 
/// Use a [AttachContainerWebsocketOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AttachContainerWebsocketOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "detachKeys")]
    pub detach_keys: Option<String>, 
    pub logs: bool, 
    pub stream: bool, 
    pub stdin: bool, 
    pub stdout: bool, 
    pub stderr: bool, 
}

impl Default for AttachContainerWebsocketOptions
{
    fn default() -> Self {
        Self {
            detach_keys: None,
            logs: false,
            stream: false,
            stdin: false,
            stdout: false,
            stderr: false,
        }
    }
}

/// Builder for the `ContainerCreate` API query parameter.
///
/// Create a container.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::CreateContainerOptionsBuilder;
///
/// let params = CreateContainerOptionsBuilder::new()
/// //  .name(/* ... */)
/// //  .platform(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct CreateContainerOptionsBuilder {
    inner: CreateContainerOptions,
}

impl CreateContainerOptionsBuilder {
    /// Construct a builder of query parameters for CreateContainerOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Assign the specified name to the container. Must match
    /// `/?[a-zA-Z0-9][a-zA-Z0-9_.-]+`.
    pub fn name(mut self, name: &str) -> Self {
        self.inner.name = Some(name.into());
        self
    }

    /// Platform in the format `os[/arch[/variant]]` used for image lookup.
    /// 
    /// When specified, the daemon checks if the requested image is present
    /// in the local image cache with the given OS and Architecture, and
    /// otherwise returns a `404` status.
    /// 
    /// If the option is not set, the host's native OS and Architecture are
    /// used to look up the image in the image cache. However, if no platform
    /// is passed and the given image does exist in the local image cache,
    /// but its OS or architecture does not match, the container is created
    /// with the available image, and a warning is added to the `Warnings`
    /// field in the response, for example;
    /// 
    ///     WARNING: The requested image's platform (linux/arm64/v8) does not
    ///              match the detected host platform (linux/amd64) and no
    ///              specific platform was requested
    pub fn platform(mut self, platform: &str) -> Self {
        self.inner.platform = platform.into();
        self
    }

    /// Consume this builder and use the `CreateContainerOptions` as parameter to the
    /// `ContainerCreate` API
    pub fn build(self) -> CreateContainerOptions {
        self.inner
    }
}

/// Internal struct used in the `ContainerCreate` API
/// 
/// Use a [CreateContainerOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CreateContainerOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>, 
    pub platform: String, 
}

impl Default for CreateContainerOptions
{
    fn default() -> Self {
        Self {
            name: None,
            platform: String::from(""),
        }
    }
}

/// Builder for the `ContainerDelete` API query parameter.
///
/// Remove a container.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::RemoveContainerOptionsBuilder;
///
/// let params = RemoveContainerOptionsBuilder::new()
/// //  .v(/* ... */)
/// //  .force(/* ... */)
/// //  .link(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct RemoveContainerOptionsBuilder {
    inner: RemoveContainerOptions,
}

impl RemoveContainerOptionsBuilder {
    /// Construct a builder of query parameters for RemoveContainerOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Remove anonymous volumes associated with the container.
    pub fn v(mut self, v: bool) -> Self {
        self.inner.v = v;
        self
    }

    /// If the container is running, kill it before removing it.
    pub fn force(mut self, force: bool) -> Self {
        self.inner.force = force;
        self
    }

    /// Remove the specified link associated with the container.
    pub fn link(mut self, link: bool) -> Self {
        self.inner.link = link;
        self
    }

    /// Consume this builder and use the `RemoveContainerOptions` as parameter to the
    /// `ContainerDelete` API
    pub fn build(self) -> RemoveContainerOptions {
        self.inner
    }
}

/// Internal struct used in the `ContainerDelete` API
/// 
/// Use a [RemoveContainerOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RemoveContainerOptions
{ 
    pub v: bool, 
    pub force: bool, 
    pub link: bool, 
}

impl Default for RemoveContainerOptions
{
    fn default() -> Self {
        Self {
            v: false,
            force: false,
            link: false,
        }
    }
}

/// Builder for the `ContainerInspect` API query parameter.
///
/// Inspect a container.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::InspectContainerOptionsBuilder;
///
/// let params = InspectContainerOptionsBuilder::new()
/// //  .size(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct InspectContainerOptionsBuilder {
    inner: InspectContainerOptions,
}

impl InspectContainerOptionsBuilder {
    /// Construct a builder of query parameters for InspectContainerOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the size of container as fields `SizeRw` and `SizeRootFs`
    pub fn size(mut self, size: bool) -> Self {
        self.inner.size = size;
        self
    }

    /// Consume this builder and use the `InspectContainerOptions` as parameter to the
    /// `ContainerInspect` API
    pub fn build(self) -> InspectContainerOptions {
        self.inner
    }
}

/// Internal struct used in the `ContainerInspect` API
/// 
/// Use a [InspectContainerOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InspectContainerOptions
{ 
    pub size: bool, 
}

impl Default for InspectContainerOptions
{
    fn default() -> Self {
        Self {
            size: false,
        }
    }
}

/// Builder for the `ContainerKill` API query parameter.
///
/// Kill a container.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::KillContainerOptionsBuilder;
///
/// let params = KillContainerOptionsBuilder::new()
/// //  .signal(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct KillContainerOptionsBuilder {
    inner: KillContainerOptions,
}

impl KillContainerOptionsBuilder {
    /// Construct a builder of query parameters for KillContainerOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Signal to send to the container as an integer or string (e.g. `SIGINT`).
    pub fn signal(mut self, signal: &str) -> Self {
        self.inner.signal = signal.into();
        self
    }

    /// Consume this builder and use the `KillContainerOptions` as parameter to the
    /// `ContainerKill` API
    pub fn build(self) -> KillContainerOptions {
        self.inner
    }
}

/// Internal struct used in the `ContainerKill` API
/// 
/// Use a [KillContainerOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct KillContainerOptions
{ 
    pub signal: String, 
}

impl Default for KillContainerOptions
{
    fn default() -> Self {
        Self {
            signal: String::from("SIGKILL"),
        }
    }
}

/// Builder for the `ContainerList` API query parameter.
///
/// List containers.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::ListContainersOptionsBuilder;
///
/// let params = ListContainersOptionsBuilder::new()
/// //  .all(/* ... */)
/// //  .limit(/* ... */)
/// //  .size(/* ... */)
/// //  .filters(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ListContainersOptionsBuilder {
    inner: ListContainersOptions,
}

impl ListContainersOptionsBuilder {
    /// Construct a builder of query parameters for ListContainersOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return all containers. By default, only running containers are shown.
    pub fn all(mut self, all: bool) -> Self {
        self.inner.all = all;
        self
    }

    /// Return this number of most recently created containers, including
    /// non-running ones.
    pub fn limit(mut self, limit: i32) -> Self {
        self.inner.limit = Some(limit);
        self
    }

    /// Return the size of container as fields `SizeRw` and `SizeRootFs`.
    pub fn size(mut self, size: bool) -> Self {
        self.inner.size = size;
        self
    }

    /// Filters to process on the container list, encoded as JSON (a
    /// `map[string][]string`). For example, `{"status": ["paused"]}` will
    /// only return paused containers.
    /// 
    /// Available filters:
    /// 
    /// - `ancestor`=(`<image-name>[:<tag>]`, `<image id>`, or `<image@digest>`)
    /// - `before`=(`<container id>` or `<container name>`)
    /// - `expose`=(`<port>[/<proto>]`|`<startport-endport>/[<proto>]`)
    /// - `exited=<int>` containers with exit code of `<int>`
    /// - `health`=(`starting`|`healthy`|`unhealthy`|`none`)
    /// - `id=<ID>` a container's ID
    /// - `isolation=`(`default`|`process`|`hyperv`) (Windows daemon only)
    /// - `is-task=`(`true`|`false`)
    /// - `label=key` or `label="key=value"` of a container label
    /// - `name=<name>` a container's name
    /// - `network`=(`<network id>` or `<network name>`)
    /// - `publish`=(`<port>[/<proto>]`|`<startport-endport>/[<proto>]`)
    /// - `since`=(`<container id>` or `<container name>`)
    /// - `status=`(`created`|`restarting`|`running`|`removing`|`paused`|`exited`|`dead`)
    /// - `volume`=(`<volume name>` or `<mount point destination>`)
    pub fn filters(mut self, filters: &HashMap<impl Into<String> + Clone, Vec<impl Into<String> + Clone>>) -> Self {
        let mut inner_filters = HashMap::new();
        for (key, value) in filters {
            inner_filters.insert(
                Into::<String>::into(key.clone()),
                value
                    .into_iter()
                    .map(|v| Into::<String>::into(v.clone()))
                    .collect(),
            );
        }
        self.inner.filters = Some(inner_filters);
        self
    }

    /// Consume this builder and use the `ListContainersOptions` as parameter to the
    /// `ContainerList` API
    pub fn build(self) -> ListContainersOptions {
        self.inner
    }
}

/// Internal struct used in the `ContainerList` API
/// 
/// Use a [ListContainersOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ListContainersOptions
{ 
    pub all: bool, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i32>, 
    pub size: bool, 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_as_json")]
    pub filters: Option<HashMap<String, Vec<String>>>, 
}

impl Default for ListContainersOptions
{
    fn default() -> Self {
        Self {
            all: false,
            limit: None,
            size: false,
            filters: None,
        }
    }
}

/// Builder for the `ContainerLogs` API query parameter.
///
/// Get container logs.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::LogsOptionsBuilder;
///
/// let params = LogsOptionsBuilder::new()
/// //  .follow(/* ... */)
/// //  .stdout(/* ... */)
/// //  .stderr(/* ... */)
/// //  .since(/* ... */)
/// //  .until(/* ... */)
/// //  .timestamps(/* ... */)
/// //  .tail(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct LogsOptionsBuilder {
    inner: LogsOptions,
}

impl LogsOptionsBuilder {
    /// Construct a builder of query parameters for LogsOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Keep connection after returning logs.
    pub fn follow(mut self, follow: bool) -> Self {
        self.inner.follow = follow;
        self
    }

    /// Return logs from `stdout`
    pub fn stdout(mut self, stdout: bool) -> Self {
        self.inner.stdout = stdout;
        self
    }

    /// Return logs from `stderr`
    pub fn stderr(mut self, stderr: bool) -> Self {
        self.inner.stderr = stderr;
        self
    }

    /// Only return logs since this time, as a UNIX timestamp
    pub fn since(mut self, since: i32) -> Self {
        self.inner.since = since;
        self
    }

    /// Only return logs before this time, as a UNIX timestamp
    pub fn until(mut self, until: i32) -> Self {
        self.inner.until = until;
        self
    }

    /// Add timestamps to every log line
    pub fn timestamps(mut self, timestamps: bool) -> Self {
        self.inner.timestamps = timestamps;
        self
    }

    /// Only return this number of log lines from the end of the logs.
    /// Specify as an integer or `all` to output all log lines.
    pub fn tail(mut self, tail: &str) -> Self {
        self.inner.tail = tail.into();
        self
    }

    /// Consume this builder and use the `LogsOptions` as parameter to the
    /// `ContainerLogs` API
    pub fn build(self) -> LogsOptions {
        self.inner
    }
}

/// Internal struct used in the `ContainerLogs` API
/// 
/// Use a [LogsOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LogsOptions
{ 
    pub follow: bool, 
    pub stdout: bool, 
    pub stderr: bool, 
    pub since: i32, 
    pub until: i32, 
    pub timestamps: bool, 
    pub tail: String, 
}

impl Default for LogsOptions
{
    fn default() -> Self {
        Self {
            follow: false,
            stdout: false,
            stderr: false,
            since: 0,
            until: 0,
            timestamps: false,
            tail: String::from("all"),
        }
    }
}

/// Builder for the `ContainerPrune` API query parameter.
///
/// Delete stopped containers.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::PruneContainersOptionsBuilder;
///
/// let params = PruneContainersOptionsBuilder::new()
/// //  .filters(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct PruneContainersOptionsBuilder {
    inner: PruneContainersOptions,
}

impl PruneContainersOptionsBuilder {
    /// Construct a builder of query parameters for PruneContainersOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters to process on the prune list, encoded as JSON (a `map[string][]string`).
    /// 
    /// Available filters:
    /// - `until=<timestamp>` Prune containers created before this timestamp. The `<timestamp>` can be Unix timestamps, date formatted timestamps, or Go duration strings (e.g. `10m`, `1h30m`) computed relative to the daemon machine’s time.
    /// - `label` (`label=<key>`, `label=<key>=<value>`, `label!=<key>`, or `label!=<key>=<value>`) Prune containers with (or without, in case `label!=...` is used) the specified labels.
    pub fn filters(mut self, filters: &HashMap<impl Into<String> + Clone, Vec<impl Into<String> + Clone>>) -> Self {
        let mut inner_filters = HashMap::new();
        for (key, value) in filters {
            inner_filters.insert(
                Into::<String>::into(key.clone()),
                value
                    .into_iter()
                    .map(|v| Into::<String>::into(v.clone()))
                    .collect(),
            );
        }
        self.inner.filters = Some(inner_filters);
        self
    }

    /// Consume this builder and use the `PruneContainersOptions` as parameter to the
    /// `ContainerPrune` API
    pub fn build(self) -> PruneContainersOptions {
        self.inner
    }
}

/// Internal struct used in the `ContainerPrune` API
/// 
/// Use a [PruneContainersOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PruneContainersOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_as_json")]
    pub filters: Option<HashMap<String, Vec<String>>>, 
}

impl Default for PruneContainersOptions
{
    fn default() -> Self {
        Self {
            filters: None,
        }
    }
}

/// Builder for the `ContainerRename` API query parameter.
///
/// Rename a container.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::RenameContainerOptionsBuilder;
///
/// let params = RenameContainerOptionsBuilder::new()
/// //  .name(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct RenameContainerOptionsBuilder {
    inner: RenameContainerOptions,
}

impl RenameContainerOptionsBuilder {
    /// Construct a builder of query parameters for RenameContainerOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// New name for the container
    pub fn name(mut self, name: &str) -> Self {
        self.inner.name = name.into();
        self
    }

    /// Consume this builder and use the `RenameContainerOptions` as parameter to the
    /// `ContainerRename` API
    pub fn build(self) -> RenameContainerOptions {
        self.inner
    }
}

/// Internal struct used in the `ContainerRename` API
/// 
/// Use a [RenameContainerOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RenameContainerOptions
{ 
    pub name: String, 
}

impl Default for RenameContainerOptions
{
    fn default() -> Self {
        Self {
            name: Default::default(),
        }
    }
}

/// Builder for the `ContainerResize` API query parameter.
///
/// Resize a container TTY.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::ResizeContainerTTYOptionsBuilder;
///
/// let params = ResizeContainerTTYOptionsBuilder::new()
/// //  .h(/* ... */)
/// //  .w(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ResizeContainerTTYOptionsBuilder {
    inner: ResizeContainerTTYOptions,
}

impl ResizeContainerTTYOptionsBuilder {
    /// Construct a builder of query parameters for ResizeContainerTTYOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Height of the TTY session in characters
    pub fn h(mut self, h: i32) -> Self {
        self.inner.h = h;
        self
    }

    /// Width of the TTY session in characters
    pub fn w(mut self, w: i32) -> Self {
        self.inner.w = w;
        self
    }

    /// Consume this builder and use the `ResizeContainerTTYOptions` as parameter to the
    /// `ContainerResize` API
    pub fn build(self) -> ResizeContainerTTYOptions {
        self.inner
    }
}

/// Internal struct used in the `ContainerResize` API
/// 
/// Use a [ResizeContainerTTYOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResizeContainerTTYOptions
{ 
    pub h: i32, 
    pub w: i32, 
}

impl Default for ResizeContainerTTYOptions
{
    fn default() -> Self {
        Self {
            h: Default::default(),
            w: Default::default(),
        }
    }
}

/// Builder for the `ContainerRestart` API query parameter.
///
/// Restart a container.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::RestartContainerOptionsBuilder;
///
/// let params = RestartContainerOptionsBuilder::new()
/// //  .signal(/* ... */)
/// //  .t(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct RestartContainerOptionsBuilder {
    inner: RestartContainerOptions,
}

impl RestartContainerOptionsBuilder {
    /// Construct a builder of query parameters for RestartContainerOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Signal to send to the container as an integer or string (e.g. `SIGINT`).
    pub fn signal(mut self, signal: &str) -> Self {
        self.inner.signal = Some(signal.into());
        self
    }

    /// Number of seconds to wait before killing the container
    pub fn t(mut self, t: i32) -> Self {
        self.inner.t = Some(t);
        self
    }

    /// Consume this builder and use the `RestartContainerOptions` as parameter to the
    /// `ContainerRestart` API
    pub fn build(self) -> RestartContainerOptions {
        self.inner
    }
}

/// Internal struct used in the `ContainerRestart` API
/// 
/// Use a [RestartContainerOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RestartContainerOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t: Option<i32>, 
}

impl Default for RestartContainerOptions
{
    fn default() -> Self {
        Self {
            signal: None,
            t: None,
        }
    }
}

/// Builder for the `ContainerStart` API query parameter.
///
/// Start a container.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::StartContainerOptionsBuilder;
///
/// let params = StartContainerOptionsBuilder::new()
/// //  .detach_keys(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct StartContainerOptionsBuilder {
    inner: StartContainerOptions,
}

impl StartContainerOptionsBuilder {
    /// Construct a builder of query parameters for StartContainerOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the key sequence for detaching a container. Format is a
    /// single character `[a-Z]` or `ctrl-<value>` where `<value>` is one
    /// of: `a-z`, `@`, `^`, `[`, `,` or `_`.
    pub fn detach_keys(mut self, detach_keys: &str) -> Self {
        self.inner.detach_keys = Some(detach_keys.into());
        self
    }

    /// Consume this builder and use the `StartContainerOptions` as parameter to the
    /// `ContainerStart` API
    pub fn build(self) -> StartContainerOptions {
        self.inner
    }
}

/// Internal struct used in the `ContainerStart` API
/// 
/// Use a [StartContainerOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StartContainerOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "detachKeys")]
    pub detach_keys: Option<String>, 
}

impl Default for StartContainerOptions
{
    fn default() -> Self {
        Self {
            detach_keys: None,
        }
    }
}

/// Builder for the `ContainerStats` API query parameter.
///
/// Get container stats based on resource usage.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::StatsOptionsBuilder;
///
/// let params = StatsOptionsBuilder::new()
/// //  .stream(/* ... */)
/// //  .one_shot(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct StatsOptionsBuilder {
    inner: StatsOptions,
}

impl StatsOptionsBuilder {
    /// Construct a builder of query parameters for StatsOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stream the output. If false, the stats will be output once and then
    /// it will disconnect.
    pub fn stream(mut self, stream: bool) -> Self {
        self.inner.stream = stream;
        self
    }

    /// Only get a single stat instead of waiting for 2 cycles. Must be used
    /// with `stream=false`.
    pub fn one_shot(mut self, one_shot: bool) -> Self {
        self.inner.one_shot = one_shot;
        self
    }

    /// Consume this builder and use the `StatsOptions` as parameter to the
    /// `ContainerStats` API
    pub fn build(self) -> StatsOptions {
        self.inner
    }
}

/// Internal struct used in the `ContainerStats` API
/// 
/// Use a [StatsOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StatsOptions
{ 
    pub stream: bool, 
    #[serde(rename = "one-shot")]
    pub one_shot: bool, 
}

impl Default for StatsOptions
{
    fn default() -> Self {
        Self {
            stream: true,
            one_shot: false,
        }
    }
}

/// Builder for the `ContainerStop` API query parameter.
///
/// Stop a container.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::StopContainerOptionsBuilder;
///
/// let params = StopContainerOptionsBuilder::new()
/// //  .signal(/* ... */)
/// //  .t(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct StopContainerOptionsBuilder {
    inner: StopContainerOptions,
}

impl StopContainerOptionsBuilder {
    /// Construct a builder of query parameters for StopContainerOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Signal to send to the container as an integer or string (e.g. `SIGINT`).
    pub fn signal(mut self, signal: &str) -> Self {
        self.inner.signal = Some(signal.into());
        self
    }

    /// Number of seconds to wait before killing the container
    pub fn t(mut self, t: i32) -> Self {
        self.inner.t = Some(t);
        self
    }

    /// Consume this builder and use the `StopContainerOptions` as parameter to the
    /// `ContainerStop` API
    pub fn build(self) -> StopContainerOptions {
        self.inner
    }
}

/// Internal struct used in the `ContainerStop` API
/// 
/// Use a [StopContainerOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StopContainerOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t: Option<i32>, 
}

impl Default for StopContainerOptions
{
    fn default() -> Self {
        Self {
            signal: None,
            t: None,
        }
    }
}

/// Builder for the `ContainerTop` API query parameter.
///
/// List processes running inside a container.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::TopOptionsBuilder;
///
/// let params = TopOptionsBuilder::new()
/// //  .ps_args(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct TopOptionsBuilder {
    inner: TopOptions,
}

impl TopOptionsBuilder {
    /// Construct a builder of query parameters for TopOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// The arguments to pass to `ps`. For example, `aux`
    pub fn ps_args(mut self, ps_args: &str) -> Self {
        self.inner.ps_args = ps_args.into();
        self
    }

    /// Consume this builder and use the `TopOptions` as parameter to the
    /// `ContainerTop` API
    pub fn build(self) -> TopOptions {
        self.inner
    }
}

/// Internal struct used in the `ContainerTop` API
/// 
/// Use a [TopOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TopOptions
{ 
    pub ps_args: String, 
}

impl Default for TopOptions
{
    fn default() -> Self {
        Self {
            ps_args: String::from("-ef"),
        }
    }
}

/// Builder for the `ContainerWait` API query parameter.
///
/// Wait for a container.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::WaitContainerOptionsBuilder;
///
/// let params = WaitContainerOptionsBuilder::new()
/// //  .condition(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct WaitContainerOptionsBuilder {
    inner: WaitContainerOptions,
}

impl WaitContainerOptionsBuilder {
    /// Construct a builder of query parameters for WaitContainerOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Wait until a container state reaches the given condition.
    /// 
    /// Defaults to `not-running` if omitted or empty.
    pub fn condition(mut self, condition: &str) -> Self {
        self.inner.condition = condition.into();
        self
    }

    /// Consume this builder and use the `WaitContainerOptions` as parameter to the
    /// `ContainerWait` API
    pub fn build(self) -> WaitContainerOptions {
        self.inner
    }
}

/// Internal struct used in the `ContainerWait` API
/// 
/// Use a [WaitContainerOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WaitContainerOptions
{ 
    pub condition: String, 
}

impl Default for WaitContainerOptions
{
    fn default() -> Self {
        Self {
            condition: String::from("not-running"),
        }
    }
}

/// Builder for the `PutContainerArchive` API query parameter.
///
/// Extract an archive of files or folders to a directory in a container.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::UploadToContainerOptionsBuilder;
///
/// let params = UploadToContainerOptionsBuilder::new()
/// //  .path(/* ... */)
/// //  .no_overwrite_dir_non_dir(/* ... */)
/// //  .copy_uidgid(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct UploadToContainerOptionsBuilder {
    inner: UploadToContainerOptions,
}

impl UploadToContainerOptionsBuilder {
    /// Construct a builder of query parameters for UploadToContainerOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Path to a directory in the container to extract the archive’s contents into. 
    pub fn path(mut self, path: &str) -> Self {
        self.inner.path = path.into();
        self
    }

    /// If `1`, `true`, or `True` then it will be an error if unpacking the
    /// given content would cause an existing directory to be replaced with
    /// a non-directory and vice versa.
    pub fn no_overwrite_dir_non_dir(mut self, no_overwrite_dir_non_dir: &str) -> Self {
        self.inner.no_overwrite_dir_non_dir = Some(no_overwrite_dir_non_dir.into());
        self
    }

    /// If `1`, `true`, then it will copy UID/GID maps to the dest file or
    /// dir
    pub fn copy_uidgid(mut self, copy_uidgid: &str) -> Self {
        self.inner.copy_uidgid = Some(copy_uidgid.into());
        self
    }

    /// Consume this builder and use the `UploadToContainerOptions` as parameter to the
    /// `PutContainerArchive` API
    pub fn build(self) -> UploadToContainerOptions {
        self.inner
    }
}

/// Internal struct used in the `PutContainerArchive` API
/// 
/// Use a [UploadToContainerOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UploadToContainerOptions
{ 
    pub path: String, 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "noOverwriteDirNonDir")]
    pub no_overwrite_dir_non_dir: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "copyUIDGID")]
    pub copy_uidgid: Option<String>, 
}

impl Default for UploadToContainerOptions
{
    fn default() -> Self {
        Self {
            path: Default::default(),
            no_overwrite_dir_non_dir: None,
            copy_uidgid: None,
        }
    }
}







/// Builder for the `ExecResize` API query parameter.
///
/// Resize an exec instance.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::ResizeExecOptionsBuilder;
///
/// let params = ResizeExecOptionsBuilder::new()
/// //  .h(/* ... */)
/// //  .w(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ResizeExecOptionsBuilder {
    inner: ResizeExecOptions,
}

impl ResizeExecOptionsBuilder {
    /// Construct a builder of query parameters for ResizeExecOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Height of the TTY session in characters
    pub fn h(mut self, h: i32) -> Self {
        self.inner.h = h;
        self
    }

    /// Width of the TTY session in characters
    pub fn w(mut self, w: i32) -> Self {
        self.inner.w = w;
        self
    }

    /// Consume this builder and use the `ResizeExecOptions` as parameter to the
    /// `ExecResize` API
    pub fn build(self) -> ResizeExecOptions {
        self.inner
    }
}

/// Internal struct used in the `ExecResize` API
/// 
/// Use a [ResizeExecOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResizeExecOptions
{ 
    pub h: i32, 
    pub w: i32, 
}

impl Default for ResizeExecOptions
{
    fn default() -> Self {
        Self {
            h: Default::default(),
            w: Default::default(),
        }
    }
}




/// Builder for the `BuildPrune` API query parameter.
///
/// Delete builder cache.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::PruneBuildOptionsBuilder;
///
/// let params = PruneBuildOptionsBuilder::new()
/// //  .reserved_space(/* ... */)
/// //  .max_used_space(/* ... */)
/// //  .min_free_space(/* ... */)
/// //  .all(/* ... */)
/// //  .filters(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct PruneBuildOptionsBuilder {
    inner: PruneBuildOptions,
}

impl PruneBuildOptionsBuilder {
    /// Construct a builder of query parameters for PruneBuildOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Amount of disk space in bytes to keep for cache
    pub fn reserved_space(mut self, reserved_space: i64) -> Self {
        self.inner.reserved_space = Some(reserved_space);
        self
    }

    /// Maximum amount of disk space allowed to keep for cache
    pub fn max_used_space(mut self, max_used_space: i64) -> Self {
        self.inner.max_used_space = Some(max_used_space);
        self
    }

    /// Target amount of free disk space after pruning
    pub fn min_free_space(mut self, min_free_space: i64) -> Self {
        self.inner.min_free_space = Some(min_free_space);
        self
    }

    /// Remove all types of build cache
    pub fn all(mut self, all: bool) -> Self {
        self.inner.all = Some(all);
        self
    }

    /// A JSON encoded value of the filters (a `map[string][]string`) to
    /// process on the list of build cache objects.
    /// 
    /// Available filters:
    /// 
    /// - `until=<timestamp>` remove cache older than `<timestamp>`. The `<timestamp>` can be Unix timestamps, date formatted timestamps, or Go duration strings (e.g. `10m`, `1h30m`) computed relative to the daemon's local time.
    /// - `id=<id>`
    /// - `parent=<id>`
    /// - `type=<string>`
    /// - `description=<string>`
    /// - `inuse`
    /// - `shared`
    /// - `private`
    pub fn filters(mut self, filters: &HashMap<impl Into<String> + Clone, Vec<impl Into<String> + Clone>>) -> Self {
        let mut inner_filters = HashMap::new();
        for (key, value) in filters {
            inner_filters.insert(
                Into::<String>::into(key.clone()),
                value
                    .into_iter()
                    .map(|v| Into::<String>::into(v.clone()))
                    .collect(),
            );
        }
        self.inner.filters = Some(inner_filters);
        self
    }

    /// Consume this builder and use the `PruneBuildOptions` as parameter to the
    /// `BuildPrune` API
    pub fn build(self) -> PruneBuildOptions {
        self.inner
    }
}

/// Internal struct used in the `BuildPrune` API
/// 
/// Use a [PruneBuildOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PruneBuildOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "reserved-space")]
    pub reserved_space: Option<i64>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "max-used-space")]
    pub max_used_space: Option<i64>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "min-free-space")]
    pub min_free_space: Option<i64>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub all: Option<bool>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_as_json")]
    pub filters: Option<HashMap<String, Vec<String>>>, 
}

impl Default for PruneBuildOptions
{
    fn default() -> Self {
        Self {
            reserved_space: None,
            max_used_space: None,
            min_free_space: None,
            all: None,
            filters: None,
        }
    }
}

/// Builder for the `ImageBuild` API query parameter.
///
/// Build an image.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::BuildImageOptionsBuilder;
///
/// let params = BuildImageOptionsBuilder::new()
/// //  .dockerfile(/* ... */)
/// //  .t(/* ... */)
/// //  .extrahosts(/* ... */)
/// //  .remote(/* ... */)
/// //  .q(/* ... */)
/// //  .nocache(/* ... */)
/// //  .cachefrom(/* ... */)
/// //  .pull(/* ... */)
/// //  .rm(/* ... */)
/// //  .forcerm(/* ... */)
/// //  .memory(/* ... */)
/// //  .memswap(/* ... */)
/// //  .cpushares(/* ... */)
/// //  .cpusetcpus(/* ... */)
/// //  .cpuperiod(/* ... */)
/// //  .cpuquota(/* ... */)
/// //  .buildargs(/* ... */)
/// //  .shmsize(/* ... */)
/// //  .squash(/* ... */)
/// //  .labels(/* ... */)
/// //  .networkmode(/* ... */)
/// //  .platform(/* ... */)
/// //  .target(/* ... */)
/// //  .outputs(/* ... */)
/// //  .version(/* ... */)
/// //  .session(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct BuildImageOptionsBuilder {
    inner: BuildImageOptions,
}

impl BuildImageOptionsBuilder {
    /// Construct a builder of query parameters for BuildImageOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Path within the build context to the `Dockerfile`. This is ignored if `remote` is specified and points to an external `Dockerfile`.
    pub fn dockerfile(mut self, dockerfile: &str) -> Self {
        self.inner.dockerfile = dockerfile.into();
        self
    }

    /// A name and optional tag to apply to the image in the `name:tag` format. If you omit the tag the default `latest` value is assumed. You can provide several `t` parameters.
    pub fn t(mut self, t: &str) -> Self {
        self.inner.t = Some(t.into());
        self
    }

    /// Extra hosts to add to /etc/hosts
    pub fn extrahosts(mut self, extrahosts: &str) -> Self {
        self.inner.extrahosts = Some(extrahosts.into());
        self
    }

    /// A Git repository URI or HTTP/HTTPS context URI. If the URI points to a single text file, the file’s contents are placed into a file called `Dockerfile` and the image is built from that file. If the URI points to a tarball, the file is downloaded by the daemon and the contents therein used as the context for the build. If the URI points to a tarball and the `dockerfile` parameter is also specified, there must be a file with the corresponding path inside the tarball.
    pub fn remote(mut self, remote: &str) -> Self {
        self.inner.remote = Some(remote.into());
        self
    }

    /// Suppress verbose build output.
    pub fn q(mut self, q: bool) -> Self {
        self.inner.q = q;
        self
    }

    /// Do not use the cache when building the image.
    pub fn nocache(mut self, nocache: bool) -> Self {
        self.inner.nocache = nocache;
        self
    }

    /// JSON array of images used for build cache resolution.
    pub fn cachefrom(mut self, cachefrom: &Vec<impl Into<String> + Clone>) -> Self {
        self.inner.cachefrom = Some(cachefrom
            .into_iter()
            .map(|v| Into::<String>::into(v.clone()))
            .collect());
        self
    }

    /// Attempt to pull the image even if an older image exists locally.
    pub fn pull(mut self, pull: &str) -> Self {
        self.inner.pull = Some(pull.into());
        self
    }

    /// Remove intermediate containers after a successful build.
    pub fn rm(mut self, rm: bool) -> Self {
        self.inner.rm = rm;
        self
    }

    /// Always remove intermediate containers, even upon failure.
    pub fn forcerm(mut self, forcerm: bool) -> Self {
        self.inner.forcerm = forcerm;
        self
    }

    /// Set memory limit for build.
    pub fn memory(mut self, memory: i32) -> Self {
        self.inner.memory = Some(memory);
        self
    }

    /// Total memory (memory + swap). Set as `-1` to disable swap.
    pub fn memswap(mut self, memswap: i32) -> Self {
        self.inner.memswap = Some(memswap);
        self
    }

    /// CPU shares (relative weight).
    pub fn cpushares(mut self, cpushares: i32) -> Self {
        self.inner.cpushares = Some(cpushares);
        self
    }

    /// CPUs in which to allow execution (e.g., `0-3`, `0,1`).
    pub fn cpusetcpus(mut self, cpusetcpus: &str) -> Self {
        self.inner.cpusetcpus = Some(cpusetcpus.into());
        self
    }

    /// The length of a CPU period in microseconds.
    pub fn cpuperiod(mut self, cpuperiod: i32) -> Self {
        self.inner.cpuperiod = Some(cpuperiod);
        self
    }

    /// Microseconds of CPU time that the container can get in a CPU period.
    pub fn cpuquota(mut self, cpuquota: i32) -> Self {
        self.inner.cpuquota = Some(cpuquota);
        self
    }

    /// JSON map of string pairs for build-time variables. Users pass these values at build-time. Docker uses the buildargs as the environment context for commands run via the `Dockerfile` RUN instruction, or for variable expansion in other `Dockerfile` instructions. This is not meant for passing secret values.
    /// 
    /// For example, the build arg `FOO=bar` would become `{"FOO":"bar"}` in JSON. This would result in the query parameter `buildargs={"FOO":"bar"}`. Note that `{"FOO":"bar"}` should be URI component encoded.
    /// 
    /// [Read more about the buildargs instruction.](https://docs.docker.com/engine/reference/builder/#arg)
    pub fn buildargs(mut self, buildargs: &HashMap<impl Into<String> + Clone, impl Into<String> + Clone>) -> Self {
        let mut inner_buildargs = HashMap::new();
        for (key, value) in buildargs {
            inner_buildargs.insert(
                Into::<String>::into(key.clone()),
                Into::<String>::into(value.clone()),
            );
        }
        self.inner.buildargs = Some(inner_buildargs);
        self
    }

    /// Size of `/dev/shm` in bytes. The size must be greater than 0. If omitted the system uses 64MB.
    pub fn shmsize(mut self, shmsize: i32) -> Self {
        self.inner.shmsize = Some(shmsize);
        self
    }

    /// Squash the resulting images layers into a single layer. *(Experimental release only.)*
    pub fn squash(mut self, squash: bool) -> Self {
        self.inner.squash = Some(squash);
        self
    }

    /// Arbitrary key/value labels to set on the image, as a JSON map of string pairs.
    pub fn labels(mut self, labels: &HashMap<impl Into<String> + Clone, impl Into<String> + Clone>) -> Self {
        let mut inner_labels = HashMap::new();
        for (key, value) in labels {
            inner_labels.insert(
                Into::<String>::into(key.clone()),
                Into::<String>::into(value.clone()),
            );
        }
        self.inner.labels = Some(inner_labels);
        self
    }

    /// Sets the networking mode for the run commands during build. Supported
    /// standard values are: `bridge`, `host`, `none`, and `container:<name|id>`.
    /// Any other value is taken as a custom network's name or ID to which this
    /// container should connect to.
    pub fn networkmode(mut self, networkmode: &str) -> Self {
        self.inner.networkmode = Some(networkmode.into());
        self
    }

    /// Platform in the format os[/arch[/variant]]
    pub fn platform(mut self, platform: &str) -> Self {
        self.inner.platform = platform.into();
        self
    }

    /// Target build stage
    pub fn target(mut self, target: &str) -> Self {
        self.inner.target = target.into();
        self
    }

    /// BuildKit output configuration in the format of a stringified JSON array of objects.
    /// Each object must have two top-level properties: `Type` and `Attrs`.
    /// The `Type` property must be set to 'moby'.
    /// The `Attrs` property is a map of attributes for the BuildKit output configuration.
    /// See https://docs.docker.com/build/exporters/oci-docker/ for more information.
    /// 
    /// Example:
    /// 
    /// ```
    /// [{"Type":"moby","Attrs":{"type":"image","force-compression":"true","compression":"zstd"}}]
    /// ```
    #[cfg(feature = "buildkit")]
    pub fn outputs(mut self, outputs: ImageBuildOutput) -> Self {
        self.inner.outputs = Some(outputs);
        self
    }

    /// Version of the builder backend to use.
    /// 
    /// - `1` is the first generation classic (deprecated) builder in the Docker daemon (default)
    /// - `2` is [BuildKit](https://github.com/moby/buildkit)
    pub fn version(mut self, version: BuilderVersion) -> Self {
        self.inner.version = version;
        self
    }

    /// Session ID used to communicate with Docker's internal buildkit engine
    #[cfg(feature = "buildkit")]
    pub fn session(mut self, session: &str) -> Self {
        self.inner.session = Some(session.into());
        self
    }

    /// Consume this builder and use the `BuildImageOptions` as parameter to the
    /// `ImageBuild` API
    pub fn build(self) -> BuildImageOptions {
        self.inner
    }
}

/// Internal struct used in the `ImageBuild` API
/// 
/// Use a [BuildImageOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BuildImageOptions
{ 
    pub dockerfile: String, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extrahosts: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>, 
    pub q: bool, 
    pub nocache: bool, 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_as_json")]
    pub cachefrom: Option<Vec<String>>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pull: Option<String>, 
    pub rm: bool, 
    pub forcerm: bool, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<i32>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memswap: Option<i32>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpushares: Option<i32>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpusetcpus: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuperiod: Option<i32>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuquota: Option<i32>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_as_json")]
    pub buildargs: Option<HashMap<String, String>>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shmsize: Option<i32>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub squash: Option<bool>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_as_json")]
    pub labels: Option<HashMap<String, String>>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub networkmode: Option<String>, 
    pub platform: String, 
    pub target: String, 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg(feature = "buildkit")]
    pub outputs: Option<ImageBuildOutput>, 
    pub version: BuilderVersion, 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg(feature = "buildkit")]
    pub session: Option<String>, 
}

impl Default for BuildImageOptions
{
    fn default() -> Self {
        Self {
            dockerfile: String::from("Dockerfile"),
            t: None,
            extrahosts: None,
            remote: None,
            q: false,
            nocache: false,
            cachefrom: None,
            pull: None,
            rm: true,
            forcerm: false,
            memory: None,
            memswap: None,
            cpushares: None,
            cpusetcpus: None,
            cpuperiod: None,
            cpuquota: None,
            buildargs: None,
            shmsize: None,
            squash: None,
            labels: None,
            networkmode: None,
            platform: String::from(""),
            target: String::from(""),
            #[cfg(feature = "buildkit")]
            outputs: None,
            version: Default::default(),
            #[cfg(feature = "buildkit")]
            session: None,
        }
    }
}

/// Builder for the `ImageCommit` API query parameter.
///
/// Create a new image from a container.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::CommitContainerOptionsBuilder;
///
/// let params = CommitContainerOptionsBuilder::new()
/// //  .container(/* ... */)
/// //  .repo(/* ... */)
/// //  .tag(/* ... */)
/// //  .comment(/* ... */)
/// //  .author(/* ... */)
/// //  .pause(/* ... */)
/// //  .changes(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct CommitContainerOptionsBuilder {
    inner: CommitContainerOptions,
}

impl CommitContainerOptionsBuilder {
    /// Construct a builder of query parameters for CommitContainerOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// The ID or name of the container to commit
    pub fn container(mut self, container: &str) -> Self {
        self.inner.container = Some(container.into());
        self
    }

    /// Repository name for the created image
    pub fn repo(mut self, repo: &str) -> Self {
        self.inner.repo = Some(repo.into());
        self
    }

    /// Tag name for the create image
    pub fn tag(mut self, tag: &str) -> Self {
        self.inner.tag = Some(tag.into());
        self
    }

    /// Commit message
    pub fn comment(mut self, comment: &str) -> Self {
        self.inner.comment = Some(comment.into());
        self
    }

    /// Author of the image (e.g., `John Hannibal Smith <hannibal@a-team.com>`)
    pub fn author(mut self, author: &str) -> Self {
        self.inner.author = Some(author.into());
        self
    }

    /// Whether to pause the container before committing
    pub fn pause(mut self, pause: bool) -> Self {
        self.inner.pause = pause;
        self
    }

    /// `Dockerfile` instructions to apply while committing
    pub fn changes(mut self, changes: &str) -> Self {
        self.inner.changes = Some(changes.into());
        self
    }

    /// Consume this builder and use the `CommitContainerOptions` as parameter to the
    /// `ImageCommit` API
    pub fn build(self) -> CommitContainerOptions {
        self.inner
    }
}

/// Internal struct used in the `ImageCommit` API
/// 
/// Use a [CommitContainerOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CommitContainerOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>, 
    pub pause: bool, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changes: Option<String>, 
}

impl Default for CommitContainerOptions
{
    fn default() -> Self {
        Self {
            container: None,
            repo: None,
            tag: None,
            comment: None,
            author: None,
            pause: true,
            changes: None,
        }
    }
}

/// Builder for the `ImageCreate` API query parameter.
///
/// Create an image.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::CreateImageOptionsBuilder;
///
/// let params = CreateImageOptionsBuilder::new()
/// //  .from_image(/* ... */)
/// //  .from_src(/* ... */)
/// //  .repo(/* ... */)
/// //  .tag(/* ... */)
/// //  .message(/* ... */)
/// //  .changes(/* ... */)
/// //  .platform(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct CreateImageOptionsBuilder {
    inner: CreateImageOptions,
}

impl CreateImageOptionsBuilder {
    /// Construct a builder of query parameters for CreateImageOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Name of the image to pull. If the name includes a tag or digest, specific behavior applies:
    /// 
    /// - If only `fromImage` includes a tag, that tag is used.
    /// - If both `fromImage` and `tag` are provided, `tag` takes precedence.
    /// - If `fromImage` includes a digest, the image is pulled by digest, and `tag` is ignored.
    /// - If neither a tag nor digest is specified, all tags are pulled.
    pub fn from_image(mut self, from_image: &str) -> Self {
        self.inner.from_image = Some(from_image.into());
        self
    }

    /// Source to import. The value may be a URL from which the image can be retrieved or `-` to read the image from the request body. This parameter may only be used when importing an image.
    pub fn from_src(mut self, from_src: &str) -> Self {
        self.inner.from_src = Some(from_src.into());
        self
    }

    /// Repository name given to an image when it is imported. The repo may include a tag. This parameter may only be used when importing an image.
    pub fn repo(mut self, repo: &str) -> Self {
        self.inner.repo = Some(repo.into());
        self
    }

    /// Tag or digest. If empty when pulling an image, this causes all tags for the given image to be pulled.
    pub fn tag(mut self, tag: &str) -> Self {
        self.inner.tag = Some(tag.into());
        self
    }

    /// Set commit message for imported image.
    pub fn message(mut self, message: &str) -> Self {
        self.inner.message = Some(message.into());
        self
    }

    /// Apply `Dockerfile` instructions to the image that is created,
    /// for example: `changes=ENV DEBUG=true`.
    /// Note that `ENV DEBUG=true` should be URI component encoded.
    /// 
    /// Supported `Dockerfile` instructions:
    /// `CMD`|`ENTRYPOINT`|`ENV`|`EXPOSE`|`ONBUILD`|`USER`|`VOLUME`|`WORKDIR`
    pub fn changes(mut self, changes: Vec<String>) -> Self {
        self.inner.changes = changes
            .into_iter()
            .map(|v| Into::<String>::into(v.clone()))
            .collect();
        self
    }

    /// Platform in the format os[/arch[/variant]].
    /// 
    /// When used in combination with the `fromImage` option, the daemon checks
    /// if the given image is present in the local image cache with the given
    /// OS and Architecture, and otherwise attempts to pull the image. If the
    /// option is not set, the host's native OS and Architecture are used.
    /// If the given image does not exist in the local image cache, the daemon
    /// attempts to pull the image with the host's native OS and Architecture.
    /// If the given image does exists in the local image cache, but its OS or
    /// architecture does not match, a warning is produced.
    /// 
    /// When used with the `fromSrc` option to import an image from an archive,
    /// this option sets the platform information for the imported image. If
    /// the option is not set, the host's native OS and Architecture are used
    /// for the imported image.
    pub fn platform(mut self, platform: &str) -> Self {
        self.inner.platform = platform.into();
        self
    }

    /// Consume this builder and use the `CreateImageOptions` as parameter to the
    /// `ImageCreate` API
    pub fn build(self) -> CreateImageOptions {
        self.inner
    }
}

/// Internal struct used in the `ImageCreate` API
/// 
/// Use a [CreateImageOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CreateImageOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "fromImage")]
    pub from_image: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "fromSrc")]
    pub from_src: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>, 
    #[serde(serialize_with = "serialize_join_newlines", skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<String>, 
    pub platform: String, 
}

impl Default for CreateImageOptions
{
    fn default() -> Self {
        Self {
            from_image: None,
            from_src: None,
            repo: None,
            tag: None,
            message: None,
            changes: Default::default(),
            platform: String::from(""),
        }
    }
}

/// Builder for the `ImageDelete` API query parameter.
///
/// Remove an image.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::RemoveImageOptionsBuilder;
///
/// let params = RemoveImageOptionsBuilder::new()
/// //  .force(/* ... */)
/// //  .noprune(/* ... */)
/// //  .platforms(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct RemoveImageOptionsBuilder {
    inner: RemoveImageOptions,
}

impl RemoveImageOptionsBuilder {
    /// Construct a builder of query parameters for RemoveImageOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Remove the image even if it is being used by stopped containers or has other tags
    pub fn force(mut self, force: bool) -> Self {
        self.inner.force = force;
        self
    }

    /// Do not delete untagged parent images
    pub fn noprune(mut self, noprune: bool) -> Self {
        self.inner.noprune = noprune;
        self
    }

    /// Select platform-specific content to delete.
    /// Multiple values are accepted.
    /// Each platform is a OCI platform encoded as a JSON string.
    pub fn platforms(mut self, platforms: Vec<String>) -> Self {
        self.inner.platforms = Some(platforms
            .into_iter()
            .map(|v| Into::<String>::into(v.clone()))
            .collect());
        self
    }

    /// Consume this builder and use the `RemoveImageOptions` as parameter to the
    /// `ImageDelete` API
    pub fn build(self) -> RemoveImageOptions {
        self.inner
    }
}

/// Internal struct used in the `ImageDelete` API
/// 
/// Use a [RemoveImageOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RemoveImageOptions
{ 
    pub force: bool, 
    pub noprune: bool, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platforms: Option<Vec<String>>, 
}

impl Default for RemoveImageOptions
{
    fn default() -> Self {
        Self {
            force: false,
            noprune: false,
            platforms: None,
        }
    }
}

/// Builder for the `ImageGet` API query parameter.
///
/// Export an image.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::ExportImageOptionsBuilder;
///
/// let params = ExportImageOptionsBuilder::new()
/// //  .platform(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ExportImageOptionsBuilder {
    inner: ExportImageOptions,
}

impl ExportImageOptionsBuilder {
    /// Construct a builder of query parameters for ExportImageOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// JSON encoded OCI platform describing a platform which will be used
    /// to select a platform-specific image to be saved if the image is
    /// multi-platform.
    /// If not provided, the full multi-platform image will be saved.
    /// 
    /// Example: `{"os": "linux", "architecture": "arm", "variant": "v5"}`
    pub fn platform(mut self, platform: Vec<String>) -> Self {
        self.inner.platform = Some(platform
            .into_iter()
            .map(|v| Into::<String>::into(v.clone()))
            .collect());
        self
    }

    /// Consume this builder and use the `ExportImageOptions` as parameter to the
    /// `ImageGet` API
    pub fn build(self) -> ExportImageOptions {
        self.inner
    }
}

/// Internal struct used in the `ImageGet` API
/// 
/// Use a [ExportImageOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportImageOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<Vec<String>>, 
}

impl Default for ExportImageOptions
{
    fn default() -> Self {
        Self {
            platform: None,
        }
    }
}

/// Builder for the `ImageGetAll` API query parameter.
///
/// Export several images.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::ExportImagesOptionsBuilder;
///
/// let params = ExportImagesOptionsBuilder::new()
/// //  .names(/* ... */)
/// //  .platform(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ExportImagesOptionsBuilder {
    inner: ExportImagesOptions,
}

impl ExportImagesOptionsBuilder {
    /// Construct a builder of query parameters for ExportImagesOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Image names to filter by
    pub fn names(mut self, names: Vec<String>) -> Self {
        self.inner.names = Some(names
            .into_iter()
            .map(|v| Into::<String>::into(v.clone()))
            .collect());
        self
    }

    /// JSON encoded OCI platform(s) which will be used to select the
    /// platform-specific image(s) to be saved if the image is
    /// multi-platform. If not provided, the full multi-platform image
    /// will be saved.
    /// 
    /// Example: `{"os": "linux", "architecture": "arm", "variant": "v5"}`
    pub fn platform(mut self, platform: Vec<String>) -> Self {
        self.inner.platform = Some(platform
            .into_iter()
            .map(|v| Into::<String>::into(v.clone()))
            .collect());
        self
    }

    /// Consume this builder and use the `ExportImagesOptions` as parameter to the
    /// `ImageGetAll` API
    pub fn build(self) -> ExportImagesOptions {
        self.inner
    }
}

/// Internal struct used in the `ImageGetAll` API
/// 
/// Use a [ExportImagesOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExportImagesOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<Vec<String>>, 
}

impl Default for ExportImagesOptions
{
    fn default() -> Self {
        Self {
            names: None,
            platform: None,
        }
    }
}

/// Builder for the `ImageHistory` API query parameter.
///
/// Get the history of an image.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::ImageHistoryOptionsBuilder;
///
/// let params = ImageHistoryOptionsBuilder::new()
/// //  .platform(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ImageHistoryOptionsBuilder {
    inner: ImageHistoryOptions,
}

impl ImageHistoryOptionsBuilder {
    /// Construct a builder of query parameters for ImageHistoryOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// JSON-encoded OCI platform to select the platform-variant.
    /// If omitted, it defaults to any locally available platform,
    /// prioritizing the daemon's host platform.
    /// 
    /// If the daemon provides a multi-platform image store, this selects
    /// the platform-variant to show the history for. If the image is
    /// a single-platform image, or if the multi-platform image does not
    /// provide a variant matching the given platform, an error is returned.
    /// 
    /// Example: `{"os": "linux", "architecture": "arm", "variant": "v5"}`
    pub fn platform(mut self, platform: &str) -> Self {
        self.inner.platform = Some(platform.into());
        self
    }

    /// Consume this builder and use the `ImageHistoryOptions` as parameter to the
    /// `ImageHistory` API
    pub fn build(self) -> ImageHistoryOptions {
        self.inner
    }
}

/// Internal struct used in the `ImageHistory` API
/// 
/// Use a [ImageHistoryOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImageHistoryOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>, 
}

impl Default for ImageHistoryOptions
{
    fn default() -> Self {
        Self {
            platform: None,
        }
    }
}

/// Builder for the `ImageInspect` API query parameter.
///
/// Inspect an image.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::InspectImageOptionsBuilder;
///
/// let params = InspectImageOptionsBuilder::new()
/// //  .manifests(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct InspectImageOptionsBuilder {
    inner: InspectImageOptions,
}

impl InspectImageOptionsBuilder {
    /// Construct a builder of query parameters for InspectImageOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Include Manifests in the image summary.
    pub fn manifests(mut self, manifests: bool) -> Self {
        self.inner.manifests = manifests;
        self
    }

    /// Consume this builder and use the `InspectImageOptions` as parameter to the
    /// `ImageInspect` API
    pub fn build(self) -> InspectImageOptions {
        self.inner
    }
}

/// Internal struct used in the `ImageInspect` API
/// 
/// Use a [InspectImageOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InspectImageOptions
{ 
    pub manifests: bool, 
}

impl Default for InspectImageOptions
{
    fn default() -> Self {
        Self {
            manifests: false,
        }
    }
}

/// Builder for the `ImageList` API query parameter.
///
/// List Images.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::ListImagesOptionsBuilder;
///
/// let params = ListImagesOptionsBuilder::new()
/// //  .all(/* ... */)
/// //  .filters(/* ... */)
/// //  .shared_size(/* ... */)
/// //  .digests(/* ... */)
/// //  .manifests(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ListImagesOptionsBuilder {
    inner: ListImagesOptions,
}

impl ListImagesOptionsBuilder {
    /// Construct a builder of query parameters for ListImagesOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Show all images. Only images from a final layer (no children) are shown by default.
    pub fn all(mut self, all: bool) -> Self {
        self.inner.all = all;
        self
    }

    /// A JSON encoded value of the filters (a `map[string][]string`) to
    /// process on the images list.
    /// 
    /// Available filters:
    /// 
    /// - `before`=(`<image-name>[:<tag>]`,  `<image id>` or `<image@digest>`)
    /// - `dangling=true`
    /// - `label=key` or `label="key=value"` of an image label
    /// - `reference`=(`<image-name>[:<tag>]`)
    /// - `since`=(`<image-name>[:<tag>]`,  `<image id>` or `<image@digest>`)
    /// - `until=<timestamp>`
    pub fn filters(mut self, filters: &HashMap<impl Into<String> + Clone, Vec<impl Into<String> + Clone>>) -> Self {
        let mut inner_filters = HashMap::new();
        for (key, value) in filters {
            inner_filters.insert(
                Into::<String>::into(key.clone()),
                value
                    .into_iter()
                    .map(|v| Into::<String>::into(v.clone()))
                    .collect(),
            );
        }
        self.inner.filters = Some(inner_filters);
        self
    }

    /// Compute and show shared size as a `SharedSize` field on each image.
    pub fn shared_size(mut self, shared_size: bool) -> Self {
        self.inner.shared_size = shared_size;
        self
    }

    /// Show digest information as a `RepoDigests` field on each image.
    pub fn digests(mut self, digests: bool) -> Self {
        self.inner.digests = digests;
        self
    }

    /// Include `Manifests` in the image summary.
    pub fn manifests(mut self, manifests: bool) -> Self {
        self.inner.manifests = manifests;
        self
    }

    /// Consume this builder and use the `ListImagesOptions` as parameter to the
    /// `ImageList` API
    pub fn build(self) -> ListImagesOptions {
        self.inner
    }
}

/// Internal struct used in the `ImageList` API
/// 
/// Use a [ListImagesOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ListImagesOptions
{ 
    pub all: bool, 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_as_json")]
    pub filters: Option<HashMap<String, Vec<String>>>, 
    #[serde(rename = "shared-size")]
    pub shared_size: bool, 
    pub digests: bool, 
    pub manifests: bool, 
}

impl Default for ListImagesOptions
{
    fn default() -> Self {
        Self {
            all: false,
            filters: None,
            shared_size: false,
            digests: false,
            manifests: false,
        }
    }
}

/// Builder for the `ImageLoad` API query parameter.
///
/// Import images.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::ImportImageOptionsBuilder;
///
/// let params = ImportImageOptionsBuilder::new()
/// //  .quiet(/* ... */)
/// //  .platform(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ImportImageOptionsBuilder {
    inner: ImportImageOptions,
}

impl ImportImageOptionsBuilder {
    /// Construct a builder of query parameters for ImportImageOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Suppress progress details during load.
    pub fn quiet(mut self, quiet: bool) -> Self {
        self.inner.quiet = quiet;
        self
    }

    /// JSON encoded OCI platform(s) which will be used to select the
    /// platform-specific image(s) to load if the image is
    /// multi-platform. If not provided, the full multi-platform image
    /// will be loaded.
    /// 
    /// Example: `{"os": "linux", "architecture": "arm", "variant": "v5"}`
    pub fn platform(mut self, platform: Vec<String>) -> Self {
        self.inner.platform = Some(platform
            .into_iter()
            .map(|v| Into::<String>::into(v.clone()))
            .collect());
        self
    }

    /// Consume this builder and use the `ImportImageOptions` as parameter to the
    /// `ImageLoad` API
    pub fn build(self) -> ImportImageOptions {
        self.inner
    }
}

/// Internal struct used in the `ImageLoad` API
/// 
/// Use a [ImportImageOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImportImageOptions
{ 
    pub quiet: bool, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<Vec<String>>, 
}

impl Default for ImportImageOptions
{
    fn default() -> Self {
        Self {
            quiet: false,
            platform: None,
        }
    }
}

/// Builder for the `ImagePrune` API query parameter.
///
/// Delete unused images.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::PruneImagesOptionsBuilder;
///
/// let params = PruneImagesOptionsBuilder::new()
/// //  .filters(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct PruneImagesOptionsBuilder {
    inner: PruneImagesOptions,
}

impl PruneImagesOptionsBuilder {
    /// Construct a builder of query parameters for PruneImagesOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters to process on the prune list, encoded as JSON (a `map[string][]string`). Available filters:
    /// 
    /// - `dangling=<boolean>` When set to `true` (or `1`), prune only
    ///    unused *and* untagged images. When set to `false`
    ///    (or `0`), all unused images are pruned.
    /// - `until=<string>` Prune images created before this timestamp. The `<timestamp>` can be Unix timestamps, date formatted timestamps, or Go duration strings (e.g. `10m`, `1h30m`) computed relative to the daemon machine’s time.
    /// - `label` (`label=<key>`, `label=<key>=<value>`, `label!=<key>`, or `label!=<key>=<value>`) Prune images with (or without, in case `label!=...` is used) the specified labels.
    pub fn filters(mut self, filters: &HashMap<impl Into<String> + Clone, Vec<impl Into<String> + Clone>>) -> Self {
        let mut inner_filters = HashMap::new();
        for (key, value) in filters {
            inner_filters.insert(
                Into::<String>::into(key.clone()),
                value
                    .into_iter()
                    .map(|v| Into::<String>::into(v.clone()))
                    .collect(),
            );
        }
        self.inner.filters = Some(inner_filters);
        self
    }

    /// Consume this builder and use the `PruneImagesOptions` as parameter to the
    /// `ImagePrune` API
    pub fn build(self) -> PruneImagesOptions {
        self.inner
    }
}

/// Internal struct used in the `ImagePrune` API
/// 
/// Use a [PruneImagesOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PruneImagesOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_as_json")]
    pub filters: Option<HashMap<String, Vec<String>>>, 
}

impl Default for PruneImagesOptions
{
    fn default() -> Self {
        Self {
            filters: None,
        }
    }
}

/// Builder for the `ImagePush` API query parameter.
///
/// Push an image.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::PushImageOptionsBuilder;
///
/// let params = PushImageOptionsBuilder::new()
/// //  .tag(/* ... */)
/// //  .platform(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct PushImageOptionsBuilder {
    inner: PushImageOptions,
}

impl PushImageOptionsBuilder {
    /// Construct a builder of query parameters for PushImageOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Tag of the image to push. For example, `latest`. If no tag is provided,
    /// all tags of the given image that are present in the local image store
    /// are pushed.
    pub fn tag(mut self, tag: &str) -> Self {
        self.inner.tag = Some(tag.into());
        self
    }

    /// JSON-encoded OCI platform to select the platform-variant to push.
    /// If not provided, all available variants will attempt to be pushed.
    /// 
    /// If the daemon provides a multi-platform image store, this selects
    /// the platform-variant to push to the registry. If the image is
    /// a single-platform image, or if the multi-platform image does not
    /// provide a variant matching the given platform, an error is returned.
    /// 
    /// Example: `{"os": "linux", "architecture": "arm", "variant": "v5"}`
    pub fn platform(mut self, platform: &str) -> Self {
        self.inner.platform = Some(platform.into());
        self
    }

    /// Consume this builder and use the `PushImageOptions` as parameter to the
    /// `ImagePush` API
    pub fn build(self) -> PushImageOptions {
        self.inner
    }
}

/// Internal struct used in the `ImagePush` API
/// 
/// Use a [PushImageOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PushImageOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>, 
}

impl Default for PushImageOptions
{
    fn default() -> Self {
        Self {
            tag: None,
            platform: None,
        }
    }
}

/// Builder for the `ImageSearch` API query parameter.
///
/// Search images.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::SearchImagesOptionsBuilder;
///
/// let params = SearchImagesOptionsBuilder::new()
/// //  .term(/* ... */)
/// //  .limit(/* ... */)
/// //  .filters(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct SearchImagesOptionsBuilder {
    inner: SearchImagesOptions,
}

impl SearchImagesOptionsBuilder {
    /// Construct a builder of query parameters for SearchImagesOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Term to search
    pub fn term(mut self, term: &str) -> Self {
        self.inner.term = term.into();
        self
    }

    /// Maximum number of results to return
    pub fn limit(mut self, limit: i32) -> Self {
        self.inner.limit = Some(limit);
        self
    }

    /// A JSON encoded value of the filters (a `map[string][]string`) to process on the images list. Available filters:
    /// 
    /// - `is-official=(true|false)`
    /// - `stars=<number>` Matches images that has at least 'number' stars.
    pub fn filters(mut self, filters: &HashMap<impl Into<String> + Clone, Vec<impl Into<String> + Clone>>) -> Self {
        let mut inner_filters = HashMap::new();
        for (key, value) in filters {
            inner_filters.insert(
                Into::<String>::into(key.clone()),
                value
                    .into_iter()
                    .map(|v| Into::<String>::into(v.clone()))
                    .collect(),
            );
        }
        self.inner.filters = Some(inner_filters);
        self
    }

    /// Consume this builder and use the `SearchImagesOptions` as parameter to the
    /// `ImageSearch` API
    pub fn build(self) -> SearchImagesOptions {
        self.inner
    }
}

/// Internal struct used in the `ImageSearch` API
/// 
/// Use a [SearchImagesOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SearchImagesOptions
{ 
    pub term: String, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i32>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_as_json")]
    pub filters: Option<HashMap<String, Vec<String>>>, 
}

impl Default for SearchImagesOptions
{
    fn default() -> Self {
        Self {
            term: Default::default(),
            limit: None,
            filters: None,
        }
    }
}

/// Builder for the `ImageTag` API query parameter.
///
/// Tag an image.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::TagImageOptionsBuilder;
///
/// let params = TagImageOptionsBuilder::new()
/// //  .repo(/* ... */)
/// //  .tag(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct TagImageOptionsBuilder {
    inner: TagImageOptions,
}

impl TagImageOptionsBuilder {
    /// Construct a builder of query parameters for TagImageOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// The repository to tag in. For example, `someuser/someimage`.
    pub fn repo(mut self, repo: &str) -> Self {
        self.inner.repo = Some(repo.into());
        self
    }

    /// The name of the new tag.
    pub fn tag(mut self, tag: &str) -> Self {
        self.inner.tag = Some(tag.into());
        self
    }

    /// Consume this builder and use the `TagImageOptions` as parameter to the
    /// `ImageTag` API
    pub fn build(self) -> TagImageOptions {
        self.inner
    }
}

/// Internal struct used in the `ImageTag` API
/// 
/// Use a [TagImageOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TagImageOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>, 
}

impl Default for TagImageOptions
{
    fn default() -> Self {
        Self {
            repo: None,
            tag: None,
        }
    }
}




/// Builder for the `NetworkInspect` API query parameter.
///
/// Inspect a network.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::InspectNetworkOptionsBuilder;
///
/// let params = InspectNetworkOptionsBuilder::new()
/// //  .verbose(/* ... */)
/// //  .scope(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct InspectNetworkOptionsBuilder {
    inner: InspectNetworkOptions,
}

impl InspectNetworkOptionsBuilder {
    /// Construct a builder of query parameters for InspectNetworkOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Detailed inspect output for troubleshooting
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.inner.verbose = verbose;
        self
    }

    /// Filter the network by scope (swarm, global, or local)
    pub fn scope(mut self, scope: &str) -> Self {
        self.inner.scope = Some(scope.into());
        self
    }

    /// Consume this builder and use the `InspectNetworkOptions` as parameter to the
    /// `NetworkInspect` API
    pub fn build(self) -> InspectNetworkOptions {
        self.inner
    }
}

/// Internal struct used in the `NetworkInspect` API
/// 
/// Use a [InspectNetworkOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InspectNetworkOptions
{ 
    pub verbose: bool, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>, 
}

impl Default for InspectNetworkOptions
{
    fn default() -> Self {
        Self {
            verbose: false,
            scope: None,
        }
    }
}

/// Builder for the `NetworkList` API query parameter.
///
/// List networks.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::ListNetworksOptionsBuilder;
///
/// let params = ListNetworksOptionsBuilder::new()
/// //  .filters(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ListNetworksOptionsBuilder {
    inner: ListNetworksOptions,
}

impl ListNetworksOptionsBuilder {
    /// Construct a builder of query parameters for ListNetworksOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// JSON encoded value of the filters (a `map[string][]string`) to process
    /// on the networks list.
    /// 
    /// Available filters:
    /// 
    /// - `dangling=<boolean>` When set to `true` (or `1`), returns all
    ///    networks that are not in use by a container. When set to `false`
    ///    (or `0`), only networks that are in use by one or more
    ///    containers are returned.
    /// - `driver=<driver-name>` Matches a network's driver.
    /// - `id=<network-id>` Matches all or part of a network ID.
    /// - `label=<key>` or `label=<key>=<value>` of a network label.
    /// - `name=<network-name>` Matches all or part of a network name.
    /// - `scope=["swarm"|"global"|"local"]` Filters networks by scope (`swarm`, `global`, or `local`).
    /// - `type=["custom"|"builtin"]` Filters networks by type. The `custom` keyword returns all user-defined networks.
    pub fn filters(mut self, filters: &HashMap<impl Into<String> + Clone, Vec<impl Into<String> + Clone>>) -> Self {
        let mut inner_filters = HashMap::new();
        for (key, value) in filters {
            inner_filters.insert(
                Into::<String>::into(key.clone()),
                value
                    .into_iter()
                    .map(|v| Into::<String>::into(v.clone()))
                    .collect(),
            );
        }
        self.inner.filters = Some(inner_filters);
        self
    }

    /// Consume this builder and use the `ListNetworksOptions` as parameter to the
    /// `NetworkList` API
    pub fn build(self) -> ListNetworksOptions {
        self.inner
    }
}

/// Internal struct used in the `NetworkList` API
/// 
/// Use a [ListNetworksOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ListNetworksOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_as_json")]
    pub filters: Option<HashMap<String, Vec<String>>>, 
}

impl Default for ListNetworksOptions
{
    fn default() -> Self {
        Self {
            filters: None,
        }
    }
}

/// Builder for the `NetworkPrune` API query parameter.
///
/// Delete unused networks.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::PruneNetworksOptionsBuilder;
///
/// let params = PruneNetworksOptionsBuilder::new()
/// //  .filters(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct PruneNetworksOptionsBuilder {
    inner: PruneNetworksOptions,
}

impl PruneNetworksOptionsBuilder {
    /// Construct a builder of query parameters for PruneNetworksOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters to process on the prune list, encoded as JSON (a `map[string][]string`).
    /// 
    /// Available filters:
    /// - `until=<timestamp>` Prune networks created before this timestamp. The `<timestamp>` can be Unix timestamps, date formatted timestamps, or Go duration strings (e.g. `10m`, `1h30m`) computed relative to the daemon machine’s time.
    /// - `label` (`label=<key>`, `label=<key>=<value>`, `label!=<key>`, or `label!=<key>=<value>`) Prune networks with (or without, in case `label!=...` is used) the specified labels.
    pub fn filters(mut self, filters: &HashMap<impl Into<String> + Clone, Vec<impl Into<String> + Clone>>) -> Self {
        let mut inner_filters = HashMap::new();
        for (key, value) in filters {
            inner_filters.insert(
                Into::<String>::into(key.clone()),
                value
                    .into_iter()
                    .map(|v| Into::<String>::into(v.clone()))
                    .collect(),
            );
        }
        self.inner.filters = Some(inner_filters);
        self
    }

    /// Consume this builder and use the `PruneNetworksOptions` as parameter to the
    /// `NetworkPrune` API
    pub fn build(self) -> PruneNetworksOptions {
        self.inner
    }
}

/// Internal struct used in the `NetworkPrune` API
/// 
/// Use a [PruneNetworksOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PruneNetworksOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_as_json")]
    pub filters: Option<HashMap<String, Vec<String>>>, 
}

impl Default for PruneNetworksOptions
{
    fn default() -> Self {
        Self {
            filters: None,
        }
    }
}




/// Builder for the `NodeDelete` API query parameter.
///
/// Delete a node.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::DeleteNodeOptionsBuilder;
///
/// let params = DeleteNodeOptionsBuilder::new()
/// //  .force(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct DeleteNodeOptionsBuilder {
    inner: DeleteNodeOptions,
}

impl DeleteNodeOptionsBuilder {
    /// Construct a builder of query parameters for DeleteNodeOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Force remove a node from the swarm
    pub fn force(mut self, force: bool) -> Self {
        self.inner.force = force;
        self
    }

    /// Consume this builder and use the `DeleteNodeOptions` as parameter to the
    /// `NodeDelete` API
    pub fn build(self) -> DeleteNodeOptions {
        self.inner
    }
}

/// Internal struct used in the `NodeDelete` API
/// 
/// Use a [DeleteNodeOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DeleteNodeOptions
{ 
    pub force: bool, 
}

impl Default for DeleteNodeOptions
{
    fn default() -> Self {
        Self {
            force: false,
        }
    }
}

/// Builder for the `NodeList` API query parameter.
///
/// List nodes.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::ListNodesOptionsBuilder;
///
/// let params = ListNodesOptionsBuilder::new()
/// //  .filters(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ListNodesOptionsBuilder {
    inner: ListNodesOptions,
}

impl ListNodesOptionsBuilder {
    /// Construct a builder of query parameters for ListNodesOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters to process on the nodes list, encoded as JSON (a `map[string][]string`).
    /// 
    /// Available filters:
    /// - `id=<node id>`
    /// - `label=<engine label>`
    /// - `membership=`(`accepted`|`pending`)`
    /// - `name=<node name>`
    /// - `node.label=<node label>`
    /// - `role=`(`manager`|`worker`)`
    pub fn filters(mut self, filters: &HashMap<impl Into<String> + Clone, Vec<impl Into<String> + Clone>>) -> Self {
        let mut inner_filters = HashMap::new();
        for (key, value) in filters {
            inner_filters.insert(
                Into::<String>::into(key.clone()),
                value
                    .into_iter()
                    .map(|v| Into::<String>::into(v.clone()))
                    .collect(),
            );
        }
        self.inner.filters = Some(inner_filters);
        self
    }

    /// Consume this builder and use the `ListNodesOptions` as parameter to the
    /// `NodeList` API
    pub fn build(self) -> ListNodesOptions {
        self.inner
    }
}

/// Internal struct used in the `NodeList` API
/// 
/// Use a [ListNodesOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ListNodesOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_as_json")]
    pub filters: Option<HashMap<String, Vec<String>>>, 
}

impl Default for ListNodesOptions
{
    fn default() -> Self {
        Self {
            filters: None,
        }
    }
}

/// Builder for the `NodeUpdate` API query parameter.
///
/// Update a node.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::UpdateNodeOptionsBuilder;
///
/// let params = UpdateNodeOptionsBuilder::new()
/// //  .version(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct UpdateNodeOptionsBuilder {
    inner: UpdateNodeOptions,
}

impl UpdateNodeOptionsBuilder {
    /// Construct a builder of query parameters for UpdateNodeOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// The version number of the node object being updated. This is required
    /// to avoid conflicting writes.
    pub fn version(mut self, version: i64) -> Self {
        self.inner.version = version;
        self
    }

    /// Consume this builder and use the `UpdateNodeOptions` as parameter to the
    /// `NodeUpdate` API
    pub fn build(self) -> UpdateNodeOptions {
        self.inner
    }
}

/// Internal struct used in the `NodeUpdate` API
/// 
/// Use a [UpdateNodeOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UpdateNodeOptions
{ 
    pub version: i64, 
}

impl Default for UpdateNodeOptions
{
    fn default() -> Self {
        Self {
            version: Default::default(),
        }
    }
}




/// Builder for the `GetPluginPrivileges` API query parameter.
///
/// Get plugin privileges.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::GetPluginPrivilegesOptionsBuilder;
///
/// let params = GetPluginPrivilegesOptionsBuilder::new()
/// //  .remote(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct GetPluginPrivilegesOptionsBuilder {
    inner: GetPluginPrivilegesOptions,
}

impl GetPluginPrivilegesOptionsBuilder {
    /// Construct a builder of query parameters for GetPluginPrivilegesOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// The name of the plugin. The `:latest` tag is optional, and is the
    /// default if omitted.
    pub fn remote(mut self, remote: &str) -> Self {
        self.inner.remote = remote.into();
        self
    }

    /// Consume this builder and use the `GetPluginPrivilegesOptions` as parameter to the
    /// `GetPluginPrivileges` API
    pub fn build(self) -> GetPluginPrivilegesOptions {
        self.inner
    }
}

/// Internal struct used in the `GetPluginPrivileges` API
/// 
/// Use a [GetPluginPrivilegesOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GetPluginPrivilegesOptions
{ 
    pub remote: String, 
}

impl Default for GetPluginPrivilegesOptions
{
    fn default() -> Self {
        Self {
            remote: Default::default(),
        }
    }
}

/// Builder for the `PluginCreate` API query parameter.
///
/// Create a plugin.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::CreatePluginOptionsBuilder;
///
/// let params = CreatePluginOptionsBuilder::new()
/// //  .name(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct CreatePluginOptionsBuilder {
    inner: CreatePluginOptions,
}

impl CreatePluginOptionsBuilder {
    /// Construct a builder of query parameters for CreatePluginOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// The name of the plugin. The `:latest` tag is optional, and is the
    /// default if omitted.
    pub fn name(mut self, name: &str) -> Self {
        self.inner.name = name.into();
        self
    }

    /// Consume this builder and use the `CreatePluginOptions` as parameter to the
    /// `PluginCreate` API
    pub fn build(self) -> CreatePluginOptions {
        self.inner
    }
}

/// Internal struct used in the `PluginCreate` API
/// 
/// Use a [CreatePluginOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CreatePluginOptions
{ 
    pub name: String, 
}

impl Default for CreatePluginOptions
{
    fn default() -> Self {
        Self {
            name: Default::default(),
        }
    }
}

/// Builder for the `PluginDelete` API query parameter.
///
/// Remove a plugin.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::RemovePluginOptionsBuilder;
///
/// let params = RemovePluginOptionsBuilder::new()
/// //  .force(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct RemovePluginOptionsBuilder {
    inner: RemovePluginOptions,
}

impl RemovePluginOptionsBuilder {
    /// Construct a builder of query parameters for RemovePluginOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable the plugin before removing. This may result in issues if the
    /// plugin is in use by a container.
    pub fn force(mut self, force: bool) -> Self {
        self.inner.force = force;
        self
    }

    /// Consume this builder and use the `RemovePluginOptions` as parameter to the
    /// `PluginDelete` API
    pub fn build(self) -> RemovePluginOptions {
        self.inner
    }
}

/// Internal struct used in the `PluginDelete` API
/// 
/// Use a [RemovePluginOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RemovePluginOptions
{ 
    pub force: bool, 
}

impl Default for RemovePluginOptions
{
    fn default() -> Self {
        Self {
            force: false,
        }
    }
}

/// Builder for the `PluginDisable` API query parameter.
///
/// Disable a plugin.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::DisablePluginOptionsBuilder;
///
/// let params = DisablePluginOptionsBuilder::new()
/// //  .force(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct DisablePluginOptionsBuilder {
    inner: DisablePluginOptions,
}

impl DisablePluginOptionsBuilder {
    /// Construct a builder of query parameters for DisablePluginOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Force disable a plugin even if still in use.
    pub fn force(mut self, force: bool) -> Self {
        self.inner.force = Some(force);
        self
    }

    /// Consume this builder and use the `DisablePluginOptions` as parameter to the
    /// `PluginDisable` API
    pub fn build(self) -> DisablePluginOptions {
        self.inner
    }
}

/// Internal struct used in the `PluginDisable` API
/// 
/// Use a [DisablePluginOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DisablePluginOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force: Option<bool>, 
}

impl Default for DisablePluginOptions
{
    fn default() -> Self {
        Self {
            force: None,
        }
    }
}

/// Builder for the `PluginEnable` API query parameter.
///
/// Enable a plugin.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::EnablePluginOptionsBuilder;
///
/// let params = EnablePluginOptionsBuilder::new()
/// //  .timeout(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct EnablePluginOptionsBuilder {
    inner: EnablePluginOptions,
}

impl EnablePluginOptionsBuilder {
    /// Construct a builder of query parameters for EnablePluginOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the HTTP client timeout (in seconds)
    pub fn timeout(mut self, timeout: i32) -> Self {
        self.inner.timeout = timeout;
        self
    }

    /// Consume this builder and use the `EnablePluginOptions` as parameter to the
    /// `PluginEnable` API
    pub fn build(self) -> EnablePluginOptions {
        self.inner
    }
}

/// Internal struct used in the `PluginEnable` API
/// 
/// Use a [EnablePluginOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EnablePluginOptions
{ 
    pub timeout: i32, 
}

impl Default for EnablePluginOptions
{
    fn default() -> Self {
        Self {
            timeout: 0,
        }
    }
}

/// Builder for the `PluginList` API query parameter.
///
/// List plugins.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::ListPluginsOptionsBuilder;
///
/// let params = ListPluginsOptionsBuilder::new()
/// //  .filters(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ListPluginsOptionsBuilder {
    inner: ListPluginsOptions,
}

impl ListPluginsOptionsBuilder {
    /// Construct a builder of query parameters for ListPluginsOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// A JSON encoded value of the filters (a `map[string][]string`) to
    /// process on the plugin list.
    /// 
    /// Available filters:
    /// 
    /// - `capability=<capability name>`
    /// - `enable=<true>|<false>`
    pub fn filters(mut self, filters: &HashMap<impl Into<String> + Clone, Vec<impl Into<String> + Clone>>) -> Self {
        let mut inner_filters = HashMap::new();
        for (key, value) in filters {
            inner_filters.insert(
                Into::<String>::into(key.clone()),
                value
                    .into_iter()
                    .map(|v| Into::<String>::into(v.clone()))
                    .collect(),
            );
        }
        self.inner.filters = Some(inner_filters);
        self
    }

    /// Consume this builder and use the `ListPluginsOptions` as parameter to the
    /// `PluginList` API
    pub fn build(self) -> ListPluginsOptions {
        self.inner
    }
}

/// Internal struct used in the `PluginList` API
/// 
/// Use a [ListPluginsOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ListPluginsOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_as_json")]
    pub filters: Option<HashMap<String, Vec<String>>>, 
}

impl Default for ListPluginsOptions
{
    fn default() -> Self {
        Self {
            filters: None,
        }
    }
}

/// Builder for the `PluginPull` API query parameter.
///
/// Install a plugin.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::InstallPluginOptionsBuilder;
///
/// let params = InstallPluginOptionsBuilder::new()
/// //  .remote(/* ... */)
/// //  .name(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct InstallPluginOptionsBuilder {
    inner: InstallPluginOptions,
}

impl InstallPluginOptionsBuilder {
    /// Construct a builder of query parameters for InstallPluginOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Remote reference for plugin to install.
    /// 
    /// The `:latest` tag is optional, and is used as the default if omitted.
    pub fn remote(mut self, remote: &str) -> Self {
        self.inner.remote = remote.into();
        self
    }

    /// Local name for the pulled plugin.
    /// 
    /// The `:latest` tag is optional, and is used as the default if omitted.
    pub fn name(mut self, name: &str) -> Self {
        self.inner.name = Some(name.into());
        self
    }

    /// Consume this builder and use the `InstallPluginOptions` as parameter to the
    /// `PluginPull` API
    pub fn build(self) -> InstallPluginOptions {
        self.inner
    }
}

/// Internal struct used in the `PluginPull` API
/// 
/// Use a [InstallPluginOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InstallPluginOptions
{ 
    pub remote: String, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>, 
}

impl Default for InstallPluginOptions
{
    fn default() -> Self {
        Self {
            remote: Default::default(),
            name: None,
        }
    }
}

/// Builder for the `PluginUpgrade` API query parameter.
///
/// Upgrade a plugin.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::UpgradePluginOptionsBuilder;
///
/// let params = UpgradePluginOptionsBuilder::new()
/// //  .remote(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct UpgradePluginOptionsBuilder {
    inner: UpgradePluginOptions,
}

impl UpgradePluginOptionsBuilder {
    /// Construct a builder of query parameters for UpgradePluginOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Remote reference to upgrade to.
    /// 
    /// The `:latest` tag is optional, and is used as the default if omitted.
    pub fn remote(mut self, remote: &str) -> Self {
        self.inner.remote = remote.into();
        self
    }

    /// Consume this builder and use the `UpgradePluginOptions` as parameter to the
    /// `PluginUpgrade` API
    pub fn build(self) -> UpgradePluginOptions {
        self.inner
    }
}

/// Internal struct used in the `PluginUpgrade` API
/// 
/// Use a [UpgradePluginOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UpgradePluginOptions
{ 
    pub remote: String, 
}

impl Default for UpgradePluginOptions
{
    fn default() -> Self {
        Self {
            remote: Default::default(),
        }
    }
}




/// Builder for the `SecretList` API query parameter.
///
/// List secrets.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::ListSecretsOptionsBuilder;
///
/// let params = ListSecretsOptionsBuilder::new()
/// //  .filters(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ListSecretsOptionsBuilder {
    inner: ListSecretsOptions,
}

impl ListSecretsOptionsBuilder {
    /// Construct a builder of query parameters for ListSecretsOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// A JSON encoded value of the filters (a `map[string][]string`) to
    /// process on the secrets list.
    /// 
    /// Available filters:
    /// 
    /// - `id=<secret id>`
    /// - `label=<key> or label=<key>=value`
    /// - `name=<secret name>`
    /// - `names=<secret name>`
    pub fn filters(mut self, filters: &HashMap<impl Into<String> + Clone, Vec<impl Into<String> + Clone>>) -> Self {
        let mut inner_filters = HashMap::new();
        for (key, value) in filters {
            inner_filters.insert(
                Into::<String>::into(key.clone()),
                value
                    .into_iter()
                    .map(|v| Into::<String>::into(v.clone()))
                    .collect(),
            );
        }
        self.inner.filters = Some(inner_filters);
        self
    }

    /// Consume this builder and use the `ListSecretsOptions` as parameter to the
    /// `SecretList` API
    pub fn build(self) -> ListSecretsOptions {
        self.inner
    }
}

/// Internal struct used in the `SecretList` API
/// 
/// Use a [ListSecretsOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ListSecretsOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_as_json")]
    pub filters: Option<HashMap<String, Vec<String>>>, 
}

impl Default for ListSecretsOptions
{
    fn default() -> Self {
        Self {
            filters: None,
        }
    }
}

/// Builder for the `SecretUpdate` API query parameter.
///
/// Update a Secret.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::UpdateSecretOptionsBuilder;
///
/// let params = UpdateSecretOptionsBuilder::new()
/// //  .version(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct UpdateSecretOptionsBuilder {
    inner: UpdateSecretOptions,
}

impl UpdateSecretOptionsBuilder {
    /// Construct a builder of query parameters for UpdateSecretOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// The version number of the secret object being updated. This is
    /// required to avoid conflicting writes.
    pub fn version(mut self, version: i64) -> Self {
        self.inner.version = version;
        self
    }

    /// Consume this builder and use the `UpdateSecretOptions` as parameter to the
    /// `SecretUpdate` API
    pub fn build(self) -> UpdateSecretOptions {
        self.inner
    }
}

/// Internal struct used in the `SecretUpdate` API
/// 
/// Use a [UpdateSecretOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UpdateSecretOptions
{ 
    pub version: i64, 
}

impl Default for UpdateSecretOptions
{
    fn default() -> Self {
        Self {
            version: Default::default(),
        }
    }
}




/// Builder for the `ServiceInspect` API query parameter.
///
/// Inspect a service.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::InspectServiceOptionsBuilder;
///
/// let params = InspectServiceOptionsBuilder::new()
/// //  .insert_defaults(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct InspectServiceOptionsBuilder {
    inner: InspectServiceOptions,
}

impl InspectServiceOptionsBuilder {
    /// Construct a builder of query parameters for InspectServiceOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fill empty fields with default values.
    pub fn insert_defaults(mut self, insert_defaults: bool) -> Self {
        self.inner.insert_defaults = insert_defaults;
        self
    }

    /// Consume this builder and use the `InspectServiceOptions` as parameter to the
    /// `ServiceInspect` API
    pub fn build(self) -> InspectServiceOptions {
        self.inner
    }
}

/// Internal struct used in the `ServiceInspect` API
/// 
/// Use a [InspectServiceOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InspectServiceOptions
{ 
    #[serde(rename = "insertDefaults")]
    pub insert_defaults: bool, 
}

impl Default for InspectServiceOptions
{
    fn default() -> Self {
        Self {
            insert_defaults: false,
        }
    }
}

/// Builder for the `ServiceList` API query parameter.
///
/// List services.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::ListServicesOptionsBuilder;
///
/// let params = ListServicesOptionsBuilder::new()
/// //  .filters(/* ... */)
/// //  .status(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ListServicesOptionsBuilder {
    inner: ListServicesOptions,
}

impl ListServicesOptionsBuilder {
    /// Construct a builder of query parameters for ListServicesOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// A JSON encoded value of the filters (a `map[string][]string`) to
    /// process on the services list.
    /// 
    /// Available filters:
    /// 
    /// - `id=<service id>`
    /// - `label=<service label>`
    /// - `mode=["replicated"|"global"]`
    /// - `name=<service name>`
    pub fn filters(mut self, filters: &HashMap<impl Into<String> + Clone, Vec<impl Into<String> + Clone>>) -> Self {
        let mut inner_filters = HashMap::new();
        for (key, value) in filters {
            inner_filters.insert(
                Into::<String>::into(key.clone()),
                value
                    .into_iter()
                    .map(|v| Into::<String>::into(v.clone()))
                    .collect(),
            );
        }
        self.inner.filters = Some(inner_filters);
        self
    }

    /// Include service status, with count of running and desired tasks.
    pub fn status(mut self, status: bool) -> Self {
        self.inner.status = Some(status);
        self
    }

    /// Consume this builder and use the `ListServicesOptions` as parameter to the
    /// `ServiceList` API
    pub fn build(self) -> ListServicesOptions {
        self.inner
    }
}

/// Internal struct used in the `ServiceList` API
/// 
/// Use a [ListServicesOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ListServicesOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_as_json")]
    pub filters: Option<HashMap<String, Vec<String>>>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<bool>, 
}

impl Default for ListServicesOptions
{
    fn default() -> Self {
        Self {
            filters: None,
            status: None,
        }
    }
}

/// Builder for the `ServiceLogs` API query parameter.
///
/// Get service logs.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::ServiceLogsOptionsBuilder;
///
/// let params = ServiceLogsOptionsBuilder::new()
/// //  .details(/* ... */)
/// //  .follow(/* ... */)
/// //  .stdout(/* ... */)
/// //  .stderr(/* ... */)
/// //  .since(/* ... */)
/// //  .timestamps(/* ... */)
/// //  .tail(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ServiceLogsOptionsBuilder {
    inner: ServiceLogsOptions,
}

impl ServiceLogsOptionsBuilder {
    /// Construct a builder of query parameters for ServiceLogsOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Show service context and extra details provided to logs.
    pub fn details(mut self, details: bool) -> Self {
        self.inner.details = details;
        self
    }

    /// Keep connection after returning logs.
    pub fn follow(mut self, follow: bool) -> Self {
        self.inner.follow = follow;
        self
    }

    /// Return logs from `stdout`
    pub fn stdout(mut self, stdout: bool) -> Self {
        self.inner.stdout = stdout;
        self
    }

    /// Return logs from `stderr`
    pub fn stderr(mut self, stderr: bool) -> Self {
        self.inner.stderr = stderr;
        self
    }

    /// Only return logs since this time, as a UNIX timestamp
    pub fn since(mut self, since: i32) -> Self {
        self.inner.since = since;
        self
    }

    /// Add timestamps to every log line
    pub fn timestamps(mut self, timestamps: bool) -> Self {
        self.inner.timestamps = timestamps;
        self
    }

    /// Only return this number of log lines from the end of the logs.
    /// Specify as an integer or `all` to output all log lines.
    pub fn tail(mut self, tail: &str) -> Self {
        self.inner.tail = tail.into();
        self
    }

    /// Consume this builder and use the `ServiceLogsOptions` as parameter to the
    /// `ServiceLogs` API
    pub fn build(self) -> ServiceLogsOptions {
        self.inner
    }
}

/// Internal struct used in the `ServiceLogs` API
/// 
/// Use a [ServiceLogsOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ServiceLogsOptions
{ 
    pub details: bool, 
    pub follow: bool, 
    pub stdout: bool, 
    pub stderr: bool, 
    pub since: i32, 
    pub timestamps: bool, 
    pub tail: String, 
}

impl Default for ServiceLogsOptions
{
    fn default() -> Self {
        Self {
            details: false,
            follow: false,
            stdout: false,
            stderr: false,
            since: 0,
            timestamps: false,
            tail: String::from("all"),
        }
    }
}

/// Builder for the `ServiceUpdate` API query parameter.
///
/// Update a service.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::UpdateServiceOptionsBuilder;
///
/// let params = UpdateServiceOptionsBuilder::new()
/// //  .version(/* ... */)
/// //  .registry_auth_from(/* ... */)
/// //  .rollback(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct UpdateServiceOptionsBuilder {
    inner: UpdateServiceOptions,
}

impl UpdateServiceOptionsBuilder {
    /// Construct a builder of query parameters for UpdateServiceOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// The version number of the service object being updated. This is
    /// required to avoid conflicting writes.
    /// This version number should be the value as currently set on the
    /// service *before* the update. You can find the current version by
    /// calling `GET /services/{id}`
    pub fn version(mut self, version: i32) -> Self {
        self.inner.version = version;
        self
    }

    /// If the `X-Registry-Auth` header is not specified, this parameter
    /// indicates where to find registry authorization credentials.
    pub fn registry_auth_from(mut self, registry_auth_from: &str) -> Self {
        self.inner.registry_auth_from = registry_auth_from.into();
        self
    }

    /// Set to this parameter to `previous` to cause a server-side rollback
    /// to the previous service spec. The supplied spec will be ignored in
    /// this case.
    pub fn rollback(mut self, rollback: &str) -> Self {
        self.inner.rollback = Some(rollback.into());
        self
    }

    /// Consume this builder and use the `UpdateServiceOptions` as parameter to the
    /// `ServiceUpdate` API
    pub fn build(self) -> UpdateServiceOptions {
        self.inner
    }
}

/// Internal struct used in the `ServiceUpdate` API
/// 
/// Use a [UpdateServiceOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UpdateServiceOptions
{ 
    pub version: i32, 
    #[serde(rename = "registryAuthFrom")]
    pub registry_auth_from: String, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback: Option<String>, 
}

impl Default for UpdateServiceOptions
{
    fn default() -> Self {
        Self {
            version: Default::default(),
            registry_auth_from: String::from("spec"),
            rollback: None,
        }
    }
}







/// Builder for the `SwarmLeave` API query parameter.
///
/// Leave a swarm.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::LeaveSwarmOptionsBuilder;
///
/// let params = LeaveSwarmOptionsBuilder::new()
/// //  .force(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct LeaveSwarmOptionsBuilder {
    inner: LeaveSwarmOptions,
}

impl LeaveSwarmOptionsBuilder {
    /// Construct a builder of query parameters for LeaveSwarmOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Force leave swarm, even if this is the last manager or that it will
    /// break the cluster.
    pub fn force(mut self, force: bool) -> Self {
        self.inner.force = force;
        self
    }

    /// Consume this builder and use the `LeaveSwarmOptions` as parameter to the
    /// `SwarmLeave` API
    pub fn build(self) -> LeaveSwarmOptions {
        self.inner
    }
}

/// Internal struct used in the `SwarmLeave` API
/// 
/// Use a [LeaveSwarmOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LeaveSwarmOptions
{ 
    pub force: bool, 
}

impl Default for LeaveSwarmOptions
{
    fn default() -> Self {
        Self {
            force: false,
        }
    }
}

/// Builder for the `SwarmUpdate` API query parameter.
///
/// Update a swarm.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::UpdateSwarmOptionsBuilder;
///
/// let params = UpdateSwarmOptionsBuilder::new()
/// //  .version(/* ... */)
/// //  .rotate_worker_token(/* ... */)
/// //  .rotate_manager_token(/* ... */)
/// //  .rotate_manager_unlock_key(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct UpdateSwarmOptionsBuilder {
    inner: UpdateSwarmOptions,
}

impl UpdateSwarmOptionsBuilder {
    /// Construct a builder of query parameters for UpdateSwarmOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// The version number of the swarm object being updated. This is
    /// required to avoid conflicting writes.
    pub fn version(mut self, version: i64) -> Self {
        self.inner.version = version;
        self
    }

    /// Rotate the worker join token.
    pub fn rotate_worker_token(mut self, rotate_worker_token: bool) -> Self {
        self.inner.rotate_worker_token = rotate_worker_token;
        self
    }

    /// Rotate the manager join token.
    pub fn rotate_manager_token(mut self, rotate_manager_token: bool) -> Self {
        self.inner.rotate_manager_token = rotate_manager_token;
        self
    }

    /// Rotate the manager unlock key.
    pub fn rotate_manager_unlock_key(mut self, rotate_manager_unlock_key: bool) -> Self {
        self.inner.rotate_manager_unlock_key = rotate_manager_unlock_key;
        self
    }

    /// Consume this builder and use the `UpdateSwarmOptions` as parameter to the
    /// `SwarmUpdate` API
    pub fn build(self) -> UpdateSwarmOptions {
        self.inner
    }
}

/// Internal struct used in the `SwarmUpdate` API
/// 
/// Use a [UpdateSwarmOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UpdateSwarmOptions
{ 
    pub version: i64, 
    #[serde(rename = "rotateWorkerToken")]
    pub rotate_worker_token: bool, 
    #[serde(rename = "rotateManagerToken")]
    pub rotate_manager_token: bool, 
    #[serde(rename = "rotateManagerUnlockKey")]
    pub rotate_manager_unlock_key: bool, 
}

impl Default for UpdateSwarmOptions
{
    fn default() -> Self {
        Self {
            version: Default::default(),
            rotate_worker_token: false,
            rotate_manager_token: false,
            rotate_manager_unlock_key: false,
        }
    }
}




/// Builder for the `SystemDataUsage` API query parameter.
///
/// Get data usage information.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::DataUsageOptionsBuilder;
///
/// let params = DataUsageOptionsBuilder::new()
/// //  ._type(/* ... */)
/// //  .verbose(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct DataUsageOptionsBuilder {
    inner: DataUsageOptions,
}

impl DataUsageOptionsBuilder {
    /// Construct a builder of query parameters for DataUsageOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Object types, for which to compute and return data.
    pub fn _type(mut self, _type: Vec<String>) -> Self {
        self.inner._type = Some(_type
            .into_iter()
            .map(|v| Into::<String>::into(v.clone()))
            .collect());
        self
    }

    /// Show detailed information on space usage.
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.inner.verbose = verbose;
        self
    }

    /// Consume this builder and use the `DataUsageOptions` as parameter to the
    /// `SystemDataUsage` API
    pub fn build(self) -> DataUsageOptions {
        self.inner
    }
}

/// Internal struct used in the `SystemDataUsage` API
/// 
/// Use a [DataUsageOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DataUsageOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    pub _type: Option<Vec<String>>, 
    pub verbose: bool, 
}

impl Default for DataUsageOptions
{
    fn default() -> Self {
        Self {
            _type: None,
            verbose: false,
        }
    }
}

/// Builder for the `SystemEvents` API query parameter.
///
/// Monitor events.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::EventsOptionsBuilder;
///
/// let params = EventsOptionsBuilder::new()
/// //  .since(/* ... */)
/// //  .until(/* ... */)
/// //  .filters(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct EventsOptionsBuilder {
    inner: EventsOptions,
}

impl EventsOptionsBuilder {
    /// Construct a builder of query parameters for EventsOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Show events created since this timestamp then stream new events.
    pub fn since(mut self, since: &str) -> Self {
        self.inner.since = Some(since.into());
        self
    }

    /// Show events created until this timestamp then stop streaming.
    pub fn until(mut self, until: &str) -> Self {
        self.inner.until = Some(until.into());
        self
    }

    /// A JSON encoded value of filters (a `map[string][]string`) to process on the event list. Available filters:
    /// 
    /// - `config=<string>` config name or ID
    /// - `container=<string>` container name or ID
    /// - `daemon=<string>` daemon name or ID
    /// - `event=<string>` event type
    /// - `image=<string>` image name or ID
    /// - `label=<string>` image or container label
    /// - `network=<string>` network name or ID
    /// - `node=<string>` node ID
    /// - `plugin`=<string> plugin name or ID
    /// - `scope`=<string> local or swarm
    /// - `secret=<string>` secret name or ID
    /// - `service=<string>` service name or ID
    /// - `type=<string>` object to filter by, one of `container`, `image`, `volume`, `network`, `daemon`, `plugin`, `node`, `service`, `secret` or `config`
    /// - `volume=<string>` volume name
    pub fn filters(mut self, filters: &HashMap<impl Into<String> + Clone, Vec<impl Into<String> + Clone>>) -> Self {
        let mut inner_filters = HashMap::new();
        for (key, value) in filters {
            inner_filters.insert(
                Into::<String>::into(key.clone()),
                value
                    .into_iter()
                    .map(|v| Into::<String>::into(v.clone()))
                    .collect(),
            );
        }
        self.inner.filters = Some(inner_filters);
        self
    }

    /// Consume this builder and use the `EventsOptions` as parameter to the
    /// `SystemEvents` API
    pub fn build(self) -> EventsOptions {
        self.inner
    }
}

/// Internal struct used in the `SystemEvents` API
/// 
/// Use a [EventsOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EventsOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_as_json")]
    pub filters: Option<HashMap<String, Vec<String>>>, 
}

impl Default for EventsOptions
{
    fn default() -> Self {
        Self {
            since: None,
            until: None,
            filters: None,
        }
    }
}




/// Builder for the `TaskList` API query parameter.
///
/// List tasks.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::ListTasksOptionsBuilder;
///
/// let params = ListTasksOptionsBuilder::new()
/// //  .filters(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ListTasksOptionsBuilder {
    inner: ListTasksOptions,
}

impl ListTasksOptionsBuilder {
    /// Construct a builder of query parameters for ListTasksOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// A JSON encoded value of the filters (a `map[string][]string`) to
    /// process on the tasks list.
    /// 
    /// Available filters:
    /// 
    /// - `desired-state=(running | shutdown | accepted)`
    /// - `id=<task id>`
    /// - `label=key` or `label="key=value"`
    /// - `name=<task name>`
    /// - `node=<node id or name>`
    /// - `service=<service name>`
    pub fn filters(mut self, filters: &HashMap<impl Into<String> + Clone, Vec<impl Into<String> + Clone>>) -> Self {
        let mut inner_filters = HashMap::new();
        for (key, value) in filters {
            inner_filters.insert(
                Into::<String>::into(key.clone()),
                value
                    .into_iter()
                    .map(|v| Into::<String>::into(v.clone()))
                    .collect(),
            );
        }
        self.inner.filters = Some(inner_filters);
        self
    }

    /// Consume this builder and use the `ListTasksOptions` as parameter to the
    /// `TaskList` API
    pub fn build(self) -> ListTasksOptions {
        self.inner
    }
}

/// Internal struct used in the `TaskList` API
/// 
/// Use a [ListTasksOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ListTasksOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_as_json")]
    pub filters: Option<HashMap<String, Vec<String>>>, 
}

impl Default for ListTasksOptions
{
    fn default() -> Self {
        Self {
            filters: None,
        }
    }
}

/// Builder for the `TaskLogs` API query parameter.
///
/// Get task logs.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::TaskLogsOptionsBuilder;
///
/// let params = TaskLogsOptionsBuilder::new()
/// //  .details(/* ... */)
/// //  .follow(/* ... */)
/// //  .stdout(/* ... */)
/// //  .stderr(/* ... */)
/// //  .since(/* ... */)
/// //  .timestamps(/* ... */)
/// //  .tail(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct TaskLogsOptionsBuilder {
    inner: TaskLogsOptions,
}

impl TaskLogsOptionsBuilder {
    /// Construct a builder of query parameters for TaskLogsOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Show task context and extra details provided to logs.
    pub fn details(mut self, details: bool) -> Self {
        self.inner.details = details;
        self
    }

    /// Keep connection after returning logs.
    pub fn follow(mut self, follow: bool) -> Self {
        self.inner.follow = follow;
        self
    }

    /// Return logs from `stdout`
    pub fn stdout(mut self, stdout: bool) -> Self {
        self.inner.stdout = stdout;
        self
    }

    /// Return logs from `stderr`
    pub fn stderr(mut self, stderr: bool) -> Self {
        self.inner.stderr = stderr;
        self
    }

    /// Only return logs since this time, as a UNIX timestamp
    pub fn since(mut self, since: i32) -> Self {
        self.inner.since = since;
        self
    }

    /// Add timestamps to every log line
    pub fn timestamps(mut self, timestamps: bool) -> Self {
        self.inner.timestamps = timestamps;
        self
    }

    /// Only return this number of log lines from the end of the logs.
    /// Specify as an integer or `all` to output all log lines.
    pub fn tail(mut self, tail: &str) -> Self {
        self.inner.tail = tail.into();
        self
    }

    /// Consume this builder and use the `TaskLogsOptions` as parameter to the
    /// `TaskLogs` API
    pub fn build(self) -> TaskLogsOptions {
        self.inner
    }
}

/// Internal struct used in the `TaskLogs` API
/// 
/// Use a [TaskLogsOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TaskLogsOptions
{ 
    pub details: bool, 
    pub follow: bool, 
    pub stdout: bool, 
    pub stderr: bool, 
    pub since: i32, 
    pub timestamps: bool, 
    pub tail: String, 
}

impl Default for TaskLogsOptions
{
    fn default() -> Self {
        Self {
            details: false,
            follow: false,
            stdout: false,
            stderr: false,
            since: 0,
            timestamps: false,
            tail: String::from("all"),
        }
    }
}




/// Builder for the `VolumeDelete` API query parameter.
///
/// Remove a volume.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::RemoveVolumeOptionsBuilder;
///
/// let params = RemoveVolumeOptionsBuilder::new()
/// //  .force(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct RemoveVolumeOptionsBuilder {
    inner: RemoveVolumeOptions,
}

impl RemoveVolumeOptionsBuilder {
    /// Construct a builder of query parameters for RemoveVolumeOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Force the removal of the volume
    pub fn force(mut self, force: bool) -> Self {
        self.inner.force = force;
        self
    }

    /// Consume this builder and use the `RemoveVolumeOptions` as parameter to the
    /// `VolumeDelete` API
    pub fn build(self) -> RemoveVolumeOptions {
        self.inner
    }
}

/// Internal struct used in the `VolumeDelete` API
/// 
/// Use a [RemoveVolumeOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RemoveVolumeOptions
{ 
    pub force: bool, 
}

impl Default for RemoveVolumeOptions
{
    fn default() -> Self {
        Self {
            force: false,
        }
    }
}

/// Builder for the `VolumeList` API query parameter.
///
/// List volumes.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::ListVolumesOptionsBuilder;
///
/// let params = ListVolumesOptionsBuilder::new()
/// //  .filters(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ListVolumesOptionsBuilder {
    inner: ListVolumesOptions,
}

impl ListVolumesOptionsBuilder {
    /// Construct a builder of query parameters for ListVolumesOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// JSON encoded value of the filters (a `map[string][]string`) to
    /// process on the volumes list. Available filters:
    /// 
    /// - `dangling=<boolean>` When set to `true` (or `1`), returns all
    ///    volumes that are not in use by a container. When set to `false`
    ///    (or `0`), only volumes that are in use by one or more
    ///    containers are returned.
    /// - `driver=<volume-driver-name>` Matches volumes based on their driver.
    /// - `label=<key>` or `label=<key>:<value>` Matches volumes based on
    ///    the presence of a `label` alone or a `label` and a value.
    /// - `name=<volume-name>` Matches all or part of a volume name.
    pub fn filters(mut self, filters: &HashMap<impl Into<String> + Clone, Vec<impl Into<String> + Clone>>) -> Self {
        let mut inner_filters = HashMap::new();
        for (key, value) in filters {
            inner_filters.insert(
                Into::<String>::into(key.clone()),
                value
                    .into_iter()
                    .map(|v| Into::<String>::into(v.clone()))
                    .collect(),
            );
        }
        self.inner.filters = Some(inner_filters);
        self
    }

    /// Consume this builder and use the `ListVolumesOptions` as parameter to the
    /// `VolumeList` API
    pub fn build(self) -> ListVolumesOptions {
        self.inner
    }
}

/// Internal struct used in the `VolumeList` API
/// 
/// Use a [ListVolumesOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ListVolumesOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_as_json")]
    pub filters: Option<HashMap<String, Vec<String>>>, 
}

impl Default for ListVolumesOptions
{
    fn default() -> Self {
        Self {
            filters: None,
        }
    }
}

/// Builder for the `VolumePrune` API query parameter.
///
/// Delete unused volumes.
///
/// ## Examples
///
/// ```rust
/// use bollard_stubs::query_parameters::PruneVolumesOptionsBuilder;
///
/// let params = PruneVolumesOptionsBuilder::new()
/// //  .filters(/* ... */)
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct PruneVolumesOptionsBuilder {
    inner: PruneVolumesOptions,
}

impl PruneVolumesOptionsBuilder {
    /// Construct a builder of query parameters for PruneVolumesOptions using defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters to process on the prune list, encoded as JSON (a `map[string][]string`).
    /// 
    /// Available filters:
    /// - `label` (`label=<key>`, `label=<key>=<value>`, `label!=<key>`, or `label!=<key>=<value>`) Prune volumes with (or without, in case `label!=...` is used) the specified labels.
    /// - `all` (`all=true`) - Consider all (local) volumes for pruning and not just anonymous volumes.
    pub fn filters(mut self, filters: &HashMap<impl Into<String> + Clone, Vec<impl Into<String> + Clone>>) -> Self {
        let mut inner_filters = HashMap::new();
        for (key, value) in filters {
            inner_filters.insert(
                Into::<String>::into(key.clone()),
                value
                    .into_iter()
                    .map(|v| Into::<String>::into(v.clone()))
                    .collect(),
            );
        }
        self.inner.filters = Some(inner_filters);
        self
    }

    /// Consume this builder and use the `PruneVolumesOptions` as parameter to the
    /// `VolumePrune` API
    pub fn build(self) -> PruneVolumesOptions {
        self.inner
    }
}

/// Internal struct used in the `VolumePrune` API
/// 
/// Use a [PruneVolumesOptionsBuilder] to instantiate this struct.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PruneVolumesOptions
{ 
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_as_json")]
    pub filters: Option<HashMap<String, Vec<String>>>, 
}

impl Default for PruneVolumesOptions
{
    fn default() -> Self {
        Self {
            filters: None,
        }
    }
}




// Filtered out: VolumeUpdate
// \"Update a volume. Valid only for Swarm cluster volumes\" 
//   - version

