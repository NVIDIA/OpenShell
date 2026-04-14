//! Plugin API: manage Docker plugins

use super::Docker;
use crate::auth::{DockerCredentials, DockerCredentialsHeader};
use crate::{docker::BodyType, errors::Error};
use bytes::Bytes;
use futures_core::Stream;
use futures_util::StreamExt;
use http::request::Builder;
use http_body_util::Full;
use hyper::Method;

pub use crate::models::*;

impl Docker {
    /// ---
    ///
    /// # List Plugins
    ///
    /// Returns a list of plugins.
    ///
    /// # Arguments
    ///
    ///  - Optional [ListPluginsOptions](crate::query_parameters::ListPluginsOptions) struct.
    ///
    /// # Returns
    ///
    ///  - Vector of [Plugin](Plugin), wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::ListPluginsOptionsBuilder;
    ///
    /// use std::collections::HashMap;
    /// use std::default::Default;
    ///
    /// let mut filters = HashMap::new();
    /// filters.insert("capability", vec!["volumedriver"]);
    ///
    /// let filters: HashMap<String, Vec<String>> = filters.into_iter().map(|(k, v)| (k.to_string(), v.into_iter().map(String::from).collect())).collect();
    /// let options = ListPluginsOptionsBuilder::default()
    ///     .filters(&filters)
    ///     .build();
    ///
    /// docker.list_plugins(Some(options));
    /// ```
    pub async fn list_plugins(
        &self,
        options: Option<crate::query_parameters::ListPluginsOptions>,
    ) -> Result<Vec<Plugin>, Error> {
        let url = "/plugins";

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
    /// # Inspect Plugin
    ///
    /// Inspect a plugin.
    ///
    /// # Arguments
    ///
    ///  - Plugin name as a string slice.
    ///
    /// # Returns
    ///
    ///  - [Plugin](Plugin), wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    ///
    /// docker.inspect_plugin("vieux/sshfs:latest");
    /// ```
    pub async fn inspect_plugin(&self, plugin_name: &str) -> Result<Plugin, Error> {
        let url = format!("/plugins/{plugin_name}/json");

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
    /// # Remove Plugin
    ///
    /// Remove a plugin.
    ///
    /// # Arguments
    ///
    ///  - Plugin name as a string slice.
    ///  - Optional [RemovePluginOptions](crate::query_parameters::RemovePluginOptions) struct.
    ///
    /// # Returns
    ///
    ///  - [Plugin](Plugin), wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::RemovePluginOptionsBuilder;
    ///
    /// let options = RemovePluginOptionsBuilder::default()
    ///     .force(true)
    ///     .build();
    ///
    /// docker.remove_plugin("vieux/sshfs:latest", Some(options));
    /// ```
    pub async fn remove_plugin(
        &self,
        plugin_name: &str,
        options: Option<crate::query_parameters::RemovePluginOptions>,
    ) -> Result<Plugin, Error> {
        let url = format!("/plugins/{plugin_name}");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::DELETE),
            options,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Enable Plugin
    ///
    /// Enable a plugin.
    ///
    /// # Arguments
    ///
    ///  - Plugin name as a string slice.
    ///  - Optional [EnablePluginOptions](crate::query_parameters::EnablePluginOptions) struct.
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
    /// use bollard::query_parameters::EnablePluginOptionsBuilder;
    ///
    /// let options = EnablePluginOptionsBuilder::default()
    ///     .timeout(30)
    ///     .build();
    ///
    /// docker.enable_plugin("vieux/sshfs:latest", Some(options));
    /// ```
    pub async fn enable_plugin(
        &self,
        plugin_name: &str,
        options: Option<crate::query_parameters::EnablePluginOptions>,
    ) -> Result<(), Error> {
        let url = format!("/plugins/{plugin_name}/enable");

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
    /// # Disable Plugin
    ///
    /// Disable a plugin.
    ///
    /// # Arguments
    ///
    ///  - Plugin name as a string slice.
    ///  - Optional [DisablePluginOptions](crate::query_parameters::DisablePluginOptions) struct.
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
    /// use bollard::query_parameters::DisablePluginOptionsBuilder;
    ///
    /// let options = DisablePluginOptionsBuilder::default()
    ///     .force(true)
    ///     .build();
    ///
    /// docker.disable_plugin("vieux/sshfs:latest", Some(options));
    /// ```
    pub async fn disable_plugin(
        &self,
        plugin_name: &str,
        options: Option<crate::query_parameters::DisablePluginOptions>,
    ) -> Result<(), Error> {
        let url = format!("/plugins/{plugin_name}/disable");

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
    /// # Get Plugin Privileges
    ///
    /// Get the list of privileges required by a plugin.
    ///
    /// # Arguments
    ///
    ///  - [GetPluginPrivilegesOptions](crate::query_parameters::GetPluginPrivilegesOptions) struct.
    ///
    /// # Returns
    ///
    ///  - Vector of [PluginPrivilege](PluginPrivilege), wrapped in a Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::GetPluginPrivilegesOptionsBuilder;
    ///
    /// let options = GetPluginPrivilegesOptionsBuilder::default()
    ///     .remote("vieux/sshfs:latest")
    ///     .build();
    ///
    /// docker.get_plugin_privileges(options);
    /// ```
    pub async fn get_plugin_privileges(
        &self,
        options: crate::query_parameters::GetPluginPrivilegesOptions,
    ) -> Result<Vec<PluginPrivilege>, Error> {
        let url = "/plugins/privileges";

        let req = self.build_request(
            url,
            Builder::new().method(Method::GET),
            Some(options),
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Install Plugin
    ///
    /// Pull and install a plugin from a registry. Returns a stream of progress info.
    ///
    /// # Arguments
    ///
    ///  - [InstallPluginOptions](crate::query_parameters::InstallPluginOptions) struct.
    ///  - Vector of [PluginPrivilege](PluginPrivilege) to grant (from [get_plugin_privileges](Docker::get_plugin_privileges)).
    ///  - Optional [Docker Credentials](DockerCredentials) struct for registry authentication.
    ///
    /// # Returns
    ///
    ///  - A Stream of [CreateImageInfo](CreateImageInfo) (contains progress/status/error info).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    /// use bollard::query_parameters::{GetPluginPrivilegesOptionsBuilder, InstallPluginOptionsBuilder};
    /// use futures_util::stream::TryStreamExt;
    ///
    /// # async {
    /// // First get the required privileges
    /// let priv_opts = GetPluginPrivilegesOptionsBuilder::default()
    ///     .remote("vieux/sshfs:latest")
    ///     .build();
    /// let privileges = docker.get_plugin_privileges(priv_opts).await?;
    ///
    /// // Then install with those privileges
    /// let options = InstallPluginOptionsBuilder::default()
    ///     .remote("vieux/sshfs:latest")
    ///     .name("my-sshfs-plugin")
    ///     .build();
    ///
    /// let mut stream = docker.install_plugin(options, privileges, None);
    /// while let Some(info) = stream.try_next().await? {
    ///     println!("{:?}", info);
    /// }
    /// # Ok::<(), bollard::errors::Error>(())
    /// # };
    /// ```
    pub fn install_plugin(
        &self,
        options: crate::query_parameters::InstallPluginOptions,
        privileges: Vec<PluginPrivilege>,
        credentials: Option<DockerCredentials>,
    ) -> impl Stream<Item = Result<CreateImageInfo, Error>> + '_ {
        let url = "/plugins/pull";

        let req = self.build_request_with_registry_auth(
            url,
            Builder::new().method(Method::POST),
            Some(options),
            Docker::serialize_payload(Some(privileges)),
            DockerCredentialsHeader::Auth(credentials),
        );

        self.process_into_stream(req).map(|res| {
            if let Ok(CreateImageInfo {
                error_detail:
                    Some(ErrorDetail {
                        message: Some(error),
                        ..
                    }),
                ..
            }) = res
            {
                Err(Error::DockerStreamError { error })
            } else {
                res
            }
        })
    }

    /// ---
    ///
    /// # Create Plugin
    ///
    /// Create a plugin from a tar archive containing the rootfs and configuration.
    ///
    /// # Arguments
    ///
    ///  - [CreatePluginOptions](crate::query_parameters::CreatePluginOptions) struct.
    ///  - Tar archive body containing the plugin rootfs directory and config.json file.
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
    /// use bollard::query_parameters::CreatePluginOptionsBuilder;
    /// use bollard::body_full;
    ///
    /// use std::fs::File;
    /// use std::io::Read;
    ///
    /// let options = CreatePluginOptionsBuilder::default()
    ///     .name("my-plugin:latest")
    ///     .build();
    ///
    /// let mut file = File::open("plugin.tar.gz").unwrap();
    /// let mut contents = Vec::new();
    /// file.read_to_end(&mut contents).unwrap();
    ///
    /// docker.create_plugin(options, body_full(contents.into()));
    /// ```
    pub async fn create_plugin(
        &self,
        options: crate::query_parameters::CreatePluginOptions,
        tar: BodyType,
    ) -> Result<(), Error> {
        let url = "/plugins/create";

        let req = self.build_request(
            url,
            Builder::new()
                .method(Method::POST)
                .header("Content-Type", "application/x-tar"),
            Some(options),
            Ok(tar),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Upgrade Plugin
    ///
    /// Upgrade an existing plugin to a newer version.
    ///
    /// # Arguments
    ///
    ///  - Plugin name as a string slice.
    ///  - [UpgradePluginOptions](crate::query_parameters::UpgradePluginOptions) struct.
    ///  - Vector of [PluginPrivilege](PluginPrivilege) to grant.
    ///  - Optional [Docker Credentials](DockerCredentials) struct for registry authentication.
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
    /// use bollard::query_parameters::UpgradePluginOptionsBuilder;
    /// use bollard::models::PluginPrivilege;
    ///
    /// let options = UpgradePluginOptionsBuilder::default()
    ///     .remote("vieux/sshfs:next")
    ///     .build();
    ///
    /// let privileges = vec![PluginPrivilege {
    ///     name: Some("network".to_string()),
    ///     description: Some("Allow access to host network".to_string()),
    ///     value: Some(vec!["host".to_string()]),
    /// }];
    ///
    /// docker.upgrade_plugin("vieux/sshfs:latest", options, privileges, None);
    /// ```
    pub async fn upgrade_plugin(
        &self,
        plugin_name: &str,
        options: crate::query_parameters::UpgradePluginOptions,
        privileges: Vec<PluginPrivilege>,
        credentials: Option<DockerCredentials>,
    ) -> Result<(), Error> {
        let url = format!("/plugins/{plugin_name}/upgrade");

        let req = self.build_request_with_registry_auth(
            &url,
            Builder::new().method(Method::POST),
            Some(options),
            Docker::serialize_payload(Some(privileges)),
            DockerCredentialsHeader::Auth(credentials),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Push Plugin
    ///
    /// Push a plugin to a registry.
    ///
    /// # Arguments
    ///
    ///  - Plugin name as a string slice.
    ///  - Optional [Docker Credentials](DockerCredentials) struct for registry authentication.
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
    /// use bollard::auth::DockerCredentials;
    ///
    /// let credentials = Some(DockerCredentials {
    ///     username: Some("my-username".to_string()),
    ///     password: Some("my-password".to_string()),
    ///     ..Default::default()
    /// });
    ///
    /// docker.push_plugin("my-plugin:latest", credentials);
    /// ```
    pub async fn push_plugin(
        &self,
        plugin_name: &str,
        credentials: Option<DockerCredentials>,
    ) -> Result<(), Error> {
        let url = format!("/plugins/{plugin_name}/push");

        let req = self.build_request_with_registry_auth(
            &url,
            Builder::new().method(Method::POST),
            None::<String>,
            Ok(BodyType::Left(Full::new(Bytes::new()))),
            DockerCredentialsHeader::Auth(credentials),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Set Plugin Configuration
    ///
    /// Configure a plugin by setting environment variables or other settings.
    ///
    /// # Arguments
    ///
    ///  - Plugin name as a string slice.
    ///  - Vector of configuration strings in the format "KEY=value".
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
    /// let config = vec![
    ///     "DEBUG=1".to_string(),
    ///     "MAX_CONNECTIONS=1000".to_string(),
    /// ];
    ///
    /// docker.set_plugin_config("vieux/sshfs:latest", config);
    /// ```
    pub async fn set_plugin_config(
        &self,
        plugin_name: &str,
        config: Vec<String>,
    ) -> Result<(), Error> {
        let url = format!("/plugins/{plugin_name}/set");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::POST),
            None::<String>,
            Docker::serialize_payload(Some(config)),
        );

        self.process_into_unit(req).await
    }
}
