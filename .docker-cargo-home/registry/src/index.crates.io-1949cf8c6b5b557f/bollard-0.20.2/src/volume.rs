//! Volume API: Create and manage persistent storage that can be attached to containers.

use bytes::Bytes;
use http::request::Builder;
use http_body_util::Full;
use hyper::Method;

use super::Docker;
use crate::docker::BodyType;
use crate::errors::Error;
use crate::models::*;

impl Docker {
    /// ---
    ///
    /// # List volumes
    ///
    /// # Arguments
    ///
    ///  - [List Volumes Options](crate::query_parameters::ListVolumesOptions) struct.
    ///
    /// # Returns
    ///
    ///  - A [Volume List Response]VolumeListResponse) struct, wrapped in a
    ///    Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    ///
    /// use bollard::query_parameters::ListVolumesOptionsBuilder;
    ///
    /// use std::collections::HashMap;
    ///
    /// let mut filters = HashMap::new();
    /// filters.insert("dangling", vec!("1"));
    ///
    /// let options = ListVolumesOptionsBuilder::default().filters(&filters).build();
    ///
    /// docker.list_volumes(Some(options));
    /// ```
    pub async fn list_volumes(
        &self,
        options: Option<impl Into<crate::query_parameters::ListVolumesOptions>>,
    ) -> Result<VolumeListResponse, Error> {
        let url = "/volumes";

        let req = self.build_request(
            url,
            Builder::new().method(Method::GET),
            options.map(Into::into),
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Create Volume
    ///
    /// Create a new volume.
    ///
    /// # Arguments
    ///
    ///  - [Volume Create Request](VolumeCreateRequest) struct.
    ///
    /// # Returns
    ///
    ///  - A [Volume](Volume) struct, wrapped in a
    ///    Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    ///
    /// use bollard::models::VolumeCreateRequest;
    ///
    /// use std::default::Default;
    ///
    /// let config = VolumeCreateRequest {
    ///     name: Some(String::from("certs")),
    ///     ..Default::default()
    /// };
    ///
    /// docker.create_volume(config);
    /// ```
    pub async fn create_volume(
        &self,
        config: impl Into<VolumeCreateRequest>,
    ) -> Result<Volume, Error> {
        let url = "/volumes/create";

        let req = self.build_request(
            url,
            Builder::new().method(Method::POST),
            None::<String>,
            Docker::serialize_payload(Some(config.into())),
        );

        self.process_into_value(req).await
    }

    /// ---
    ///
    /// # Inspect a Volume
    ///
    /// # Arguments
    ///
    ///  - Volume name as a string slice.
    ///
    /// # Returns
    ///
    ///  - A [Volume](Volume) struct, wrapped in a
    ///    Future.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    ///
    /// docker.inspect_volume("my_volume_name");
    /// ```
    pub async fn inspect_volume(&self, volume_name: &str) -> Result<Volume, Error> {
        let url = format!("/volumes/{volume_name}");

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
    /// # Remove a Volume
    ///
    /// # Arguments
    ///
    ///  - Volume name as a string slice.
    ///
    /// # Arguments
    ///
    ///  - [Remove Volume Options](crate::query_parameters::RemoveVolumeOptions) struct.
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
    /// use bollard::query_parameters::RemoveVolumeOptionsBuilder;
    ///
    /// let options = RemoveVolumeOptionsBuilder::default().force(true).build();
    ///
    /// docker.remove_volume("my_volume_name", Some(options));
    /// ```
    pub async fn remove_volume(
        &self,
        volume_name: &str,
        options: Option<impl Into<crate::query_parameters::RemoveVolumeOptions>>,
    ) -> Result<(), Error> {
        let url = format!("/volumes/{volume_name}");

        let req = self.build_request(
            &url,
            Builder::new().method(Method::DELETE),
            options.map(Into::into),
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_unit(req).await
    }

    /// ---
    ///
    /// # Prune Volumes
    ///
    /// Delete unused volumes.
    ///
    /// # Arguments
    ///
    ///  - A [Prune Volumes Options](crate::query_parameters::PruneVolumesOptions) struct.
    ///
    /// # Returns
    ///
    ///  - A [Volume Prune Response](VolumePruneResponse) struct.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bollard::Docker;
    /// # let docker = Docker::connect_with_http_defaults().unwrap();
    ///
    /// use bollard::query_parameters::PruneVolumesOptionsBuilder;
    ///
    /// use std::collections::HashMap;
    ///
    /// let mut filters = HashMap::new();
    /// filters.insert("label", vec!["maintainer=some_maintainer"]);
    ///
    /// let options = PruneVolumesOptionsBuilder::default().filters(&filters).build();
    ///
    /// docker.prune_volumes(Some(options));
    /// ```
    pub async fn prune_volumes(
        &self,
        options: Option<impl Into<crate::query_parameters::PruneVolumesOptions>>,
    ) -> Result<VolumePruneResponse, Error> {
        let url = "/volumes/prune";

        let req = self.build_request(
            url,
            Builder::new().method(Method::POST),
            options.map(Into::into),
            Ok(BodyType::Left(Full::new(Bytes::new()))),
        );

        self.process_into_value(req).await
    }
}
