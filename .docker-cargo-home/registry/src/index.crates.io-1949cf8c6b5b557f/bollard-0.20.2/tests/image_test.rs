use bytes::BufMut;
use futures_util::future::ready;
use futures_util::stream::{StreamExt, TryStreamExt};
use http_body_util::Full;
use tokio::runtime::Runtime;

use bollard::body_full;
use bollard::errors::Error;
use bollard::models::{ContainerConfig, ContainerCreateBody};
use bollard::query_parameters::{
    BuildImageOptionsBuilder, CommitContainerOptionsBuilder, CreateContainerOptions,
    CreateImageOptionsBuilder, ImportImageOptionsBuilder, ListImagesOptionsBuilder,
    PruneImagesOptionsBuilder, RemoveContainerOptions, RemoveImageOptions,
    RemoveImageOptionsBuilder, SearchImagesOptionsBuilder, StartContainerOptions,
    TagImageOptionsBuilder, WaitContainerOptions,
};
#[cfg(feature = "buildkit")]
use bollard::query_parameters::{BuilderVersion, ImageBuildOutput, PruneBuildOptions};
use bollard::Docker;

use std::collections::HashMap;
use std::default::Default;
use std::fs::{remove_file, File};
use std::io::Write;

#[macro_use]
pub mod common;
use crate::common::*;

async fn create_image_test(docker: Docker) -> Result<(), Error> {
    create_image_hello_world(&docker).await?;

    Ok(())
}

async fn create_image_wasm_test(docker: Docker) -> Result<(), Error> {
    let image = "empty-wasm:latest";

    let options = CreateImageOptionsBuilder::default()
        .from_src("-") // from_src must be "-" when sending the archive in the request body
        .repo(image)
        .build();

    let req_body = bytes::Bytes::from({
        let mut buffer = Vec::new();

        {
            let mut builder = tar::Builder::new(&mut buffer);
            let mut header = tar::Header::new_gnu();
            header.set_path("entrypoint.wasm")?;
            header.set_size(0);
            header.set_cksum();

            builder.append_data(&mut header, "entrypoint.wasm", [].as_slice())?;
            builder.finish()?;
        }

        buffer
    });

    docker
        .create_image(Some(options), Some(body_full(req_body)), None)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, bollard::errors::Error>>()
        .unwrap();

    let result = &docker.inspect_image(image).await?;

    assert!(result.repo_tags.as_ref().unwrap() == [image.to_owned()].as_slice());

    Ok(())
}

async fn search_images_test(docker: Docker) -> Result<(), Error> {
    let result = &docker
        .search_images(
            SearchImagesOptionsBuilder::default()
                .term("hello-world")
                .build(),
        )
        .await?;

    assert!(result
        .iter()
        .any(|api_image| &api_image.name.as_ref().unwrap()[..] == "hello-world"));

    Ok::<_, Error>(())
}

async fn inspect_image_test(docker: Docker) -> Result<(), Error> {
    let image = if cfg!(windows) {
        format!("{}hello-world:nanoserver", registry_http_addr())
    } else {
        format!("{}hello-world:linux", registry_http_addr())
    };

    create_image_hello_world(&docker).await?;

    let result = &docker.inspect_image(&image).await?;

    assert!(result
        .repo_tags
        .as_ref()
        .unwrap()
        .iter()
        .any(|repo_tag| repo_tag == &image));

    Ok(())
}

async fn list_images_test(docker: Docker) -> Result<(), Error> {
    let image = if cfg!(windows) {
        format!("{}hello-world:nanoserver", registry_http_addr())
    } else {
        format!("{}hello-world:linux", registry_http_addr())
    };

    create_image_hello_world(&docker).await?;

    let result = &docker
        .list_images(Some(ListImagesOptionsBuilder::default().all(true).build()))
        .await?;

    assert!(result.iter().any(|api_image| {
        api_image
            .repo_tags
            .iter()
            .any(|repo_tag| repo_tag == &image)
    }));

    Ok(())
}

async fn image_history_test(docker: Docker) -> Result<(), Error> {
    let image = if cfg!(windows) {
        format!("{}hello-world:nanoserver", registry_http_addr())
    } else {
        format!("{}hello-world:linux", registry_http_addr())
    };

    create_image_hello_world(&docker).await?;

    let result = &docker.image_history(&image).await?;

    assert!(result
        .iter()
        .take(1)
        .any(|history| history.tags.iter().any(|tag| tag == &image)));

    Ok(())
}

async fn prune_images_test(docker: Docker) -> Result<(), Error> {
    let mut filters = HashMap::new();
    filters.insert("label", vec!["maintainer=some_maintainer"]);
    let _ = &docker
        .prune_images(Some(
            PruneImagesOptionsBuilder::default()
                .filters(&filters)
                .build(),
        ))
        .await?;

    Ok(())
}

async fn remove_image_test(docker: Docker) -> Result<(), Error> {
    let image = if cfg!(windows) {
        format!("{}hello-world:nanoserver", registry_http_addr())
    } else {
        format!("{}hello-world:linux", registry_http_addr())
    };

    create_image_hello_world(&docker).await?;

    let result = &docker
        .remove_image(
            &image,
            Some(RemoveImageOptionsBuilder::default().noprune(true).build()),
            if cfg!(windows) {
                None
            } else {
                Some(integration_test_registry_credentials())
            },
        )
        .await?;

    assert!(result.iter().any(|s| s
        .untagged
        .as_ref()
        .map(|untagged| untagged == &image)
        .unwrap_or(false)));

    Ok(())
}

async fn commit_container_test(docker: Docker) -> Result<(), Error> {
    let image = if cfg!(windows) {
        format!("{}microsoft/nanoserver", registry_http_addr())
    } else {
        format!("{}alpine", registry_http_addr())
    };

    let cmd: Option<Vec<String>> = if cfg!(windows) {
        Some(
            ["cmd.exe", "/C", "copy", "nul", "bollard.txt"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
    } else {
        Some(
            ["touch", "/bollard.txt"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
    };

    create_image_hello_world(&docker).await?;

    let _ = &docker
        .create_container(
            Some(CreateContainerOptions {
                name: Some("integration_test_commit_container".to_string()),
                ..Default::default()
            }),
            ContainerCreateBody {
                cmd: cmd.clone(),
                image: Some(image.clone()),
                ..Default::default()
            },
        )
        .await?;

    let _ = &docker
        .start_container(
            "integration_test_commit_container",
            None::<StartContainerOptions>,
        )
        .await?;

    let _ = &docker
        .wait_container(
            "integration_test_commit_container",
            None::<WaitContainerOptions>,
        )
        .try_collect::<Vec<_>>()
        .await?;

    let _ = &docker
        .commit_container(
            CommitContainerOptionsBuilder::default()
                .container("integration_test_commit_container")
                .repo("integration_test_commit_container_next")
                .tag("latest")
                .pause(true)
                .build(),
            ContainerConfig {
                ..Default::default()
            },
        )
        .await?;

    let _ = &docker
        .create_container(
            Some(CreateContainerOptions {
                name: Some("integration_test_commit_container_next".to_string()),
                ..Default::default()
            }),
            ContainerCreateBody {
                image: Some("integration_test_commit_container_next".to_string()),
                cmd: if cfg!(windows) {
                    Some(
                        ["cmd.exe", "/C", "dir", "bollard.txt"]
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                    )
                } else {
                    Some(
                        ["ls", "/bollard.txt"]
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                    )
                },
                ..Default::default()
            },
        )
        .await?;

    let _ = &docker
        .start_container(
            "integration_test_commit_container_next",
            None::<StartContainerOptions>,
        )
        .await?;

    let vec = &docker
        .wait_container(
            "integration_test_commit_container_next",
            None::<WaitContainerOptions>,
        )
        .try_collect::<Vec<_>>()
        .await?;

    let first = vec.first().unwrap();
    if let Some(error) = &first.error {
        println!("{}", error.message.as_ref().unwrap());
    }
    assert_eq!(first.status_code, 0);

    let _ = &docker
        .remove_container(
            "integration_test_commit_container_next",
            None::<RemoveContainerOptions>,
        )
        .await?;

    let _ = &docker
        .remove_image(
            "integration_test_commit_container_next",
            None::<RemoveImageOptions>,
            if cfg!(windows) {
                None
            } else {
                Some(integration_test_registry_credentials())
            },
        )
        .await?;

    let _ = &docker
        .remove_container(
            "integration_test_commit_container",
            None::<RemoveContainerOptions>,
        )
        .await?;

    Ok(())
}

async fn build_image_test(docker: Docker, streaming_upload: bool) -> Result<(), Error> {
    let dockerfile = if cfg!(windows) {
        format!(
            "FROM {}microsoft/nanoserver
RUN cmd.exe /C copy nul bollard.txt
",
            registry_http_addr()
        )
    } else {
        format!(
            "FROM {}alpine
RUN touch bollard.txt
",
            registry_http_addr()
        )
    };
    let mut header = tar::Header::new_gnu();
    header.set_path("Dockerfile").unwrap();
    header.set_size(dockerfile.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    let mut tar = tar::Builder::new(Vec::new());
    tar.append(&header, dockerfile.as_bytes()).unwrap();

    let uncompressed = tar.into_inner().unwrap();
    let mut c = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    c.write_all(&uncompressed).unwrap();
    let compressed = c.finish().unwrap();

    let mut creds = HashMap::new();
    creds.insert(
        "localhost:5000".to_string(),
        integration_test_registry_credentials(),
    );

    if streaming_upload {
        let payload = Box::new(compressed).leak();
        let payload = payload.chunks(32);
        let payload = futures_util::stream::iter(payload.map(bytes::Bytes::from));

        let _ = &docker
            .build_image(
                BuildImageOptionsBuilder::default()
                    .dockerfile("Dockerfile")
                    .t("integration_test_build_image")
                    .pull("true")
                    .rm(true)
                    .build(),
                if cfg!(windows) { None } else { Some(creds) },
                Some(bollard::body_stream(payload)),
            )
            .try_collect::<Vec<_>>()
            .await?;
    } else {
        let _ = &docker
            .build_image(
                BuildImageOptionsBuilder::default()
                    .dockerfile("Dockerfile")
                    .t("integration_test_build_image")
                    .pull("true")
                    .rm(true)
                    .build(),
                if cfg!(windows) { None } else { Some(creds) },
                Some(http_body_util::Either::Left(Full::new(compressed.into()))),
            )
            .try_collect::<Vec<_>>()
            .await?;
    }

    let _ = &docker
        .create_container(
            Some(CreateContainerOptions {
                name: Some("integration_test_build_image".to_string()),
                ..Default::default()
            }),
            ContainerCreateBody {
                image: Some("integration_test_build_image".to_string()),
                cmd: if cfg!(windows) {
                    Some(
                        ["cmd.exe", "/C", "dir", "bollard.txt"]
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                    )
                } else {
                    Some(
                        ["ls", "/bollard.txt"]
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                    )
                },
                ..Default::default()
            },
        )
        .await?;

    let _ = &docker
        .start_container(
            "integration_test_build_image",
            None::<StartContainerOptions>,
        )
        .await?;

    let vec = &docker
        .wait_container("integration_test_build_image", None::<WaitContainerOptions>)
        .try_collect::<Vec<_>>()
        .await?;

    let first = vec.first().unwrap();
    if let Some(error) = &first.error {
        println!("{}", error.message.as_ref().unwrap());
    }
    assert_eq!(first.status_code, 0);
    let _ = &docker
        .remove_container(
            "integration_test_build_image",
            None::<RemoveContainerOptions>,
        )
        .await?;

    let _ = &docker
        .remove_image(
            "integration_test_build_image",
            None::<RemoveImageOptions>,
            if cfg!(windows) {
                None
            } else {
                Some(integration_test_registry_credentials())
            },
        )
        .await?;

    Ok(())
}

#[cfg(feature = "buildkit_providerless")]
async fn build_buildkit_image_test(docker: Docker, streaming_upload: bool) -> Result<(), Error> {
    use bollard::body_stream;

    let dockerfile = String::from(
        "FROM localhost:5000/alpine as builder1
RUN touch bollard.txt
FROM localhost:5000/alpine as builder2
RUN --mount=type=bind,from=builder1,target=mnt cp mnt/bollard.txt buildkit-bollard.txt
ENTRYPOINT ls buildkit-bollard.txt
",
    );
    let mut header = tar::Header::new_gnu();
    header.set_path("Dockerfile").unwrap();
    header.set_size(dockerfile.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    let mut tar = tar::Builder::new(Vec::new());
    tar.append(&header, dockerfile.as_bytes()).unwrap();

    let uncompressed = tar.into_inner().unwrap();
    let mut c = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    c.write_all(&uncompressed).unwrap();
    let compressed = c.finish().unwrap();

    let credentials = bollard::auth::DockerCredentials {
        username: Some("bollard".to_string()),
        password: std::env::var("REGISTRY_PASSWORD").ok(),
        ..Default::default()
    };
    let mut creds_hsh = std::collections::HashMap::new();
    creds_hsh.insert("localhost:5000".to_string(), credentials);

    let id = "build_buildkit_image_test";

    let build = if streaming_upload {
        let payload = Box::new(compressed).leak();
        let payload = payload.chunks(32);
        let payload = futures_util::stream::iter(payload.map(bytes::Bytes::from));

        &docker
            .build_image(
                BuildImageOptionsBuilder::default()
                    .dockerfile("Dockerfile")
                    .t("integration_test_build_buildkit_image")
                    .pull("true")
                    .version(BuilderVersion::BuilderBuildKit)
                    .rm(true)
                    .session(id)
                    .build(),
                Some(creds_hsh),
                Some(body_stream(payload)),
            )
            .try_collect::<Vec<bollard::models::BuildInfo>>()
            .await?
    } else {
        &docker
            .build_image(
                BuildImageOptionsBuilder::default()
                    .dockerfile("Dockerfile")
                    .t("integration_test_build_buildkit_image")
                    .pull("true")
                    .version(BuilderVersion::BuilderBuildKit)
                    .rm(true)
                    .session(id)
                    .build(),
                Some(creds_hsh),
                Some(http_body_util::Either::Left(Full::new(compressed.into()))),
            )
            .try_collect::<Vec<bollard::models::BuildInfo>>()
            .await?
    };

    assert!(build
        .iter()
        .flat_map(|build_info| {
            if let Some(aux) = &build_info.aux {
                match aux {
                    bollard::models::BuildInfoAux::BuildKit(res) => Vec::clone(&res.statuses),
                    _ => vec![],
                }
            } else {
                vec![]
            }
        })
        .any(|status| status.id
            == "naming to docker.io/library/integration_test_build_buildkit_image:latest"));

    let _ = &docker
        .create_container(
            Some(CreateContainerOptions {
                name: Some("integration_test_build_buildkit_image".to_string()),
                ..Default::default()
            }),
            ContainerCreateBody {
                image: Some("integration_test_build_buildkit_image".to_string()),
                cmd: Some(
                    ["ls", "/buildkit-bollard.txt"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                ),
                ..Default::default()
            },
        )
        .await?;

    let _ = &docker
        .start_container(
            "integration_test_build_buildkit_image",
            None::<StartContainerOptions>,
        )
        .await?;

    let vec = &docker
        .wait_container(
            "integration_test_build_buildkit_image",
            None::<WaitContainerOptions>,
        )
        .try_collect::<Vec<_>>()
        .await?;

    let first = vec.first().unwrap();
    if let Some(error) = &first.error {
        println!("{}", error.message.as_ref().unwrap());
    }
    assert_eq!(first.status_code, 0);
    let _ = &docker
        .remove_container(
            "integration_test_build_buildkit_image",
            None::<RemoveContainerOptions>,
        )
        .await?;

    let _ = &docker
        .remove_image(
            "integration_test_build_buildkit_image",
            None::<RemoveImageOptions>,
            None,
        )
        .await?;

    Ok(())
}

#[cfg(feature = "buildkit_providerless")]
async fn buildkit_image_missing_session_test(docker: Docker) -> Result<(), Error> {
    let dockerfile = String::from(
        "FROM alpine as builder1
RUN touch bollard.txt
FROM alpine as builder2
RUN --mount=type=bind,from=builder1,target=mnt cp mnt/bollard.txt buildkit-bollard.txt
ENTRYPOINT ls buildkit-bollard.txt
",
    );
    let mut header = tar::Header::new_gnu();
    header.set_path("Dockerfile").unwrap();
    header.set_size(dockerfile.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    let mut tar = tar::Builder::new(Vec::new());
    tar.append(&header, dockerfile.as_bytes()).unwrap();

    let uncompressed = tar.into_inner().unwrap();
    let mut c = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    c.write_all(&uncompressed).unwrap();
    let compressed = c.finish().unwrap();

    let build = &docker
        .build_image(
            BuildImageOptionsBuilder::default()
                .dockerfile("Dockerfile")
                .t("integration_test_build_buildkit_image")
                .pull("true")
                .version(BuilderVersion::BuilderBuildKit)
                .rm(true)
                .build(),
            None,
            Some(http_body_util::Either::Left(Full::new(compressed.into()))),
        )
        .try_collect::<Vec<bollard::models::BuildInfo>>()
        .await;

    assert!(build.is_err());
    let err = build.as_ref().unwrap_err();
    assert!(matches!(err, Error::MissingSessionBuildkitError {}));

    Ok(())
}

#[cfg(feature = "buildkit_providerless")]
async fn build_buildkit_secret_test(docker: Docker) -> Result<(), Error> {
    use bollard::grpc::build::SecretSource;
    use tokio::io::AsyncWriteExt;

    let token = "abcd1234";
    let dockerfile = String::from(
        "FROM localhost:5000/alpine as builder1
RUN --mount=type=secret,id=token cat /run/secrets/token | tee /token
FROM localhost:5000/alpine as builder2
COPY --from=builder1 /token /",
    );

    let mut header = tar::Header::new_gnu();
    header.set_path("Dockerfile").unwrap();
    header.set_size(dockerfile.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    let mut tar = tar::Builder::new(Vec::new());
    tar.append(&header, dockerfile.as_bytes()).unwrap();

    let uncompressed = tar.into_inner().unwrap();
    let mut c = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    c.write_all(&uncompressed).unwrap();
    let compressed = c.finish().unwrap();

    let name = "integration_test_build_buildkit_secret";

    let temp_dir = std::env::temp_dir();
    let temp_path = temp_dir.join("bollard_integration_test_build_buildkit_secret.token");

    let mut temp_file = tokio::fs::File::create(&temp_path).await?;
    temp_file.write_all(token.as_bytes()).await?;

    let secret_source = SecretSource::File(temp_path.clone());
    let frontend_opts = bollard::grpc::build::ImageBuildFrontendOptions::builder()
        .pull(true)
        .set_secret("token", &secret_source)
        .build();

    let driver = bollard::grpc::driver::moby::Moby::new(&docker);

    let load_input =
        bollard::grpc::build::ImageBuildLoadInput::Upload(bytes::Bytes::from(compressed));

    let credentials = bollard::auth::DockerCredentials {
        username: Some("bollard".to_string()),
        password: std::env::var("REGISTRY_PASSWORD").ok(),
        ..Default::default()
    };
    let mut creds_hsh = std::collections::HashMap::new();
    creds_hsh.insert("localhost:5000", credentials);

    let res = bollard::grpc::driver::Build::docker_build(
        driver,
        name,
        frontend_opts,
        load_input,
        Some(creds_hsh),
    )
    .await;

    assert!(res.is_ok());

    let _ = &docker
        .create_container(
            Some(CreateContainerOptions {
                name: Some("integration_test_build_buildkit_secret".to_string()),
                ..Default::default()
            }),
            ContainerCreateBody {
                image: Some("integration_test_build_buildkit_secret".to_string()),
                cmd: Some(["cat", "/token"].iter().map(|s| s.to_string()).collect()),
                ..Default::default()
            },
        )
        .await?;

    let _ = &docker
        .start_container(
            "integration_test_build_buildkit_secret",
            None::<StartContainerOptions>,
        )
        .await?;

    let vec = &docker
        .wait_container(
            "integration_test_build_buildkit_secret",
            None::<WaitContainerOptions>,
        )
        .try_collect::<Vec<_>>()
        .await?;

    let first = vec.first().unwrap();
    if let Some(error) = &first.error {
        println!("{}", error.message.as_ref().unwrap());
    }
    assert_eq!(first.status_code, 0);

    let vec = &docker
        .logs(
            "integration_test_build_buildkit_secret",
            Some(bollard::query_parameters::LogsOptions {
                follow: true,
                stdout: true,
                stderr: false,
                tail: "all".to_string(),
                ..Default::default()
            }),
        )
        .try_collect::<Vec<_>>()
        .await?;

    let value = vec.first().unwrap();

    assert_eq!(format!("{value}"), token.to_string());

    let _ = &docker
        .remove_container(
            "integration_test_build_buildkit_secret",
            None::<RemoveContainerOptions>,
        )
        .await?;

    let _ = &docker
        .remove_image(
            "integration_test_build_buildkit_secret",
            None::<RemoveImageOptions>,
            None,
        )
        .await?;

    tokio::fs::remove_file(temp_path).await?;

    Ok(())
}

#[cfg(feature = "buildkit_providerless")]
async fn build_buildkit_custom_dockerfile_path_test(docker: Docker) -> Result<(), Error> {
    use std::path::PathBuf;

    let dockerfile = String::from(
        "FROM node:alpine as builder1
RUN touch bollard.txt
",
    );
    let custom_dockerfile_path = PathBuf::from("subdirectory/customfile");
    let mut header = tar::Header::new_gnu();
    header.set_path(&custom_dockerfile_path).unwrap();
    header.set_size(dockerfile.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    let mut tar = tar::Builder::new(Vec::new());
    tar.append(&header, dockerfile.as_bytes()).unwrap();

    let uncompressed = tar.into_inner().unwrap();
    let mut c = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    c.write_all(&uncompressed).unwrap();
    let compressed = c.finish().unwrap();

    let name = "integration_test_build_buildkit_custom_dockerfile_path";

    let frontend_opts = bollard::grpc::build::ImageBuildFrontendOptions::builder()
        .pull(true)
        .dockerfile(&custom_dockerfile_path)
        .build();

    let driver = bollard::grpc::driver::moby::Moby::new(&docker);

    let load_input =
        bollard::grpc::build::ImageBuildLoadInput::Upload(bytes::Bytes::from(compressed));

    let credentials = bollard::auth::DockerCredentials {
        username: Some("bollard".to_string()),
        password: std::env::var("REGISTRY_PASSWORD").ok(),
        ..Default::default()
    };
    let mut creds_hsh = std::collections::HashMap::new();
    creds_hsh.insert("localhost:5000", credentials);

    let res = bollard::grpc::driver::Build::docker_build(
        driver,
        name,
        frontend_opts,
        load_input,
        Some(creds_hsh),
    )
    .await;

    assert!(res.is_ok());
    let _ = &docker
        .remove_image(name, None::<RemoveImageOptions>, None)
        .await?;

    Ok(())
}

#[cfg(feature = "buildkit_providerless")]
async fn build_buildkit_named_context_test(docker: Docker) -> Result<(), Error> {
    let base_image = if cfg!(windows) {
        format!("{}hello-world:nanoserver", registry_http_addr())
    } else {
        format!("{}hello-world:linux", registry_http_addr())
    };

    let dockerfile = format!("FROM {base_image}");

    let mut header = tar::Header::new_gnu();
    header.set_path("Dockerfile").unwrap();
    header.set_size(dockerfile.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    let mut tar = tar::Builder::new(Vec::new());
    tar.append(&header, dockerfile.as_bytes()).unwrap();

    let uncompressed = tar.into_inner().unwrap();
    let mut c = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    c.write_all(&uncompressed).unwrap();
    let compressed = c.finish().unwrap();

    let name = "integration_test_build_buildkit_named_context";

    let frontend_opts = bollard::grpc::build::ImageBuildFrontendOptions::builder()
        .named_context(
            &base_image,
            bollard::grpc::build::NamedContext {
                path: String::from("docker-image://localhost:5000/alpine"),
            },
        )
        .build();

    let driver = bollard::grpc::driver::moby::Moby::new(&docker);

    let load_input =
        bollard::grpc::build::ImageBuildLoadInput::Upload(bytes::Bytes::from(compressed));

    let credentials = bollard::auth::DockerCredentials {
        username: Some("bollard".to_string()),
        password: std::env::var("REGISTRY_PASSWORD").ok(),
        ..Default::default()
    };
    let mut creds_hsh = std::collections::HashMap::new();
    creds_hsh.insert("localhost:5000", credentials);

    let res = bollard::grpc::driver::Build::docker_build(
        driver,
        name,
        frontend_opts,
        load_input,
        Some(creds_hsh),
    )
    .await;

    assert!(res.is_ok());

    let _ = &docker
        .create_container(
            Some(CreateContainerOptions {
                name: Some("integration_test_build_buildkit_named_context".to_string()),
                ..Default::default()
            }),
            ContainerCreateBody {
                image: Some("integration_test_build_buildkit_named_context".to_string()),
                cmd: Some(
                    ["cat", "/etc/alpine-release"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                ),
                ..Default::default()
            },
        )
        .await?;

    let _ = &docker
        .start_container(
            "integration_test_build_buildkit_named_context",
            None::<StartContainerOptions>,
        )
        .await?;

    let vec = &docker
        .wait_container(
            "integration_test_build_buildkit_named_context",
            None::<WaitContainerOptions>,
        )
        .try_collect::<Vec<_>>()
        .await?;

    let first = vec.first().unwrap();
    if let Some(error) = &first.error {
        println!("{}", error.message.as_ref().unwrap());
    }
    assert_eq!(first.status_code, 0);

    let _ = &docker
        .remove_container(
            "integration_test_build_buildkit_named_context",
            None::<RemoveContainerOptions>,
        )
        .await?;

    let _ = &docker
        .remove_image(
            "integration_test_build_buildkit_named_context",
            None::<RemoveImageOptions>,
            None,
        )
        .await?;

    Ok(())
}

#[cfg(all(feature = "buildkit", feature = "test_sshforward"))]
async fn build_buildkit_ssh_test(docker: Docker) -> Result<(), Error> {
    let git_host = std::env::var("GIT_HTTP_HOST").unwrap_or_else(|_| "localhost".to_string());
    let git_port = std::env::var("GIT_HTTP_PORT").unwrap_or_else(|_| "2222".to_string());
    let dockerfile = format!(
        "FROM {}alpine as builder1
RUN apk add --no-cache openssh-client git netcat-openbsd
RUN mkdir -p -m 0600 ~/.ssh && ssh-keyscan -t rsa -p {} {} >> ~/.ssh/known_hosts
RUN --mount=type=ssh git clone ssh://git@{}:{}/srv/git/config.git /config
",
        &registry_http_addr(),
        &git_port,
        &git_host,
        &git_host,
        &git_port,
    );

    let mut header = tar::Header::new_gnu();
    header.set_path("Dockerfile").unwrap();
    header.set_size(dockerfile.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    let mut tar = tar::Builder::new(Vec::new());
    tar.append(&header, dockerfile.as_bytes()).unwrap();

    let uncompressed = tar.into_inner().unwrap();
    let mut c = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    c.write_all(&uncompressed).unwrap();
    let compressed = c.finish().unwrap();

    let name = "integration_test_build_buildkit_ssh";

    let frontend_opts = bollard::grpc::build::ImageBuildFrontendOptions::builder()
        .pull(true)
        .extrahost(&bollard::grpc::build::ImageBuildHostIp {
            host: String::from("gitserver"),
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 17, 0, 3)),
        })
        .enable_ssh(true)
        .build();

    let driver = bollard::grpc::driver::moby::Moby::new(&docker);

    let load_input =
        bollard::grpc::build::ImageBuildLoadInput::Upload(bytes::Bytes::from(compressed));

    let credentials = bollard::auth::DockerCredentials {
        username: Some("bollard".to_string()),
        password: std::env::var("REGISTRY_PASSWORD").ok(),
        ..Default::default()
    };
    let mut creds_hsh = std::collections::HashMap::new();
    creds_hsh.insert("localhost:5000", credentials);

    let res = bollard::grpc::driver::Build::docker_build(
        driver,
        name,
        frontend_opts,
        load_input,
        Some(creds_hsh),
    )
    .await;

    assert!(res.is_ok());

    let _ = &docker
        .create_container(
            Some(CreateContainerOptions {
                name: Some("integration_test_build_buildkit_ssh".to_string()),
                ..Default::default()
            }),
            ContainerCreateBody {
                image: Some("integration_test_build_buildkit_ssh".to_string()),
                cmd: Some(["ls", "/config"].iter().map(|s| s.to_string()).collect()),
                ..Default::default()
            },
        )
        .await?;

    let _ = &docker
        .start_container(
            "integration_test_build_buildkit_ssh",
            None::<StartContainerOptions>,
        )
        .await?;

    let vec = &docker
        .wait_container(
            "integration_test_build_buildkit_ssh",
            None::<WaitContainerOptions>,
        )
        .try_collect::<Vec<_>>()
        .await?;

    let first = vec.first().unwrap();
    if let Some(error) = &first.error {
        println!("{}", error.message.as_ref().unwrap());
    }
    assert_eq!(first.status_code, 0);

    let _ = &docker
        .remove_container(
            "integration_test_build_buildkit_ssh",
            None::<RemoveContainerOptions>,
        )
        .await?;

    let _ = &docker
        .remove_image(
            "integration_test_build_buildkit_ssh",
            None::<RemoveImageOptions>,
            None,
        )
        .await?;

    Ok(())
}

#[cfg(feature = "buildkit_providerless")]
async fn build_buildkit_image_inline_driver_test(docker: Docker) -> Result<(), Error> {
    let dockerfile = String::from(
        "FROM localhost:5000/alpine as builder1
RUN touch bollard.txt
FROM localhost:5000/alpine as builder2
RUN --mount=type=bind,from=builder1,target=mnt cp mnt/bollard.txt buildkit-bollard.txt
ENTRYPOINT ls buildkit-bollard.txt
",
    );
    let mut header = tar::Header::new_gnu();
    header.set_path("Dockerfile").unwrap();
    header.set_size(dockerfile.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    let mut tar = tar::Builder::new(Vec::new());
    tar.append(&header, dockerfile.as_bytes()).unwrap();

    let uncompressed = tar.into_inner().unwrap();
    let mut c = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    c.write_all(&uncompressed).unwrap();
    let compressed = c.finish().unwrap();

    let name = "integration_test_build_buildkit_image_inline_driver";

    let credentials = bollard::auth::DockerCredentials {
        username: Some("bollard".to_string()),
        password: std::env::var("REGISTRY_PASSWORD").ok(),
        ..Default::default()
    };
    let mut creds_hsh = std::collections::HashMap::new();
    creds_hsh.insert("localhost:5000".to_string(), credentials);

    let cache_attrs = std::collections::HashMap::new();
    let cache_from = bollard_buildkit_proto::moby::buildkit::v1::CacheOptionsEntry {
        r#type: String::from("inline"),
        attrs: std::collections::HashMap::clone(&cache_attrs),
    };
    let cache_to = bollard_buildkit_proto::moby::buildkit::v1::CacheOptionsEntry {
        r#type: String::from("inline"),
        attrs: cache_attrs,
    };
    let frontend_opts = bollard::grpc::build::ImageBuildFrontendOptions::builder()
        .cachefrom(&cache_from)
        .cacheto(&cache_to)
        .pull(true)
        .build();

    let driver = bollard::grpc::driver::moby::Moby::new(&docker);

    let load_input =
        bollard::grpc::build::ImageBuildLoadInput::Upload(bytes::Bytes::from(compressed));

    let credentials = bollard::auth::DockerCredentials {
        username: Some("bollard".to_string()),
        password: std::env::var("REGISTRY_PASSWORD").ok(),
        ..Default::default()
    };
    let mut creds_hsh = std::collections::HashMap::new();
    creds_hsh.insert("localhost:5000", credentials);

    let res = bollard::grpc::driver::Build::docker_build(
        driver,
        name,
        frontend_opts,
        load_input,
        Some(creds_hsh),
    )
    .await;

    assert!(res.is_ok());

    let _ = &docker
        .create_container(
            Some(CreateContainerOptions {
                name: Some("integration_test_build_buildkit_image_inline_driver".to_string()),
                ..Default::default()
            }),
            ContainerCreateBody {
                image: Some("integration_test_build_buildkit_image_inline_driver".to_string()),
                cmd: Some(
                    ["ls", "/buildkit-bollard.txt"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                ),
                ..Default::default()
            },
        )
        .await?;

    let _ = &docker
        .start_container(
            "integration_test_build_buildkit_image_inline_driver",
            None::<StartContainerOptions>,
        )
        .await?;

    let vec = &docker
        .wait_container(
            "integration_test_build_buildkit_image_inline_driver",
            None::<WaitContainerOptions>,
        )
        .try_collect::<Vec<_>>()
        .await?;

    let first = vec.first().unwrap();
    if let Some(error) = &first.error {
        println!("{}", error.message.as_ref().unwrap());
    }
    assert_eq!(first.status_code, 0);
    let _ = &docker
        .remove_container(
            "integration_test_build_buildkit_image_inline_driver",
            None::<RemoveContainerOptions>,
        )
        .await?;

    let _ = &docker
        .remove_image(
            "integration_test_build_buildkit_image_inline_driver",
            None::<RemoveImageOptions>,
            None,
        )
        .await?;

    Ok(())
}
#[cfg(feature = "buildkit_providerless")]
async fn build_buildkit_image_anonymous_auth_test(docker: Docker) -> Result<(), Error> {
    let dockerfile = String::from(
        "FROM node:alpine as builder1
RUN touch bollard.txt
",
    );
    let mut header = tar::Header::new_gnu();
    header.set_path("Dockerfile").unwrap();
    header.set_size(dockerfile.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    let mut tar = tar::Builder::new(Vec::new());
    tar.append(&header, dockerfile.as_bytes()).unwrap();

    let uncompressed = tar.into_inner().unwrap();
    let mut c = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    c.write_all(&uncompressed).unwrap();
    let compressed = c.finish().unwrap();

    let name = "integration_test_build_buildkit_image_anonymous_auth";

    let frontend_opts = bollard::grpc::build::ImageBuildFrontendOptions::builder()
        .pull(true)
        .build();

    let driver = bollard::grpc::driver::moby::Moby::new(&docker);

    let load_input =
        bollard::grpc::build::ImageBuildLoadInput::Upload(bytes::Bytes::from(compressed));

    let res =
        bollard::grpc::driver::Build::docker_build(driver, name, frontend_opts, load_input, None)
            .await;

    assert!(res.is_ok());
    let _ = &docker
        .remove_image(name, None::<RemoveImageOptions>, None)
        .await?;

    Ok(())
}

#[cfg(feature = "buildkit_providerless")]
async fn build_buildkit_image_outputs_tar_test(docker: Docker) -> Result<(), Error> {
    use std::io::Read;

    let dockerfile = String::from(
        "FROM localhost:5000/alpine as builder
RUN echo hello > message-1.txt
RUN echo world > message-2.txt
FROM scratch as export
COPY --from=builder message-1.txt .
COPY --from=builder message-2.txt .
",
    );
    let mut header = tar::Header::new_gnu();
    header.set_path("Dockerfile").unwrap();
    header.set_size(dockerfile.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    let mut tar = tar::Builder::new(Vec::new());
    tar.append(&header, dockerfile.as_bytes()).unwrap();

    let uncompressed = tar.into_inner().unwrap();
    let mut c = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    c.write_all(&uncompressed).unwrap();
    let compressed = c.finish().unwrap();

    let credentials = bollard::auth::DockerCredentials {
        username: Some("bollard".to_string()),
        password: std::env::var("REGISTRY_PASSWORD").ok(),
        ..Default::default()
    };
    let mut creds_hsh = std::collections::HashMap::new();
    creds_hsh.insert("localhost:5000".to_string(), credentials);

    let dest_path = std::path::Path::new("/tmp/buildkit-outputs.tar");

    // cleanup - usually for local testing, the grpc handler will overwrite
    if dest_path.exists() {
        std::fs::remove_file(dest_path).unwrap();
    }
    assert!(!dest_path.exists());

    let id = "build_buildkit_image_outputs_tar_test";
    let build = &docker
        .build_image(
            BuildImageOptionsBuilder::default()
                .dockerfile("Dockerfile")
                .t("integration_test_build_buildkit_image")
                .pull("true")
                .version(BuilderVersion::BuilderBuildKit)
                .rm(true)
                .session(id)
                .outputs(ImageBuildOutput::Tar(
                    "/tmp/buildkit-outputs.tar".to_string(),
                ))
                .build(),
            Some(creds_hsh),
            Some(http_body_util::Either::Left(Full::new(compressed.into()))),
        )
        .try_collect::<Vec<bollard::models::BuildInfo>>()
        .await?;

    assert!(build
        .iter()
        .flat_map(|build_info| {
            if let Some(aux) = &build_info.aux {
                match aux {
                    bollard::models::BuildInfoAux::BuildKit(res) => Vec::clone(&res.statuses),
                    _ => vec![],
                }
            } else {
                vec![]
            }
        })
        .any(|status| status.id == "sending tarball"));

    assert!(dest_path.exists());

    let export_file = std::fs::File::open(dest_path)?;
    let mut export_archive = tar::Archive::new(export_file);

    let mut results = vec![];

    let iter = export_archive.entries()?;
    for entry in iter {
        let mut entry = entry?;
        let path = entry.path()?.display().to_string();
        let mut content = String::new();
        assert!(entry.read_to_string(&mut content).is_ok());
        results.push((path, content));
    }

    assert_eq!(
        results[0],
        (String::from("message-1.txt"), String::from("hello\n"))
    );
    assert_eq!(
        results[1],
        (String::from("message-2.txt"), String::from("world\n"))
    );

    assert_eq!(results.len(), 2);

    Ok(())
}

#[cfg(feature = "buildkit_providerless")]
async fn build_buildkit_image_outputs_local_test(docker: Docker) -> Result<(), Error> {
    let dockerfile = String::from(
        "FROM localhost:5000/alpine as builder
RUN echo hello > message-1.txt
RUN mkdir subfolder && echo world > subfolder/message-2.txt
RUN touch empty.txt
",
    );
    let mut header = tar::Header::new_gnu();
    header.set_path("Dockerfile").unwrap();
    header.set_size(dockerfile.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    let mut tar = tar::Builder::new(Vec::new());
    tar.append(&header, dockerfile.as_bytes()).unwrap();

    let uncompressed = tar.into_inner().unwrap();
    let mut c = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    c.write_all(&uncompressed).unwrap();
    let compressed = c.finish().unwrap();

    let credentials = bollard::auth::DockerCredentials {
        username: Some("bollard".to_string()),
        password: std::env::var("REGISTRY_PASSWORD").ok(),
        ..Default::default()
    };
    let mut creds_hsh = std::collections::HashMap::new();
    creds_hsh.insert("localhost:5000".to_string(), credentials);

    let dest_path = std::path::Path::new("/tmp/buildkit-outputs");

    // cleanup - usually for local testing, the grpc handler will overwrite
    if dest_path.exists() {
        if dest_path.is_file() {
            std::fs::remove_file(dest_path).unwrap();
        } else {
            std::fs::remove_dir_all(dest_path).unwrap();
        }
    }
    assert!(!dest_path.exists());

    let id = "build_buildkit_image_outputs_local_test";
    let build = &docker
        .build_image(
            BuildImageOptionsBuilder::default()
                .dockerfile("Dockerfile")
                .t("integration_test_build_buildkit_image")
                .pull("true")
                .version(BuilderVersion::BuilderBuildKit)
                .rm(true)
                .session(id)
                .outputs(ImageBuildOutput::Local("/tmp/buildkit-outputs".to_string()))
                .build(),
            Some(creds_hsh),
            Some(http_body_util::Either::Left(Full::new(compressed.into()))),
        )
        .try_collect::<Vec<bollard::models::BuildInfo>>()
        .await?;

    assert!(build
        .iter()
        .flat_map(|build_info| {
            if let Some(aux) = &build_info.aux {
                match aux {
                    bollard::models::BuildInfoAux::BuildKit(res) => Vec::clone(&res.statuses),
                    _ => vec![],
                }
            } else {
                vec![]
            }
        })
        .any(|status| status.id == "copying files"));

    assert_eq!(
        std::fs::read_to_string(dest_path.join("message-1.txt")).unwrap(),
        String::from("hello\n")
    );

    assert_eq!(
        std::fs::read_to_string(dest_path.join("subfolder/message-2.txt")).unwrap(),
        String::from("world\n")
    );

    assert_eq!(
        std::fs::read_to_string(dest_path.join("empty.txt")).unwrap(),
        String::from("")
    );

    Ok(())
}

// Although prune_build can be run without BuildKit enabled, only the BuildKit builder actually
// uses it. The V1 builder caches in the form of intermediate images instead.
#[cfg(feature = "buildkit_providerless")]
async fn prune_build_test(docker: Docker) -> Result<(), Error> {
    use bollard::query_parameters::DataUsageOptions;

    let dockerfile = format!(
        "FROM {}alpine
RUN echo bollard > bollard.txt
",
        registry_http_addr()
    );
    let mut header = tar::Header::new_gnu();
    header.set_path("Dockerfile").unwrap();
    header.set_size(dockerfile.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    let mut tar = tar::Builder::new(Vec::new());
    tar.append(&header, dockerfile.as_bytes()).unwrap();

    let uncompressed = tar.into_inner().unwrap();
    let mut c = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    c.write_all(&uncompressed).unwrap();
    let compressed = c.finish().unwrap();

    let credentials = bollard::auth::DockerCredentials {
        username: Some("bollard".to_string()),
        password: std::env::var("REGISTRY_PASSWORD").ok(),
        ..Default::default()
    };
    let mut creds_hsh = std::collections::HashMap::new();
    creds_hsh.insert("localhost:5000".to_string(), credentials);

    let id = "prune_build_test";

    let _ = &docker
        .build_image(
            BuildImageOptionsBuilder::default()
                .dockerfile("Dockerfile")
                .t("integration_test_prune_build")
                .pull("true")
                .version(BuilderVersion::BuilderBuildKit)
                .rm(true)
                .session(id)
                .build(),
            Some(creds_hsh),
            Some(http_body_util::Either::Left(Full::new(compressed.into()))),
        )
        .try_collect::<Vec<bollard::models::BuildInfo>>()
        .await?;

    // Remove the image before running prune_build since the bytes of bollard.txt are stored in
    // the build cache and shared with the image
    let _ = &docker
        .remove_image(
            "integration_test_prune_build",
            None::<RemoveImageOptions>,
            None,
        )
        .await?;

    let old_cache_size = docker
        .df(None::<DataUsageOptions>)
        .await?
        .build_cache_disk_usage
        .and_then(|data| data.total_size)
        .unwrap_or(0);

    let prune_info = docker.prune_build(None::<PruneBuildOptions>).await?;

    let new_cache_size = docker
        .df(None::<DataUsageOptions>)
        .await?
        .build_cache_disk_usage
        .and_then(|data| data.total_size)
        .unwrap_or(0);

    assert!(old_cache_size >= new_cache_size);
    assert!(prune_info.caches_deleted.is_some());

    Ok(())
}

async fn export_image_test(docker: Docker) -> Result<(), Error> {
    create_image_hello_world(&docker).await?;

    let image = if cfg!(windows) {
        format!("{}hello-world:nanoserver", registry_http_addr())
    } else {
        format!("{}hello-world:linux", registry_http_addr())
    };
    let temp_file = if cfg!(windows) {
        "C:\\Users\\appveyor\\Appdata\\Local\\Temp\\bollard_test_image_export.tar"
    } else {
        "/tmp/bollard_test_image_export.tar"
    };

    let res = docker.export_image(&image);

    let mut archive_file = File::create(temp_file).unwrap();
    // Shouldn't load the whole file into memory, stream it to disk instead
    res.for_each(move |data| {
        archive_file.write_all(&data.unwrap()).unwrap();
        archive_file.sync_all().unwrap();
        ready(())
    })
    .await;

    // assert that the file containg the exported archive actually exists
    let test_file = File::open(temp_file).unwrap();
    // and metadata can be read
    test_file.metadata().unwrap();

    // And delete it to clean up
    remove_file(temp_file).unwrap();
    Ok(())
}

async fn export_images_test(docker: Docker) -> Result<(), Error> {
    // pull from registry
    create_image_hello_world(&docker).await?;

    let repo = format!("{}hello-world", registry_http_addr());
    let image = format!("{repo}:linux");

    docker
        .tag_image(
            &image,
            Some(
                TagImageOptionsBuilder::default()
                    .repo(repo.as_ref())
                    .tag("mycopy")
                    .build(),
            ),
        )
        .await?;

    let copy = format!("{repo}:mycopy");
    let images = vec![image.as_ref(), copy.as_ref()];
    let res = docker.export_images(&images);

    let temp_file = "/tmp/bollard_test_images_export.tar";
    let mut archive_file = File::create(temp_file).unwrap();
    // Shouldn't load the whole file into memory, stream it to disk instead
    res.for_each(move |data| {
        archive_file.write_all(&data.unwrap()).unwrap();
        archive_file.sync_all().unwrap();
        ready(())
    })
    .await;

    // assert that the file containing the exported archive actually exists
    let test_file = File::open(temp_file).unwrap();
    // and metadata can be read
    test_file.metadata().unwrap();

    // And delete it to clean up
    remove_file(temp_file).unwrap();
    Ok(())
}

async fn issue_55_test(docker: Docker) -> Result<(), Error> {
    let dockerfile = "FROM ubuntu:24.04
RUN apt-get update && \
    apt-get install -y \
        build-essential \
        cmake \
        curl \
        file \
        git \
        graphviz \
        musl-dev \
        musl-tools \
        libpq-dev \
        libsqlite3-dev \
        libssl-dev \
        linux-libc-dev \
        pkgconf \
        sudo \
        xutils-dev \
        gcc-13-arm-linux-gnueabihf \
        && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
";
    let mut header = tar::Header::new_gnu();
    header.set_path("Dockerfile").unwrap();
    header.set_size(dockerfile.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    let mut tar = tar::Builder::new(Vec::new());
    tar.append(&header, dockerfile.as_bytes()).unwrap();

    let uncompressed = tar.into_inner().unwrap();
    let mut c = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    c.write_all(&uncompressed).unwrap();
    let compressed = c.finish().unwrap();

    let mut stream = docker.build_image(
        BuildImageOptionsBuilder::default()
            .dockerfile("Dockerfile")
            .t("issue_55")
            .pull("true")
            .rm(true)
            .build(),
        None,
        Some(http_body_util::Either::Left(Full::new(compressed.into()))),
    );

    while let Some(update) = stream.next().await {
        assert!(update.is_ok());
    }

    Ok(())
}

async fn import_image_test(docker: Docker) -> Result<(), Error> {
    // round-trip test
    create_image_hello_world(&docker).await?;

    let image = if cfg!(windows) {
        format!("{}hello-world:nanoserver", registry_http_addr())
    } else {
        format!("{}hello-world:linux", registry_http_addr())
    };

    let mut res = docker.export_image(&image);

    let mut buf = bytes::BytesMut::new();
    while let Some(data) = res.next().await {
        buf.put_slice(&data.unwrap());
    }

    let mut creds = HashMap::new();
    creds.insert(
        "localhost:5000".to_string(),
        integration_test_registry_credentials(),
    );

    docker
        .import_image(
            ImportImageOptionsBuilder::default().build(),
            body_full(buf.freeze()),
            Some(creds),
        )
        .try_collect::<Vec<_>>()
        .await?;

    Ok(())
}

async fn import_image_test_stream(docker: Docker) -> Result<(), Error> {
    // round-trip test
    create_image_hello_world(&docker).await?;

    let image = if cfg!(windows) {
        format!("{}hello-world:nanoserver", registry_http_addr())
    } else {
        format!("{}hello-world:linux", registry_http_addr())
    };

    let res = docker.export_image(&image);

    let mut creds = HashMap::new();
    creds.insert(
        "localhost:5000".to_string(),
        integration_test_registry_credentials(),
    );

    docker
        .import_image_stream(
            ImportImageOptionsBuilder::default().build(),
            res,
            Some(creds),
        )
        .try_collect::<Vec<_>>()
        .await?;

    Ok(())
}

// ND - Test sometimes hangs on appveyor.
#[cfg(not(windows))]
#[test]
fn integration_test_search_images() {
    connect_to_docker_and_run!(search_images_test);
}

#[test]
fn integration_test_create_image() {
    connect_to_docker_and_run!(create_image_test);
}

#[test]
#[cfg(unix)]
fn integration_test_create_image_wasm() {
    connect_to_docker_and_run!(create_image_wasm_test);
}

#[test]
// ND - Test sometimes hangs on appveyor.
#[cfg(not(windows))]
fn integration_test_inspect_image() {
    connect_to_docker_and_run!(inspect_image_test);
}

#[test]
// ND - Test sometimes hangs on appveyor.
#[cfg(not(windows))]
fn integration_test_images_list() {
    connect_to_docker_and_run!(list_images_test);
}

#[test]
fn integration_test_image_history() {
    connect_to_docker_and_run!(image_history_test);
}

#[test]
fn integration_test_prune_images() {
    connect_to_docker_and_run!(prune_images_test);
}

#[test]
// ND - Test sometimes hangs on appveyor.
#[cfg(not(windows))]
fn integration_test_remove_image() {
    connect_to_docker_and_run!(remove_image_test);
}

#[test]
fn integration_test_commit_container() {
    connect_to_docker_and_run!(commit_container_test);
}

#[test]
fn integration_test_build_image() {
    connect_to_docker_and_run!(|docker| build_image_test(docker, false));
    connect_to_docker_and_run!(|docker| build_image_test(docker, true));
}

#[test]
#[cfg(feature = "buildkit_providerless")]
fn integration_test_build_buildkit_image() {
    connect_to_docker_and_run!(|docker| build_buildkit_image_test(docker, false));
    connect_to_docker_and_run!(|docker| build_buildkit_image_test(docker, true));
}

#[test]
#[cfg(feature = "buildkit_providerless")]
fn integration_test_buildkit_image_missing_session_test() {
    connect_to_docker_and_run!(buildkit_image_missing_session_test);
}

#[test]
#[cfg(feature = "buildkit_providerless")]
fn integration_test_build_buildkit_secret() {
    connect_to_docker_and_run!(build_buildkit_secret_test);
}

#[test]
#[cfg(feature = "buildkit_providerless")]
fn integration_test_build_buildkit_custom_dockerfile_path() {
    connect_to_docker_and_run!(build_buildkit_custom_dockerfile_path_test);
}

#[test]
#[cfg(feature = "buildkit_providerless")]
fn integration_test_build_buildkit_named_context() {
    connect_to_docker_and_run!(build_buildkit_named_context_test);
}

#[test]
#[cfg(all(feature = "buildkit", feature = "test_sshforward"))]
fn integration_test_build_buildkit_ssh() {
    connect_to_docker_and_run!(build_buildkit_ssh_test);
}

#[test]
#[cfg(feature = "buildkit_providerless")]
fn integration_test_build_buildkit_inline_driver() {
    connect_to_docker_and_run!(build_buildkit_image_inline_driver_test);
}

#[test]
#[cfg(feature = "buildkit_providerless")]
fn integration_test_build_buildkit_anonymous_auth() {
    connect_to_docker_and_run!(build_buildkit_image_anonymous_auth_test);
}

#[test]
#[cfg(feature = "buildkit_providerless")]
fn integration_test_build_buildkit_image_outputs_tar() {
    connect_to_docker_and_run!(build_buildkit_image_outputs_tar_test);
}

#[test]
#[cfg(feature = "buildkit_providerless")]
fn integration_test_build_buildkit_image_outputs_local() {
    connect_to_docker_and_run!(build_buildkit_image_outputs_local_test);
}

#[test]
#[cfg(feature = "buildkit_providerless")]
fn integration_test_prune_build() {
    connect_to_docker_and_run!(prune_build_test);
}

#[test]
#[cfg(unix)]
fn integration_test_export_image() {
    connect_to_docker_and_run!(export_image_test);
}

#[test]
#[cfg(unix)]
fn integration_test_export_images() {
    connect_to_docker_and_run!(export_images_test);
}

#[test]
#[cfg(unix)]
// Flaky
#[ignore]
fn integration_test_issue_55() {
    connect_to_docker_and_run!(issue_55_test);
}

#[test]
#[cfg(unix)]
fn integration_test_import_image() {
    connect_to_docker_and_run!(import_image_test);
}

#[test]
#[cfg(unix)]
fn integration_test_import_image_stream() {
    connect_to_docker_and_run!(import_image_test_stream);
}
