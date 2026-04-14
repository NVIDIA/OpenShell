#![type_length_limit = "2097152"]

use bollard::container::AttachContainerResults;
#[cfg(feature = "test_checkpoint")]
use bollard::container::{
    CreateCheckpointOptions, DeleteCheckpointOptions, ListCheckpointsOptions,
};
use bollard::errors::Error;
#[cfg(feature = "test_checkpoint")]
use bollard::query_parameters::RemoveContainerOptionsBuilder;
use bollard::query_parameters::{
    AttachContainerOptionsBuilder, ContainerArchiveInfoOptionsBuilder, CreateImageOptionsBuilder,
    DownloadFromContainerOptionsBuilder, KillContainerOptionsBuilder, ListContainersOptionsBuilder,
    LogsOptionsBuilder, PushImageOptionsBuilder, RenameContainerOptionsBuilder,
    ResizeContainerTTYOptionsBuilder, StatsOptionsBuilder, TagImageOptionsBuilder,
    TopOptionsBuilder, UploadToContainerOptionsBuilder,
};
use bollard::{body_full, Docker};
use bollard::{body_stream, models::*};

use futures_util::future::ready;
use futures_util::stream::TryStreamExt;
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;
use tokio::runtime::Runtime;

use std::fs::{remove_file, File};
use std::io::Write;

#[macro_use]
pub mod common;
use crate::common::*;

async fn list_containers_test(docker: Docker) -> Result<(), Error> {
    let image = if cfg!(windows) {
        format!("{}hello-world:nanoserver", registry_http_addr())
    } else {
        format!("{}hello-world:linux", registry_http_addr())
    };

    create_container_hello_world(&docker, "integration_test_list_containers").await?;
    let result = &docker
        .list_containers(Some(ListContainersOptionsBuilder::new().all(true).build()))
        .await?;

    assert_ne!(0, result.len());
    assert!(result
        .iter()
        .any(|container| container.image.as_ref().unwrap() == &image));

    let _ = &docker
        .remove_container("integration_test_list_containers", None)
        .await?;

    Ok(())
}

async fn image_push_test(docker: Docker) -> Result<(), Error> {
    let image = if cfg!(windows) {
        format!("{}hello-world:nanoserver", registry_http_addr())
    } else {
        format!("{}hello-world:linux", registry_http_addr())
    };

    let _ = &docker
        .create_image(
            Some(
                CreateImageOptionsBuilder::default()
                    .from_image(&image)
                    .build(),
            ),
            None,
            if cfg!(windows) {
                None
            } else {
                Some(integration_test_registry_credentials())
            },
        )
        .try_collect::<Vec<_>>()
        .await?;

    let _ = &docker
        .tag_image(
            &image,
            Some(
                TagImageOptionsBuilder::default()
                    .repo(&format!("{}my-hello-world", registry_http_addr()))
                    .build(),
            ),
        )
        .await?;

    let _ = &docker
        .push_image(
            format!("{}my-hello-world", registry_http_addr()).as_ref(),
            Some(PushImageOptionsBuilder::default().build()),
            if cfg!(windows) {
                None
            } else {
                Some(integration_test_registry_credentials())
            },
        )
        .try_collect::<Vec<_>>()
        .await?;

    let new_image_url = format!("{}my-hello-world", registry_http_addr());
    let _ = &docker
        .create_image(
            Some(
                CreateImageOptionsBuilder::default()
                    .from_image(&new_image_url)
                    .build(),
            ),
            None,
            if cfg!(windows) {
                None
            } else {
                Some(integration_test_registry_credentials())
            },
        )
        .try_collect::<Vec<_>>()
        .await?;

    Ok(())
}

async fn container_restart_test(docker: Docker) -> Result<(), Error> {
    create_daemon(&docker, "integration_test_restart_container").await?;

    let result = &docker
        .inspect_container("integration_test_restart_container", None)
        .await?;

    let started_at = result.state.as_ref().unwrap().started_at.as_ref();

    let _ = &docker
        .restart_container("integration_test_restart_container", None)
        .await?;
    let result = &docker
        .inspect_container("integration_test_restart_container", None)
        .await?;

    assert_ne!(
        started_at,
        result.state.as_ref().unwrap().started_at.as_ref()
    );
    kill_container(&docker, "integration_test_restart_container").await?;

    Ok(())
}

async fn top_processes_test(docker: Docker) -> Result<(), Error> {
    let top_options = if cfg!(windows) {
        None
    } else {
        Some(TopOptionsBuilder::default().ps_args("aux").build())
    };

    create_daemon(&docker, "integration_test_top_processes").await?;

    let result = &docker
        .top_processes("integration_test_top_processes", top_options)
        .await?;

    assert_ne!(result.titles.as_ref().unwrap()[0].len(), 0);
    kill_container(&docker, "integration_test_top_processes").await?;

    Ok(())
}

async fn logs_test(docker: Docker) -> Result<(), Error> {
    create_container_hello_world(&docker, "integration_test_logs").await?;

    // for some reason on windows, even though we start the container,
    // wait until it finishes, the API request for logs seems to be flaky
    // on the first request.
    #[cfg(windows)]
    &docker
        .logs(
            "integration_test_logs",
            Some(
                LogsOptionsBuilder::default()
                    .follow(true)
                    .stdout(true)
                    .stderr(false)
                    .tail("all")
                    .build(),
            ),
        )
        .try_collect::<Vec<_>>()
        .await?;

    let vec = &docker
        .logs(
            "integration_test_logs",
            Some(
                LogsOptionsBuilder::default()
                    .follow(true)
                    .stdout(true)
                    .stderr(false)
                    .tail("all")
                    .build(),
            ),
        )
        .try_collect::<Vec<_>>()
        .await?;

    let value = vec.get(1).unwrap();

    assert_eq!(format!("{value}"), "Hello from Docker!\n".to_string());

    let _ = &docker
        .remove_container("integration_test_logs", None)
        .await?;

    Ok(())
}

async fn container_changes_test(docker: Docker) -> Result<(), Error> {
    create_container_hello_world(&docker, "integration_test_container_changes").await?;

    let result = &docker
        .container_changes("integration_test_container_changes")
        .await?;

    if cfg!(windows) {
        assert_ne!(result.as_ref().unwrap().len(), 0)
    } else {
        assert!(result.is_none())
    };

    let _ = &docker
        .remove_container("integration_test_container_changes", None)
        .await?;

    Ok(())
}

async fn stats_test(docker: Docker) -> Result<(), Error> {
    create_daemon(&docker, "integration_test_stats").await?;

    let vec = &docker
        .stats(
            "integration_test_stats",
            Some(StatsOptionsBuilder::default().stream(false).build()),
        )
        .try_collect::<Vec<_>>()
        .await?;

    let value = vec.first();

    assert_eq!(
        value.unwrap().name,
        Some("/integration_test_stats".to_string())
    );
    kill_container(&docker, "integration_test_stats")
        .await
        .unwrap_or(());

    Ok(())
}

async fn kill_container_test(docker: Docker) -> Result<(), Error> {
    let kill_options = Some(
        KillContainerOptionsBuilder::default()
            .signal("SIGKILL")
            .build(),
    );

    create_daemon(&docker, "integration_test_kill_container").await?;

    let _ = &docker
        .kill_container("integration_test_kill_container", kill_options)
        .await?;
    let _ = &docker
        .remove_container("integration_test_kill_container", None)
        .await?;

    Ok(())
}

async fn attach_container_test(docker: Docker) -> Result<(), Error> {
    create_shell_daemon(&docker, "integration_test_attach_container").await?;

    let unique_string = "bollard_unique_string";
    let AttachContainerResults { output, mut input } = docker
        .attach_container(
            "integration_test_attach_container",
            Some(
                AttachContainerOptionsBuilder::default()
                    .stream(true)
                    .stdout(true)
                    .stdin(true)
                    .build(),
            ),
        )
        .await?;

    input
        .write_all(format!("echo {unique_string}\n").as_bytes())
        .await?;
    input.write_all("exit\n".as_bytes()).await?;

    let log = match tokio::time::timeout(tokio::time::Duration::from_secs(2), output.try_collect())
        .await
    {
        Ok(res) => res?,
        Err(_) => {
            docker
                .kill_container("integration_test_attach_container", None)
                .await?;
            vec![]
        }
    };

    let _ = &docker
        .wait_container("integration_test_attach_container", None)
        .try_collect::<Vec<_>>()
        .await?;

    let _ = &docker
        .remove_container("integration_test_attach_container", None)
        .await?;

    let input_found = log
        .iter()
        .any(|val| val.to_string().contains(unique_string));

    assert!(input_found);

    Ok(())
}

async fn resize_container_test(docker: Docker) -> Result<(), Error> {
    create_shell_daemon(&docker, "integration_test_resize_container_tty").await?;

    docker
        .resize_container_tty(
            "integration_test_resize_container_tty",
            ResizeContainerTTYOptionsBuilder::default()
                .w(50)
                .h(50)
                .build(),
        )
        .await?;

    let _ = &docker
        .kill_container("integration_test_resize_container_tty", None)
        .await?;

    let _ = &docker
        .wait_container("integration_test_resize_container_tty", None)
        .try_collect::<Vec<_>>()
        .await;

    let _ = &docker
        .remove_container("integration_test_resize_container_tty", None)
        .await?;

    Ok(())
}

async fn update_container_test(docker: Docker) -> Result<(), Error> {
    let update_options = ContainerUpdateBody {
        memory: Some(314572800),
        memory_swap: Some(314572800),
        restart_policy: Some(RestartPolicy {
            name: Some(RestartPolicyNameEnum::ON_FAILURE),
            maximum_retry_count: Some(3),
        }),
        ..Default::default()
    };

    create_daemon(&docker, "integration_test_update_container").await?;
    let _ = &docker
        .update_container("integration_test_update_container", update_options)
        .await?;
    let result = &docker
        .inspect_container("integration_test_update_container", None)
        .await?;

    assert_eq!(
        314572800,
        result.host_config.as_ref().unwrap().memory.unwrap()
    );

    let _ = &docker
        .kill_container("integration_test_update_container", None)
        .await?;

    let _ = &docker
        .wait_container("integration_test_update_container", None)
        .try_collect::<Vec<_>>()
        .await;

    let result = &docker
        .inspect_container("integration_test_update_container", None)
        .await?;

    assert_eq!(
        ContainerStateStatusEnum::EXITED,
        result.state.as_ref().unwrap().status.unwrap()
    );

    let _ = &docker
        .remove_container("integration_test_update_container", None)
        .await?;

    Ok(())
}

async fn rename_container_test(docker: Docker) -> Result<(), Error> {
    create_container_hello_world(&docker, "integration_test_rename_container").await?;
    let _ = &docker
        .rename_container(
            "integration_test_rename_container",
            RenameContainerOptionsBuilder::default()
                .name("integration_test_rename_container_renamed")
                .build(),
        )
        .await?;

    let _ = &docker
        .remove_container("integration_test_rename_container_renamed", None)
        .await?;

    Ok(())
}

async fn pause_container_test(docker: Docker) -> Result<(), Error> {
    create_daemon(&docker, "integration_test_pause_container").await?;

    let _ = &docker
        .pause_container("integration_test_pause_container")
        .await?;

    let result = &docker
        .inspect_container("integration_test_pause_container", None)
        .await?;

    assert_eq!(
        ContainerStateStatusEnum::PAUSED,
        result.state.as_ref().unwrap().status.unwrap()
    );

    let _ = &docker
        .unpause_container("integration_test_pause_container")
        .await?;

    let result = &docker
        .inspect_container("integration_test_pause_container", None)
        .await?;

    assert_eq!(
        ContainerStateStatusEnum::RUNNING,
        result.state.as_ref().unwrap().status.unwrap()
    );

    kill_container(&docker, "integration_test_pause_container").await?;

    Ok(())
}

async fn prune_containers_test(docker: Docker) -> Result<(), Error> {
    let _ = &docker.prune_containers(None).await?;

    let result = &docker
        .list_containers(Some(
            ListContainersOptionsBuilder::default().all(true).build(),
        ))
        .await?;

    assert_eq!(
        0,
        result
            .iter()
            .filter(|r| vec![
                "bollard",
                "registry:2",
                "stefanscherer/registry-windows",
                "moby/buildkit:master",
                // Containers existing on CircleCI after a prune
                "docker.io/library/docker:27.3",
                "public.ecr.aws/eks-distro/kubernetes/pause:3.6"
            ]
            .into_iter()
            .all(|v| v != r.image.as_ref().unwrap()))
            .count()
    );

    Ok(())
}

async fn archive_container_test(docker: Docker, streaming_upload: bool) -> Result<(), Error> {
    let image = if cfg!(windows) {
        format!("{}microsoft/nanoserver", registry_http_addr())
    } else {
        format!("{}alpine", registry_http_addr())
    };

    let readme = r#"Hello from Bollard!"#.as_bytes();

    let mut header = tar::Header::new_gnu();
    header.set_path("readme.txt").unwrap();
    header.set_size(readme.len() as u64);
    header.set_mode(0o744);
    header.set_cksum();
    let mut tar = tar::Builder::new(Vec::new());
    tar.append(&header, readme).unwrap();

    let uncompressed = tar.into_inner().unwrap();
    let mut c = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    c.write_all(&uncompressed).unwrap();
    let payload = c.finish().unwrap();

    let _ = &docker
        .create_image(
            Some(
                CreateImageOptionsBuilder::default()
                    .from_image(&image)
                    .build(),
            ),
            None,
            if cfg!(windows) {
                None
            } else {
                Some(integration_test_registry_credentials())
            },
        )
        .try_collect::<Vec<_>>()
        .await?;

    let _ = &docker
        .create_container(
            Some(
                bollard::query_parameters::CreateContainerOptionsBuilder::default()
                    .name("integration_test_archive_container")
                    .build(),
            ),
            ContainerCreateBody {
                image: Some(image.to_owned()),
                ..Default::default()
            },
        )
        .await?;

    if streaming_upload {
        // Make payload live for the lifetime of the test and convert it to an async Bytes stream.
        // Normally you would use an existing async stream.
        let payload = Box::new(payload).leak();
        let payload = payload.chunks(32);
        let payload = futures_util::stream::iter(payload.map(bytes::Bytes::from));

        let _ = &docker
            .upload_to_container(
                "integration_test_archive_container",
                Some(
                    UploadToContainerOptionsBuilder::default()
                        .path(if cfg!(windows) {
                            "C:\\Windows\\Logs"
                        } else {
                            "/tmp"
                        })
                        .build(),
                ),
                body_stream(payload),
            )
            .await?;
    } else {
        let _ = &docker
            .upload_to_container(
                "integration_test_archive_container",
                Some(
                    UploadToContainerOptionsBuilder::default()
                        .path(if cfg!(windows) {
                            "C:\\Windows\\Logs"
                        } else {
                            "/tmp"
                        })
                        .build(),
                ),
                body_full(payload.into()),
            )
            .await?;
    }
    let res = docker
        .get_container_archive_info(
            "integration_test_archive_container",
            Some(
                ContainerArchiveInfoOptionsBuilder::default()
                    .path(if cfg!(windows) {
                        "C:\\Windows\\Logs\\"
                    } else {
                        "/tmp"
                    })
                    .build(),
            ),
        )
        .await?;

    assert_eq!(res.name, if cfg!(windows) { "Logs" } else { "tmp" });

    let res = docker.download_from_container(
        "integration_test_archive_container",
        Some(
            DownloadFromContainerOptionsBuilder::default()
                .path(if cfg!(windows) {
                    "C:\\Windows\\Logs\\"
                } else {
                    "/tmp"
                })
                .build(),
        ),
    );

    let bytes = concat_byte_stream(res).await?;

    let mut a: tar::Archive<&[u8]> = tar::Archive::new(&bytes[..]);

    use std::io::Read;
    let files: Vec<String> = a
        .entries()
        .unwrap()
        .map(|file| file.unwrap())
        .filter(|file| {
            let path = file.header().path().unwrap();
            println!("{path:?}");
            if path
                == std::path::Path::new(if cfg!(windows) {
                    "Logs/readme.txt"
                } else {
                    "tmp/readme.txt"
                })
            {
                return true;
            }
            false
        })
        .map(|mut r| {
            let mut s = String::new();
            r.read_to_string(&mut s).unwrap();
            s
        })
        .collect();

    assert_eq!(1, files.len());

    assert_eq!("Hello from Bollard!", files.first().unwrap());

    let _ = &docker
        .remove_container("integration_test_archive_container", None)
        .await?;

    Ok(())
}

async fn inspect_container_test(docker: Docker) -> Result<(), Error> {
    create_daemon(&docker, "integration_test_inspect_container").await?;
    let result = &docker
        .inspect_container("integration_test_inspect_container", None)
        .await?;

    assert_eq!(None, result.host_config.as_ref().unwrap().cap_add);

    // Just verify we can read the config directly
    let config = result.config.as_ref().unwrap();

    assert!(config.image.is_some());

    kill_container(&docker, "integration_test_inspect_container").await?;

    Ok(())
}

async fn mount_volume_container_test(docker: Docker) -> Result<(), Error> {
    let image = if cfg!(windows) {
        format!("{}microsoft/nanoserver", registry_http_addr())
    } else {
        format!("{}alpine", registry_http_addr())
    };

    let mut port_bindings = ::std::collections::HashMap::new();
    port_bindings.insert(
        String::from("443/tcp"),
        Some(vec![PortBinding {
            host_ip: Some(String::from("127.0.0.1")),
            host_port: Some(String::from("4443")),
        }]),
    );

    let host_config = HostConfig {
        mounts: Some(vec![Mount {
            target: Some(if cfg!(windows) {
                String::from("C:\\Windows\\Temp")
            } else {
                String::from("/tmp")
            }),
            source: Some(if cfg!(windows) {
                String::from("C:\\Windows\\Temp")
            } else {
                String::from("/tmp")
            }),
            typ: Some(MountTypeEnum::BIND),
            consistency: Some(String::from("default")),
            ..Default::default()
        }]),
        port_bindings: Some(port_bindings),
        ..Default::default()
    };

    let _ = &docker.create_image(
        Some(
            CreateImageOptionsBuilder::default()
                .from_image(&image)
                .build(),
        ),
        None,
        if cfg!(windows) {
            None
        } else {
            Some(integration_test_registry_credentials())
        },
    );

    let _ = &docker
        .create_container(
            Some(
                bollard::query_parameters::CreateContainerOptionsBuilder::default()
                    .name("integration_test_mount_volume_container")
                    .build(),
            ),
            ContainerCreateBody {
                image: Some(image.clone()),
                host_config: Some(host_config),
                exposed_ports: Some(vec!["8080".to_string()]),
                ..Default::default()
            },
        )
        .await?;

    let result = &docker
        .inspect_container("integration_test_mount_volume_container", None)
        .await?;

    println!("{:?}", result.host_config);

    assert_eq!(
        if cfg!(windows) {
            "C:\\Windows\\Temp"
        } else {
            "/tmp"
        },
        result
            .host_config
            .as_ref()
            .unwrap()
            .mounts
            .as_ref()
            .unwrap()
            .first()
            .unwrap()
            .target
            .as_ref()
            .unwrap()
    );

    assert_eq!(
        "4443",
        result
            .host_config
            .as_ref()
            .unwrap()
            .port_bindings
            .as_ref()
            .unwrap()
            .get("443/tcp")
            .unwrap()
            .as_ref()
            .unwrap()
            .first()
            .unwrap()
            .host_port
            .as_ref()
            .unwrap()
    );

    println!("{:?}", result.config);

    assert!(result
        .config
        .as_ref()
        .unwrap()
        .exposed_ports
        .as_ref()
        .unwrap()
        .contains(&"8080".to_string()));

    let _ = &docker
        .remove_container("integration_test_mount_volume_container", None)
        .await?;

    Ok(())
}

async fn export_container_test(docker: Docker) -> Result<(), Error> {
    create_image_hello_world(&docker).await?;

    let temp_file = if cfg!(windows) {
        "C:\\Users\\appveyor\\Appdata\\Local\\Temp\\bollard_test_container_export.tar"
    } else {
        "/tmp/bollard_test_container_export.tar"
    };

    create_container_hello_world(&docker, "integration_test_export_container").await?;
    let res = docker.export_container("integration_test_export_container");

    let mut archive_file = File::create(temp_file).unwrap();
    // Shouldn't load the whole file into memory, stream it to disk instead
    res.for_each(move |data| {
        archive_file.write_all(&data.unwrap()).unwrap();
        archive_file.sync_all().unwrap();
        ready(())
    })
    .await;

    docker
        .remove_container("integration_test_export_container", None)
        .await?;

    // assert that the file containg the exported archive actually exists
    let test_file = File::open(temp_file).unwrap();
    // and metadata can be read
    test_file.metadata().unwrap();

    // And delete it to clean up
    remove_file(temp_file).unwrap();
    Ok(())
}

#[test]
fn integration_test_list_containers() {
    connect_to_docker_and_run!(list_containers_test);
}

#[test]
fn integration_test_image_push() {
    connect_to_docker_and_run!(image_push_test);
}

#[test]
fn integration_test_restart_container() {
    connect_to_docker_and_run!(container_restart_test);
}

#[test]
fn integration_test_top_processes() {
    connect_to_docker_and_run!(top_processes_test);
}

#[test]
// #[cfg(not(windows))]
// // This works on windows, but is flaky for some reason.
fn integration_test_logs() {
    connect_to_docker_and_run!(logs_test);
}

#[test]
fn integration_test_container_changes() {
    connect_to_docker_and_run!(container_changes_test);
}

#[test]
fn integration_test_stats() {
    connect_to_docker_and_run!(stats_test);
}

#[test]
fn integration_test_kill_container() {
    connect_to_docker_and_run!(kill_container_test);
}

// note: resource updating isn't supported on Windows
#[test]
#[cfg(not(windows))]
fn integration_test_update_container() {
    connect_to_docker_and_run!(update_container_test);
}

#[test]
fn integration_test_rename_container() {
    connect_to_docker_and_run!(rename_container_test);
}

// note: cannot pause Windows Server Containers
#[test]
#[cfg(not(windows))]
fn integration_test_pause_container() {
    connect_to_docker_and_run!(pause_container_test);
}

#[test]
fn integration_test_prune_containers() {
    connect_to_docker_and_run!(prune_containers_test);
}

#[test]
fn integration_test_archive_containers() {
    connect_to_docker_and_run!(|docker| archive_container_test(docker, true));
    connect_to_docker_and_run!(|docker| archive_container_test(docker, false));
}

#[test]
fn integration_test_inspect_containers() {
    connect_to_docker_and_run!(inspect_container_test);
}

#[test]
fn integration_test_mount_volume_containers() {
    connect_to_docker_and_run!(mount_volume_container_test);
}

#[test]
fn integration_test_attach_container() {
    connect_to_docker_and_run!(attach_container_test);
}

#[cfg(feature = "test_websocket")]
async fn attach_container_websocket_test(docker: Docker) -> Result<(), Error> {
    create_shell_daemon(&docker, "integration_test_attach_container_ws").await?;

    let AttachContainerResults { output, mut input } = docker
        .attach_container_websocket(
            "integration_test_attach_container_ws",
            Some(
                AttachContainerOptionsBuilder::default()
                    .stream(true)
                    .stdout(true)
                    .stdin(true)
                    .build(),
            ),
        )
        .await?;

    input.write_all(b"echo test\n").await?;
    input.flush().await?;
    input.write_all(b"exit\n").await?;
    input.flush().await?;

    let log = match tokio::time::timeout(
        tokio::time::Duration::from_secs(2),
        output.try_collect::<Vec<_>>(),
    )
    .await
    {
        Ok(res) => res?,
        Err(_) => {
            docker
                .kill_container("integration_test_attach_container_ws", None)
                .await?;
            vec![]
        }
    };

    let output_found = log.iter().any(|val| val.to_string().contains("test"));
    assert!(output_found);

    let _ = &docker
        .wait_container("integration_test_attach_container_ws", None)
        .try_collect::<Vec<_>>()
        .await;

    let _ = &docker
        .remove_container("integration_test_attach_container_ws", None)
        .await?;

    Ok(())
}

#[test]
#[cfg(feature = "test_websocket")]
fn integration_test_attach_container_websocket() {
    connect_to_docker_and_run!(attach_container_websocket_test);
}

#[test]
fn integration_test_resize_container_tty() {
    connect_to_docker_and_run!(resize_container_test);
}

// note: container exports aren't supported on Windows
#[test]
#[cfg(not(windows))]
fn integration_test_export_container() {
    connect_to_docker_and_run!(export_container_test);
}

#[cfg(feature = "test_checkpoint")]
async fn checkpoint_test(docker: Docker) -> Result<(), Error> {
    let image = format!("{}alpine:latest", registry_http_addr());

    let _ = &docker
        .create_image(
            Some(
                CreateImageOptionsBuilder::default()
                    .from_image(&image)
                    .build(),
            ),
            None,
            Some(integration_test_registry_credentials()),
        )
        .try_collect::<Vec<_>>()
        .await?;

    let _ = &docker
        .create_container(
            Some(
                bollard::query_parameters::CreateContainerOptionsBuilder::default()
                    .name("integration_test_checkpoint")
                    .build(),
            ),
            ContainerCreateBody {
                image: Some(image.clone()),
                cmd: Some(vec!["sleep".to_string(), "300".to_string()]),
                ..Default::default()
            },
        )
        .await?;

    docker
        .start_container("integration_test_checkpoint", None)
        .await?;

    let checkpoints = docker
        .list_checkpoints(
            "integration_test_checkpoint",
            None::<ListCheckpointsOptions>,
        )
        .await?;
    assert!(checkpoints.is_empty());

    let create_options = CreateCheckpointOptions {
        checkpoint_id: String::from("test-checkpoint-1"),
        checkpoint_dir: None,
        exit: false,
    };
    docker
        .create_checkpoint("integration_test_checkpoint", create_options)
        .await?;

    let checkpoints = docker
        .list_checkpoints(
            "integration_test_checkpoint",
            None::<ListCheckpointsOptions>,
        )
        .await?;
    assert_eq!(1, checkpoints.len());
    assert_eq!("test-checkpoint-1", checkpoints[0].name);

    docker
        .delete_checkpoint(
            "integration_test_checkpoint",
            "test-checkpoint-1",
            None::<DeleteCheckpointOptions>,
        )
        .await?;

    let checkpoints = docker
        .list_checkpoints(
            "integration_test_checkpoint",
            None::<ListCheckpointsOptions>,
        )
        .await?;
    assert!(checkpoints.is_empty());

    docker
        .kill_container("integration_test_checkpoint", None)
        .await
        .ok();

    docker
        .remove_container(
            "integration_test_checkpoint",
            Some(RemoveContainerOptionsBuilder::default().force(true).build()),
        )
        .await?;

    Ok(())
}

#[test]
#[cfg(feature = "test_checkpoint")]
#[cfg(not(windows))]
fn integration_test_checkpoint() {
    connect_to_docker_and_run!(checkpoint_test);
}
