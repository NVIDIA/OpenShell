#![type_length_limit = "2097152"]
#![allow(deprecated)]

use std::task::Poll;

use bollard::container::*;
use bollard::errors::Error;
use bollard::exec::*;
use bollard::query_parameters::{
    KillContainerOptions, RemoveContainerOptions, WaitContainerOptions,
};
use bollard::Docker;

use futures_util::future;
use futures_util::stream::TryStreamExt;
use futures_util::StreamExt;
use tokio::runtime::Runtime;

#[macro_use]
pub mod common;
use crate::common::*;

async fn start_exec_test(docker: Docker) -> Result<(), Error> {
    create_daemon(&docker, "integration_test_start_exec_test").await?;

    let message = &docker
        .create_exec(
            "integration_test_start_exec_test",
            CreateExecOptions {
                attach_stdout: Some(true),
                cmd: if cfg!(windows) {
                    Some(vec![
                        "cmd.exe",
                        "/C",
                        "type",
                        "C:\\Windows\\System32\\Inetsrv\\Config\\ApplicationHost.config",
                    ])
                } else {
                    Some(vec!["/bin/cat", "/etc/config/uhttpd"])
                },
                ..Default::default()
            },
        )
        .await?;

    let results = docker
        .start_exec(&message.id, None::<StartExecOptions>)
        .await?;

    assert!(match results {
        StartExecResults::Attached { output, .. } => {
            let log: Vec<_> = output.try_collect().await?;
            assert!(!log.is_empty());
            match &log[0] {
                LogOutput::StdOut { message } => {
                    let (n, expected) = if cfg!(windows) {
                        (0, "<configuration>\r")
                    } else {
                        (1, "config uhttpd main")
                    };

                    let s = String::from_utf8_lossy(message);
                    s.split('\n').nth(n).expect("log exists") == expected
                }
                _ => false,
            }
        }
        _ => false,
    });

    let _ = &docker
        .kill_container(
            "integration_test_start_exec_test",
            None::<KillContainerOptions>,
        )
        .await?;

    let _ = &docker
        .wait_container(
            "integration_test_start_exec_test",
            None::<WaitContainerOptions>,
        )
        .try_collect::<Vec<_>>()
        .await;

    let _ = &docker
        .remove_container(
            "integration_test_start_exec_test",
            None::<RemoveContainerOptions>,
        )
        .await?;

    Ok(())
}

async fn inspect_exec_test(docker: Docker) -> Result<(), Error> {
    create_daemon(&docker, "integration_test_inspect_exec_test").await?;

    let message = &docker
        .create_exec(
            "integration_test_inspect_exec_test",
            CreateExecOptions {
                attach_stdout: Some(true),
                cmd: if cfg!(windows) {
                    Some(vec![
                        "cmd.exe",
                        "/C",
                        "type",
                        "C:\\Windows\\System32\\Inetsrv\\Config\\ApplicationHost.config",
                    ])
                } else {
                    Some(vec!["/bin/cat", "/etc/config/uhttpd"])
                },
                ..Default::default()
            },
        )
        .await?;

    docker
        .start_exec(
            &message.id,
            Some(StartExecOptions {
                detach: true,
                ..Default::default()
            }),
        )
        .await?;

    let exec_process = &docker.inspect_exec(&message.id).await?;

    assert_eq!(
        if cfg!(windows) { "cmd.exe" } else { "/bin/cat" },
        exec_process
            .process_config
            .as_ref()
            .unwrap()
            .entrypoint
            .as_ref()
            .unwrap()
    );

    let _ = &docker
        .kill_container(
            "integration_test_inspect_exec_test",
            None::<KillContainerOptions>,
        )
        .await?;

    let _ = &docker
        .wait_container(
            "integration_test_inspect_exec_test",
            None::<WaitContainerOptions>,
        )
        .try_collect::<Vec<_>>()
        .await;

    let _ = &docker
        .remove_container(
            "integration_test_inspect_exec_test",
            None::<RemoveContainerOptions>,
        )
        .await?;

    Ok(())
}

async fn start_exec_output_capacity_test_short(docker: Docker) -> Result<(), Error> {
    create_daemon(&docker, "start_exec_output_capacity_test_short").await?;

    let text1 = "a".repeat(1024);

    let message = &docker
        .create_exec(
            "start_exec_output_capacity_test_short",
            CreateExecOptions {
                attach_stdout: Some(true),
                cmd: if cfg!(windows) {
                    Some(vec!["cmd.exe", "/C", "echo", &text1])
                } else {
                    Some(vec!["/bin/echo", &text1])
                },
                ..Default::default()
            },
        )
        .await?;

    let results = docker
        .start_exec(&message.id, None::<StartExecOptions>)
        .await?;

    if let StartExecResults::Attached { output, .. } = results {
        let mut i = 0;
        let stop_fut = future::poll_fn(|_cx| {
            i += 1;
            if i < text1.len() {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        });
        let stream = output.take_until(stop_fut);

        let log: Vec<_> = stream.try_collect::<Vec<_>>().await?;
        assert!(!log.is_empty());
        let mut buf = String::new();

        for chunk in &log {
            if let LogOutput::StdOut { message } = chunk {
                let s = String::from_utf8_lossy(message);
                buf.push_str(&s);
            }
        }

        assert_eq!(buf.trim(), text1);
    }

    let _ = &docker
        .kill_container(
            "start_exec_output_capacity_test_short",
            None::<KillContainerOptions>,
        )
        .await?;

    let _ = &docker
        .wait_container(
            "start_exec_output_capacity_test_short",
            None::<WaitContainerOptions>,
        )
        .try_collect::<Vec<_>>()
        .await;

    let _ = &docker
        .remove_container(
            "start_exec_output_capacity_test_short",
            None::<RemoveContainerOptions>,
        )
        .await?;

    Ok(())
}

async fn start_exec_output_capacity_test_long(docker: Docker) -> Result<(), Error> {
    create_daemon(&docker, "start_exec_output_capacity_test_long").await?;

    let text2 = "a".repeat(7 * 1024);

    let message = &docker
        .create_exec(
            "start_exec_output_capacity_test_long",
            CreateExecOptions {
                attach_stdout: Some(true),
                cmd: if cfg!(windows) {
                    Some(vec!["cmd.exe", "/C", "echo", &text2])
                } else {
                    Some(vec!["/bin/echo", &text2])
                },
                ..Default::default()
            },
        )
        .await?;

    let results = docker
        .start_exec(
            &message.id,
            Some(StartExecOptions {
                output_capacity: Some(100 * 1024),
                ..Default::default()
            }),
        )
        .await?;

    if let StartExecResults::Attached { output, .. } = results {
        let mut i = 0;
        let stop_fut = future::poll_fn(|_cx| {
            i += 1;
            if i < text2.len() {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        });
        let stream = output.take_until(stop_fut);

        let log: Vec<_> = stream.try_collect::<Vec<_>>().await?;
        assert!(!log.is_empty());
        let mut buf = String::new();

        for chunk in &log {
            if let LogOutput::StdOut { message } = chunk {
                let s = String::from_utf8_lossy(message);
                buf.push_str(&s);
            }
        }

        assert_eq!(buf.trim(), text2);
    }

    let _ = &docker
        .kill_container(
            "start_exec_output_capacity_test_long",
            None::<KillContainerOptions>,
        )
        .await?;

    let _ = &docker
        .wait_container(
            "start_exec_output_capacity_test_long",
            None::<WaitContainerOptions>,
        )
        .try_collect::<Vec<_>>()
        .await;

    let _ = &docker
        .remove_container(
            "start_exec_output_capacity_test_long",
            None::<RemoveContainerOptions>,
        )
        .await?;

    Ok(())
}

#[test]
fn integration_test_start_exec() {
    connect_to_docker_and_run!(start_exec_test);
}

#[test]
fn integration_test_inspect_exec() {
    connect_to_docker_and_run!(inspect_exec_test);
}

#[test]
fn integration_test_start_exec_output_capacity_short() {
    connect_to_docker_and_run!(start_exec_output_capacity_test_short);
}

#[test]
fn integration_test_start_exec_output_capacity_long() {
    connect_to_docker_and_run!(start_exec_output_capacity_test_long);
}
