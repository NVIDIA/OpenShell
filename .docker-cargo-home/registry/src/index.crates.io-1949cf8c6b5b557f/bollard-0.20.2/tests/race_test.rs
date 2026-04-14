use bollard::{query_parameters::ListImagesOptionsBuilder, Docker};
use once_cell::sync::OnceCell;

static DOCKER: OnceCell<Docker> = OnceCell::new();
#[cfg(all(unix, not(feature = "test_http"), not(feature = "test_ssl")))]
fn get_docker() -> Result<&'static Docker, bollard::errors::Error> {
    DOCKER.get_or_try_init(Docker::connect_with_unix_defaults)
}

#[cfg(all(feature = "test_http", not(feature = "test_ssl")))]
fn get_docker() -> Result<&'static Docker, bollard::errors::Error> {
    DOCKER.get_or_try_init(Docker::connect_with_http_defaults)
}

#[cfg(feature = "test_ssl")]
fn get_docker() -> Result<&'static Docker, bollard::errors::Error> {
    DOCKER.get_or_try_init(Docker::connect_with_ssl_defaults)
}

#[cfg(windows)]
fn get_docker() -> Result<&'static Docker, bollard::errors::Error> {
    DOCKER.get_or_try_init(Docker::connect_with_named_pipe_defaults)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_runtime() {
    run_test(10).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_runtime_2() {
    run_test(10).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_runtime_3() {
    run_test(100).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_runtime_4() {
    run_test(100).await;
}

async fn run_test(count: usize) {
    let docker = get_docker().unwrap();
    for _ in 0..count {
        let _ = &docker
            .list_images(Some(ListImagesOptionsBuilder::default().all(true).build()))
            .await
            .unwrap();
    }
}
