use bollard::{errors::Error, Docker};
use tokio::runtime::Runtime;

#[macro_use]
pub mod common;
use crate::common::*;

#[test]
#[cfg(not(windows))]
fn integration_test_inspect_registry_image() {
    // happy path /distribution/{image_ref}/json test
    async fn inspect_test(docker: Docker) -> Result<(), Error> {
        let image = format!("{}hello-world:linux", registry_http_addr());
        let creds = integration_test_registry_credentials();
        let response = docker.inspect_registry_image(&image, Some(creds)).await?;

        let expected_os = "linux".to_string();
        assert!(!response.platforms.is_empty());
        assert_eq!(response.platforms[0].os, Some(expected_os));
        Ok(())
    }

    connect_to_docker_and_run!(inspect_test);
}
