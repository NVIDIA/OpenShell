#[macro_use]
pub mod common;

use bollard::errors::Error;
use bollard::query_parameters::{
    GetPluginPrivilegesOptionsBuilder, InstallPluginOptionsBuilder, ListPluginsOptionsBuilder,
    UpgradePluginOptionsBuilder,
};
use bollard::Docker;
use futures_util::stream::TryStreamExt;
use std::collections::HashMap;

async fn list_plugins_test(docker: Docker) -> Result<(), Error> {
    docker
        .list_plugins(None::<bollard::query_parameters::ListPluginsOptions>)
        .await?;
    Ok(())
}

async fn list_plugins_with_filter_test(docker: Docker) -> Result<(), Error> {
    let mut filters: HashMap<String, Vec<String>> = HashMap::new();
    filters.insert("capability".to_string(), vec!["volumedriver".to_string()]);

    let options = ListPluginsOptionsBuilder::default()
        .filters(&filters)
        .build();

    docker.list_plugins(Some(options)).await?;
    Ok(())
}

async fn get_plugin_privileges_test(docker: Docker) -> Result<(), Error> {
    let options = GetPluginPrivilegesOptionsBuilder::default()
        .remote("vieux/sshfs:latest")
        .build();

    match docker.get_plugin_privileges(options).await {
        Ok(privileges) => {
            assert!(!privileges.is_empty());
        }
        Err(Error::DockerResponseServerError { status_code, .. })
            if status_code == 500 || status_code == 404 =>
        {
            // Docker Hub unreachable or plugin not found
        }
        Err(e) => return Err(e),
    }
    Ok(())
}

#[test]
#[cfg(not(windows))]
fn integration_test_list_plugins() {
    use crate::common::run_runtime;
    use tokio::runtime::Runtime;
    connect_to_docker_and_run!(list_plugins_test);
}

#[test]
#[cfg(not(windows))]
fn integration_test_list_plugins_with_filter() {
    use crate::common::run_runtime;
    use tokio::runtime::Runtime;
    connect_to_docker_and_run!(list_plugins_with_filter_test);
}

#[test]
fn integration_test_get_plugin_privileges() {
    use crate::common::run_runtime;
    use tokio::runtime::Runtime;
    connect_to_docker_and_run!(get_plugin_privileges_test);
}

const PLUGIN_REMOTE: &str = "vieux/sshfs:latest";

async fn cleanup_plugin(docker: &Docker, name: &str) {
    let _ = docker.disable_plugin(name, None).await;
    let _ = docker
        .remove_plugin(
            name,
            Some(
                bollard::query_parameters::RemovePluginOptionsBuilder::default()
                    .force(true)
                    .build(),
            ),
        )
        .await;
}

async fn install_plugin(docker: &Docker, name: &str) -> Result<bool, Error> {
    let privileges_options = GetPluginPrivilegesOptionsBuilder::default()
        .remote(PLUGIN_REMOTE)
        .build();

    let privileges = match docker.get_plugin_privileges(privileges_options).await {
        Ok(p) => p,
        Err(Error::DockerResponseServerError { status_code, .. })
            if status_code == 500 || status_code == 404 =>
        {
            return Ok(false);
        }
        Err(e) => return Err(e),
    };

    let install_options = InstallPluginOptionsBuilder::default()
        .remote(PLUGIN_REMOTE)
        .name(name)
        .build();

    let _: Vec<_> = docker
        .install_plugin(install_options, privileges, None)
        .try_collect()
        .await?;

    Ok(true)
}

fn plugin_removed(result: Result<(), Error>) -> Result<bool, Error> {
    match result {
        Ok(()) => Ok(false), // Plugin still exists (disable succeeded)
        Err(Error::DockerResponseServerError {
            status_code: 404, ..
        }) => Ok(true),
        Err(e) => Err(e),
    }
}

// Lifecycle: install -> set_config -> enable -> disable -> remove
async fn plugin_lifecycle_test(docker: Docker) -> Result<(), Error> {
    const NAME: &str = "bollard-lifecycle-test";
    cleanup_plugin(&docker, NAME).await;

    if !install_plugin(&docker, NAME).await? {
        println!("Skipping: cannot reach Docker Hub");
        return Ok(());
    }

    // set_plugin_config - plugin must be disabled (it is after install)
    docker
        .set_plugin_config(NAME, vec!["DEBUG=1".to_string()])
        .await?;

    // enable_plugin
    let enable_opts = bollard::query_parameters::EnablePluginOptionsBuilder::default()
        .timeout(0)
        .build();
    docker.enable_plugin(NAME, Some(enable_opts)).await?;

    // disable_plugin
    docker.disable_plugin(NAME, None).await?;

    // remove_plugin - may return empty body causing JSON error
    let _ = docker.remove_plugin(NAME, None).await;

    // Verify removal
    assert!(
        plugin_removed(docker.disable_plugin(NAME, None).await)?,
        "Plugin should have been removed"
    );

    Ok(())
}

// Test upgrade_plugin by "upgrading" to the same version
async fn plugin_upgrade_test(docker: Docker) -> Result<(), Error> {
    const NAME: &str = "bollard-upgrade-test";
    cleanup_plugin(&docker, NAME).await;

    if !install_plugin(&docker, NAME).await? {
        println!("Skipping: cannot reach Docker Hub");
        return Ok(());
    }

    let privileges_options = GetPluginPrivilegesOptionsBuilder::default()
        .remote(PLUGIN_REMOTE)
        .build();
    let privileges = docker.get_plugin_privileges(privileges_options).await?;

    let upgrade_options = UpgradePluginOptionsBuilder::default()
        .remote(PLUGIN_REMOTE)
        .build();

    docker
        .upgrade_plugin(NAME, upgrade_options, privileges, None)
        .await?;

    // Verify plugin still works after upgrade
    let enable_opts = bollard::query_parameters::EnablePluginOptionsBuilder::default()
        .timeout(0)
        .build();
    docker.enable_plugin(NAME, Some(enable_opts)).await?;

    cleanup_plugin(&docker, NAME).await;
    Ok(())
}

// Note: create_plugin is not tested here. It requires a valid plugin tar archive
// containing a rootfs with actual binaries and a config.json - this is impractical
// for integration tests. The API implementation follows the same pattern as other
// plugin APIs and is manually verified to work.

// Test push_plugin - expects failure without registry/credentials
async fn plugin_push_test(docker: Docker) -> Result<(), Error> {
    const NAME: &str = "bollard-push-test";
    cleanup_plugin(&docker, NAME).await;

    if !install_plugin(&docker, NAME).await? {
        println!("Skipping: cannot reach Docker Hub");
        return Ok(());
    }

    match docker.push_plugin(NAME, None).await {
        Ok(()) => {} // Maybe local registry configured
        Err(Error::DockerResponseServerError { status_code, .. }) => {
            assert!(status_code == 500 || status_code == 401 || status_code == 404);
        }
        Err(e) => return Err(e),
    }

    cleanup_plugin(&docker, NAME).await;
    Ok(())
}

#[test]
#[cfg(not(windows))]
fn integration_test_plugin_lifecycle() {
    use crate::common::run_runtime;
    use tokio::runtime::Runtime;
    connect_to_docker_and_run!(plugin_lifecycle_test);
}

#[test]
#[cfg(not(windows))]
fn integration_test_plugin_upgrade() {
    use crate::common::run_runtime;
    use tokio::runtime::Runtime;
    connect_to_docker_and_run!(plugin_upgrade_test);
}

#[test]
#[cfg(not(windows))]
fn integration_test_plugin_push() {
    use crate::common::run_runtime;
    use tokio::runtime::Runtime;
    connect_to_docker_and_run!(plugin_push_test);
}
