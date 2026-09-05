// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "linux")]

//! End-to-end coverage for interactive OIDC PKCE login and gateway RBAC.
//!
//! The test replaces Linux's `xdg-open` with a recorder, then drives the
//! captured Keycloak login URL with curl. This exercises the same loopback
//! callback and token exchange used by a real browser without requiring a GUI.
//! It logs in as the fixture identities and verifies standard-user and admin-only
//! actions against a live Docker- or Podman-backed gateway.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
use openshell_e2e::harness::binary::openshell_cmd;
use serde_json::Value;
use tokio::process::Command;
use tokio::sync::Mutex;
use url::Url;

static SANDBOX_LIFECYCLE_LOCK: Mutex<()> = Mutex::const_new(());

#[derive(Clone, Copy)]
struct IdentityScenario {
    gateway_name: &'static str,
    username: &'static str,
    password: &'static str,
    expected_role: &'static str,
}

const ADMIN: IdentityScenario = IdentityScenario {
    gateway_name: "oidc-pkce-admin",
    username: "admin@test",
    password: "admin",
    expected_role: "openshell-admin",
};

const USER: IdentityScenario = IdentityScenario {
    gateway_name: "oidc-pkce-user",
    username: "user@test",
    password: "user",
    expected_role: "openshell-user",
};

const USER_B: IdentityScenario = IdentityScenario {
    gateway_name: "oidc-pkce-user-b",
    username: "user-b@test",
    password: "user-b",
    expected_role: "openshell-user",
};

struct LoginSession {
    config_home: tempfile::TempDir,
    identity: IdentityScenario,
    subject: String,
}

#[tokio::test]
async fn admin_can_list_sandboxes() {
    let session = login_identity(ADMIN).await;
    assert_allowed(
        &session,
        &["sandbox", "list", "--output", "json"],
        "list sandboxes",
    )
    .await;
}

#[tokio::test]
async fn user_can_report_gateway_validated_identity() {
    let session = login_identity(USER).await;
    let output = assert_allowed(
        &session,
        &["whoami", "--output", "json"],
        "report current identity",
    )
    .await;
    let stdout = String::from_utf8(output.stdout).expect("whoami output should be UTF-8");
    let json_start = stdout.find('{').expect("whoami output should contain JSON");
    let json_end = stdout
        .rfind('}')
        .expect("whoami output should contain a complete JSON object");
    let identity: Value = serde_json::from_str(&stdout[json_start..=json_end])
        .expect("whoami --output json should return JSON on stdout");

    assert_eq!(identity["subject"], session.subject);
    assert_eq!(identity["identity_provider"], "oidc");
    assert!(
        identity["roles"]
            .as_array()
            .is_some_and(|roles| roles.iter().any(|role| role == USER.expected_role)),
        "whoami should report the configured user role: {identity}"
    );
}

#[tokio::test]
async fn user_can_list_sandboxes() {
    const WORKSPACE: &str = "oidc-user-list-sb";
    let user = login_identity(USER).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &user, WORKSPACE, "user").await;
    assert_workspace_allowed(
        &user,
        WORKSPACE,
        &["sandbox", "list", "--output", "json"],
        "list sandboxes",
    )
    .await;
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn admin_can_create_sandbox() {
    let session = login_identity(ADMIN).await;
    let _lifecycle = SANDBOX_LIFECYCLE_LOCK.lock().await;
    assert_can_create_sandbox(&session, "default", "oidc-admin-create").await;
}

#[tokio::test]
async fn user_can_create_sandbox() {
    const WORKSPACE: &str = "oidc-user-create";
    let user = login_identity(USER).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &user, WORKSPACE, "user").await;
    let _lifecycle = SANDBOX_LIFECYCLE_LOCK.lock().await;
    assert_can_create_sandbox(&user, WORKSPACE, "oidc-user-create").await;
    delete_workspace(&admin, WORKSPACE).await;
}

/// Workspace users must be able to create sandboxes with inferred-provider
/// commands (e.g. `claude`) without requiring Platform Admin access.
#[tokio::test]
async fn user_can_create_sandbox_with_inferred_provider_command() {
    const WORKSPACE: &str = "oidc-inferred-cmd";
    let user = login_identity(USER).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &user, WORKSPACE, "user").await;
    let _lifecycle = SANDBOX_LIFECYCLE_LOCK.lock().await;

    // Use `claude` as the command so the CLI infers provider type
    // `claude-code`. The sandbox won't actually start (no provider
    // credentials), but provider inference must remain available to a
    // workspace user.
    let output = run_workspace_cli(
        &user,
        WORKSPACE,
        &[
            "sandbox",
            "create",
            "--name",
            "oidc-inferred-cmd",
            "--no-tty",
            "--",
            "claude",
        ],
    )
    .await;
    let combined = combined_output(&output);

    // The sandbox won't start because there are no provider credentials,
    // but the error must be about the missing provider — NOT a
    // platform-admin gate on GetGatewayConfig.
    assert!(
        !combined.to_ascii_lowercase().contains("platform admin"),
        "workspace user hit a platform-admin gate on an inferred-provider command:\n{combined}"
    );
    assert!(
        combined.contains("missing required provider"),
        "expected missing-provider error for non-interactive session, got:\n{combined}"
    );

    let _ = run_workspace_cli(
        &user,
        WORKSPACE,
        &["sandbox", "delete", "oidc-inferred-cmd"],
    )
    .await;
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn admin_can_delete_sandbox() {
    let session = login_identity(ADMIN).await;
    let _lifecycle = SANDBOX_LIFECYCLE_LOCK.lock().await;
    assert_can_delete_sandbox(&session, "default", "oidc-admin-delete").await;
}

#[tokio::test]
async fn user_can_delete_sandbox() {
    const WORKSPACE: &str = "oidc-user-delete";
    let user = login_identity(USER).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &user, WORKSPACE, "user").await;
    let _lifecycle = SANDBOX_LIFECYCLE_LOCK.lock().await;
    assert_can_delete_sandbox(&user, WORKSPACE, "oidc-user-delete").await;
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn admin_can_inspect_gateway() {
    let session = login_identity(ADMIN).await;
    let output = assert_allowed(&session, &["gateway", "info"], "inspect gateway info").await;
    let info = combined_output(&output);
    let expected_driver =
        std::env::var("OPENSHELL_E2E_DRIVER").expect("OIDC E2E requires OPENSHELL_E2E_DRIVER");
    assert!(
        info.to_ascii_lowercase()
            .contains(&expected_driver.to_ascii_lowercase()),
        "gateway info should report the {expected_driver} compute driver: {info}"
    );
}

#[tokio::test]
async fn user_cannot_inspect_gateway() {
    let session = login_identity(USER).await;
    let output = run_session_cli(&session, &["gateway", "info"]).await;
    let denied = combined_output(&output);
    assert!(
        !output.status.success(),
        "user accessed gateway info:\n{denied}"
    );
    assert!(
        denied.contains("requires admin privileges"),
        "gateway-info denial should explain that admin privileges are required:\n{denied}"
    );
    assert_admin_role_denial(&output, "inspect gateway info");
}

#[tokio::test]
async fn admin_can_list_providers() {
    let session = login_identity(ADMIN).await;
    assert_allowed(
        &session,
        &["provider", "list", "--output", "json"],
        "list providers",
    )
    .await;
}

#[tokio::test]
async fn user_can_list_providers() {
    const WORKSPACE: &str = "oidc-user-list-pr";
    let user = login_identity(USER).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &user, WORKSPACE, "user").await;
    assert_workspace_allowed(
        &user,
        WORKSPACE,
        &["provider", "list", "--output", "json"],
        "list providers",
    )
    .await;
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn admin_can_manage_provider() {
    const PROVIDER: &str = "oidc-pkce-admin-provider";
    let session = login_identity(ADMIN).await;

    assert_allowed(
        &session,
        &[
            "provider",
            "create",
            "--name",
            PROVIDER,
            "--type",
            "openai",
            "--credential",
            "OPENAI_API_KEY=e2e-test-value",
        ],
        "create a provider",
    )
    .await;

    let get = assert_allowed(&session, &["provider", "get", PROVIDER], "read a provider").await;
    assert!(
        combined_output(&get).contains(PROVIDER),
        "provider get output should contain the created provider:\n{}",
        combined_output(&get)
    );

    assert_allowed(
        &session,
        &["provider", "delete", PROVIDER],
        "delete a provider",
    )
    .await;
}

#[tokio::test]
async fn user_cannot_create_provider() {
    const WORKSPACE: &str = "oidc-user-no-create";
    let user = login_identity(USER).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &user, WORKSPACE, "user").await;
    let output = run_workspace_cli(
        &user,
        WORKSPACE,
        &[
            "provider",
            "create",
            "--name",
            "oidc-pkce-user-provider",
            "--type",
            "openai",
            "--credential",
            "OPENAI_API_KEY=e2e-test-value",
        ],
    )
    .await;
    assert_workspace_admin_denial(&output, &user, WORKSPACE, "create a provider");
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn user_cannot_delete_provider() {
    const PROVIDER: &str = "oidc-pkce-user-delete-target";
    const WORKSPACE: &str = "oidc-user-no-delete";
    let user = login_identity(USER).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &user, WORKSPACE, "user").await;
    assert_workspace_allowed(
        &admin,
        WORKSPACE,
        &[
            "provider",
            "create",
            "--name",
            PROVIDER,
            "--type",
            "openai",
            "--credential",
            "OPENAI_API_KEY=e2e-test-value",
        ],
        "create the provider deletion target",
    )
    .await;

    let denied = run_workspace_cli(&user, WORKSPACE, &["provider", "delete", PROVIDER]).await;
    assert_workspace_admin_denial(&denied, &user, WORKSPACE, "delete a provider");

    assert_workspace_allowed(
        &admin,
        WORKSPACE,
        &["provider", "delete", PROVIDER],
        "clean up the provider deletion target",
    )
    .await;
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn admin_can_create_workspace() {
    const WORKSPACE: &str = "oidc-admin-create";
    let admin = login_identity(ADMIN).await;
    let _ = run_session_cli(&admin, &["workspace", "delete", WORKSPACE]).await;
    assert_allowed(
        &admin,
        &["workspace", "create", "--name", WORKSPACE],
        "create a workspace",
    )
    .await;
    let get = assert_allowed(
        &admin,
        &["workspace", "get", WORKSPACE],
        "read the created workspace",
    )
    .await;
    assert!(combined_output(&get).contains(WORKSPACE));
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn user_cannot_create_workspace() {
    let user = login_identity(USER).await;
    let denied = run_session_cli(
        &user,
        &["workspace", "create", "--name", "oidc-user-denied"],
    )
    .await;
    assert_admin_role_denial(&denied, "create a workspace");
}

#[tokio::test]
async fn admin_can_delete_workspace() {
    const WORKSPACE: &str = "oidc-admin-delete";
    let admin = login_identity(ADMIN).await;
    let _ = run_session_cli(&admin, &["workspace", "delete", WORKSPACE]).await;
    assert_allowed(
        &admin,
        &["workspace", "create", "--name", WORKSPACE],
        "create a workspace deletion target",
    )
    .await;
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn user_cannot_delete_workspace() {
    const WORKSPACE: &str = "oidc-user-del-deny";
    let admin = login_identity(ADMIN).await;
    let user = login_identity(USER).await;
    let _ = run_session_cli(&admin, &["workspace", "delete", WORKSPACE]).await;
    assert_allowed(
        &admin,
        &["workspace", "create", "--name", WORKSPACE],
        "create a workspace deletion target",
    )
    .await;
    let denied = run_session_cli(&user, &["workspace", "delete", WORKSPACE]).await;
    assert_admin_role_denial(&denied, "delete a workspace");
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn workspace_user_can_read_workspace() {
    const WORKSPACE: &str = "oidc-ws-user-read";
    let user = login_identity(USER).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &user, WORKSPACE, "user").await;

    let get = assert_allowed(
        &user,
        &["workspace", "get", WORKSPACE],
        "read a member workspace",
    )
    .await;
    let list = assert_allowed(
        &user,
        &["workspace", "list", "--output", "json"],
        "list member workspaces",
    )
    .await;
    let members = assert_allowed(
        &user,
        &["workspace", "member", "list", "--workspace", WORKSPACE],
        "list workspace members",
    )
    .await;
    assert!(combined_output(&get).contains(WORKSPACE));
    assert!(combined_output(&list).contains(WORKSPACE));
    assert!(combined_output(&members).contains(&user.subject));
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn workspace_user_cannot_manage_members() {
    const WORKSPACE: &str = "oidc-ws-user-deny";
    let user = login_identity(USER).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &user, WORKSPACE, "user").await;
    let denied = run_session_cli(
        &user,
        &[
            "workspace",
            "member",
            "add",
            "--workspace",
            WORKSPACE,
            "--subject",
            "oidc-fake-member",
            "--role",
            "user",
        ],
    )
    .await;
    assert_workspace_admin_denial(&denied, &user, WORKSPACE, "add a workspace member");
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn workspace_admin_can_read_workspace() {
    const WORKSPACE: &str = "oidc-wsa-read";
    let user = login_identity(USER).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &user, WORKSPACE, "admin").await;

    let get = assert_allowed(
        &user,
        &["workspace", "get", WORKSPACE],
        "read an administered workspace",
    )
    .await;
    assert!(combined_output(&get).contains(WORKSPACE));
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn workspace_admin_can_create_sandbox() {
    const WORKSPACE: &str = "oidc-wsa-create-sb";
    let user = login_identity(USER).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &user, WORKSPACE, "admin").await;
    let _lifecycle = SANDBOX_LIFECYCLE_LOCK.lock().await;
    assert_can_create_sandbox(&user, WORKSPACE, "oidc-wsa-create").await;
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn workspace_admin_can_delete_sandbox() {
    const WORKSPACE: &str = "oidc-wsa-delete-sb";
    let user = login_identity(USER).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &user, WORKSPACE, "admin").await;
    let _lifecycle = SANDBOX_LIFECYCLE_LOCK.lock().await;
    assert_can_delete_sandbox(&user, WORKSPACE, "oidc-wsa-delete").await;
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn workspace_admin_can_create_provider() {
    const WORKSPACE: &str = "oidc-wsa-create-pr";
    const PROVIDER: &str = "oidc-wsa-create-provider";
    let user = login_identity(USER).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &user, WORKSPACE, "admin").await;
    assert_workspace_allowed(
        &user,
        WORKSPACE,
        &[
            "provider",
            "create",
            "--name",
            PROVIDER,
            "--type",
            "openai",
            "--credential",
            "OPENAI_API_KEY=e2e-test-value",
        ],
        "create a provider as workspace admin",
    )
    .await;

    assert_workspace_allowed(
        &admin,
        WORKSPACE,
        &["provider", "delete", PROVIDER],
        "clean up the provider created by a workspace admin",
    )
    .await;
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn workspace_admin_can_delete_provider() {
    const WORKSPACE: &str = "oidc-wsa-delete-pr";
    const PROVIDER: &str = "oidc-wsa-delete-provider";
    let user = login_identity(USER).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &user, WORKSPACE, "admin").await;
    assert_workspace_allowed(
        &admin,
        WORKSPACE,
        &[
            "provider",
            "create",
            "--name",
            PROVIDER,
            "--type",
            "openai",
            "--credential",
            "OPENAI_API_KEY=e2e-test-value",
        ],
        "create the provider deletion target",
    )
    .await;
    assert_workspace_allowed(
        &user,
        WORKSPACE,
        &["provider", "delete", PROVIDER],
        "delete a provider as workspace admin",
    )
    .await;
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn workspace_admin_can_add_user_member() {
    const WORKSPACE: &str = "oidc-wsa-add-user";
    let workspace_admin = login_identity(USER).await;
    let user = login_identity(USER_B).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &workspace_admin, WORKSPACE, "admin").await;

    assert_allowed(
        &workspace_admin,
        &[
            "workspace",
            "member",
            "add",
            "--workspace",
            WORKSPACE,
            "--subject",
            &user.subject,
            "--role",
            "user",
        ],
        "add a standard workspace member",
    )
    .await;
    let members = assert_allowed(
        &workspace_admin,
        &["workspace", "member", "list", "--workspace", WORKSPACE],
        "list workspace members after adding one",
    )
    .await;
    assert!(combined_output(&members).contains(&user.subject));
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn workspace_admin_can_remove_user_member() {
    const WORKSPACE: &str = "oidc-wsa-rm-user";
    let workspace_admin = login_identity(USER).await;
    let user = login_identity(USER_B).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &workspace_admin, WORKSPACE, "admin").await;
    assert_allowed(
        &admin,
        &[
            "workspace",
            "member",
            "add",
            "--workspace",
            WORKSPACE,
            "--subject",
            &user.subject,
            "--role",
            "user",
        ],
        "create the workspace member removal target",
    )
    .await;

    assert_allowed(
        &workspace_admin,
        &[
            "workspace",
            "member",
            "remove",
            "--workspace",
            WORKSPACE,
            "--subject",
            &user.subject,
        ],
        "remove a standard workspace member",
    )
    .await;
    let denied = run_session_cli(&user, &["workspace", "get", WORKSPACE]).await;
    assert_non_member_denial(&denied, "read a workspace after removal by its admin");
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn workspace_admin_cannot_grant_admin() {
    const WORKSPACE: &str = "oidc-ws-admin-deny";
    let user = login_identity(USER).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &user, WORKSPACE, "admin").await;
    let denied = run_session_cli(
        &user,
        &[
            "workspace",
            "member",
            "add",
            "--workspace",
            WORKSPACE,
            "--subject",
            "oidc-fake-admin",
            "--role",
            "admin",
        ],
    )
    .await;
    assert_platform_admin_denial(&denied, "grant workspace admin");
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn workspace_admin_cannot_create_workspace() {
    const WORKSPACE: &str = "oidc-wsa-no-create";
    let user = login_identity(USER).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &user, WORKSPACE, "admin").await;

    let denied =
        run_session_cli(&user, &["workspace", "create", "--name", "oidc-wsa-denied"]).await;
    assert_admin_role_denial(&denied, "create a workspace as workspace admin");
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn workspace_admin_cannot_delete_workspace() {
    const WORKSPACE: &str = "oidc-wsa-no-delete";
    let user = login_identity(USER).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &user, WORKSPACE, "admin").await;

    let denied = run_session_cli(&user, &["workspace", "delete", WORKSPACE]).await;
    assert_admin_role_denial(&denied, "delete an administered workspace");
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn workspace_admin_cannot_inspect_gateway() {
    const WORKSPACE: &str = "oidc-wsa-no-gw-info";
    let user = login_identity(USER).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &user, WORKSPACE, "admin").await;

    let denied = run_workspace_cli(&user, WORKSPACE, &["gateway", "info"]).await;
    assert_admin_role_denial(&denied, "inspect gateway info as workspace admin");
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn workspace_admin_cannot_read_another_workspace() {
    const WORKSPACE_A: &str = "oidc-wsa-xread-a";
    const WORKSPACE_B: &str = "oidc-wsa-xread-b";
    let (admin, workspace_admin, _user_b) =
        prepare_isolated_workspaces_with_admin(WORKSPACE_A, WORKSPACE_B).await;

    let denied = run_session_cli(&workspace_admin, &["workspace", "get", WORKSPACE_B]).await;
    assert_non_member_denial(&denied, "read another workspace as workspace admin");

    delete_workspace(&admin, WORKSPACE_B).await;
    delete_workspace(&admin, WORKSPACE_A).await;
}

#[tokio::test]
async fn workspace_admin_cannot_manage_another_workspace_members() {
    const WORKSPACE_A: &str = "oidc-wsa-xmem-a";
    const WORKSPACE_B: &str = "oidc-wsa-xmem-b";
    let (admin, workspace_admin, _user_b) =
        prepare_isolated_workspaces_with_admin(WORKSPACE_A, WORKSPACE_B).await;

    let denied = run_session_cli(
        &workspace_admin,
        &[
            "workspace",
            "member",
            "add",
            "--workspace",
            WORKSPACE_B,
            "--subject",
            "oidc-fake-member",
            "--role",
            "user",
        ],
    )
    .await;
    assert_non_member_denial(
        &denied,
        "manage another workspace's members as workspace admin",
    );

    delete_workspace(&admin, WORKSPACE_B).await;
    delete_workspace(&admin, WORKSPACE_A).await;
}

#[tokio::test]
async fn workspace_admin_cannot_manage_another_workspace_providers() {
    const WORKSPACE_A: &str = "oidc-wsa-xprov-a";
    const WORKSPACE_B: &str = "oidc-wsa-xprov-b";
    let (admin, workspace_admin, _user_b) =
        prepare_isolated_workspaces_with_admin(WORKSPACE_A, WORKSPACE_B).await;

    let denied = run_workspace_cli(
        &workspace_admin,
        WORKSPACE_B,
        &[
            "provider",
            "create",
            "--name",
            "oidc-wsa-xprovider",
            "--type",
            "openai",
            "--credential",
            "OPENAI_API_KEY=e2e-test-value",
        ],
    )
    .await;
    assert_non_member_denial(
        &denied,
        "manage another workspace's providers as workspace admin",
    );

    delete_workspace(&admin, WORKSPACE_B).await;
    delete_workspace(&admin, WORKSPACE_A).await;
}

#[tokio::test]
async fn membership_removal_revokes_workspace_access() {
    const WORKSPACE: &str = "oidc-ws-revoke";
    let user = login_identity(USER).await;
    let admin = login_identity(ADMIN).await;
    prepare_workspace(&admin, &user, WORKSPACE, "user").await;
    assert_allowed(
        &admin,
        &[
            "workspace",
            "member",
            "remove",
            "--workspace",
            WORKSPACE,
            "--subject",
            &user.subject,
        ],
        "remove a workspace member",
    )
    .await;
    let denied = run_session_cli(&user, &["workspace", "get", WORKSPACE]).await;
    assert_non_member_denial(&denied, "read a workspace after membership removal");
    delete_workspace(&admin, WORKSPACE).await;
}

#[tokio::test]
async fn workspace_user_cannot_read_another_users_workspace() {
    const WORKSPACE_A: &str = "oidc-xread-a";
    const WORKSPACE_B: &str = "oidc-xread-b";
    let (admin, user_a, _user_b) = prepare_isolated_workspaces(WORKSPACE_A, WORKSPACE_B).await;

    let denied = run_session_cli(&user_a, &["workspace", "get", WORKSPACE_B]).await;
    assert_non_member_denial(&denied, "read another user's workspace");

    delete_workspace(&admin, WORKSPACE_B).await;
    delete_workspace(&admin, WORKSPACE_A).await;
}

#[tokio::test]
async fn second_workspace_user_cannot_read_first_users_workspace() {
    const WORKSPACE_A: &str = "oidc-xread2-a";
    const WORKSPACE_B: &str = "oidc-xread2-b";
    let (admin, _user_a, user_b) = prepare_isolated_workspaces(WORKSPACE_A, WORKSPACE_B).await;

    let denied = run_session_cli(&user_b, &["workspace", "get", WORKSPACE_A]).await;
    assert_non_member_denial(&denied, "read another user's workspace");

    delete_workspace(&admin, WORKSPACE_B).await;
    delete_workspace(&admin, WORKSPACE_A).await;
}

#[tokio::test]
async fn workspace_list_hides_another_users_workspace() {
    const WORKSPACE_A: &str = "oidc-xlist-a";
    const WORKSPACE_B: &str = "oidc-xlist-b";
    let (admin, user_a, _user_b) = prepare_isolated_workspaces(WORKSPACE_A, WORKSPACE_B).await;

    let listed = assert_allowed(
        &user_a,
        &["workspace", "list", "--output", "json"],
        "list visible workspaces",
    )
    .await;
    let output = combined_output(&listed);
    assert!(
        output.contains(WORKSPACE_A),
        "workspace list should contain the caller's workspace:\n{output}"
    );
    assert!(
        !output.contains(WORKSPACE_B),
        "workspace list exposed another user's workspace:\n{output}"
    );

    delete_workspace(&admin, WORKSPACE_B).await;
    delete_workspace(&admin, WORKSPACE_A).await;
}

#[tokio::test]
async fn workspace_user_cannot_list_another_workspace_sandboxes() {
    const WORKSPACE_A: &str = "oidc-xsbox-a";
    const WORKSPACE_B: &str = "oidc-xsbox-b";
    let (admin, user_a, _user_b) = prepare_isolated_workspaces(WORKSPACE_A, WORKSPACE_B).await;

    let denied = run_workspace_cli(
        &user_a,
        WORKSPACE_B,
        &["sandbox", "list", "--output", "json"],
    )
    .await;
    assert_non_member_denial(&denied, "list another workspace's sandboxes");

    delete_workspace(&admin, WORKSPACE_B).await;
    delete_workspace(&admin, WORKSPACE_A).await;
}

#[tokio::test]
async fn workspace_user_cannot_create_sandbox_in_another_workspace() {
    const WORKSPACE_A: &str = "oidc-xcreate-a";
    const WORKSPACE_B: &str = "oidc-xcreate-b";
    let (admin, user_a, _user_b) = prepare_isolated_workspaces(WORKSPACE_A, WORKSPACE_B).await;

    let denied = run_workspace_cli(
        &user_a,
        WORKSPACE_B,
        &[
            "sandbox",
            "create",
            "--name",
            "oidc-xcreate-denied",
            "--no-tty",
            "--",
            "echo",
            "denied",
        ],
    )
    .await;
    assert_non_member_denial(&denied, "create a sandbox in another workspace");

    delete_workspace(&admin, WORKSPACE_B).await;
    delete_workspace(&admin, WORKSPACE_A).await;
}

#[tokio::test]
async fn workspace_user_cannot_list_another_workspace_providers() {
    const WORKSPACE_A: &str = "oidc-xprov-a";
    const WORKSPACE_B: &str = "oidc-xprov-b";
    let (admin, user_a, _user_b) = prepare_isolated_workspaces(WORKSPACE_A, WORKSPACE_B).await;

    let denied = run_workspace_cli(
        &user_a,
        WORKSPACE_B,
        &["provider", "list", "--output", "json"],
    )
    .await;
    assert_non_member_denial(&denied, "list another workspace's providers");

    delete_workspace(&admin, WORKSPACE_B).await;
    delete_workspace(&admin, WORKSPACE_A).await;
}

#[tokio::test]
async fn workspace_user_cannot_list_another_workspace_members() {
    const WORKSPACE_A: &str = "oidc-xmember-a";
    const WORKSPACE_B: &str = "oidc-xmember-b";
    let (admin, user_a, _user_b) = prepare_isolated_workspaces(WORKSPACE_A, WORKSPACE_B).await;

    let denied = run_session_cli(
        &user_a,
        &["workspace", "member", "list", "--workspace", WORKSPACE_B],
    )
    .await;
    assert_non_member_denial(&denied, "list another workspace's members");

    delete_workspace(&admin, WORKSPACE_B).await;
    delete_workspace(&admin, WORKSPACE_A).await;
}

async fn login_identity(identity: IdentityScenario) -> LoginSession {
    let issuer = std::env::var("OPENSHELL_E2E_OIDC_ISSUER")
        .unwrap_or_else(|_| "http://localhost:8180/realms/openshell".to_string());
    let gateway_endpoint = std::env::var("OPENSHELL_E2E_OIDC_GATEWAY_ENDPOINT")
        .expect("OIDC E2E requires a live gateway endpoint");
    let temp = tempfile::tempdir().expect("create isolated test directory");
    let fake_bin = temp.path().join("bin");
    std::fs::create_dir(&fake_bin).expect("create fake bin directory");
    let browser_url_file = temp.path().join("browser-url");
    install_xdg_open_recorder(&fake_bin);

    let path = prepend_path(&fake_bin);
    let mut cli = openshell_cmd();
    cli.args([
        "gateway",
        "add",
        &gateway_endpoint,
        "--name",
        identity.gateway_name,
        "--local",
        "--oidc-issuer",
        &issuer,
        "--oidc-scopes",
        "profile email openshell:all",
    ])
    .env("XDG_CONFIG_HOME", temp.path())
    .env("HOME", temp.path())
    .env("PATH", path)
    .env("OPENSHELL_E2E_BROWSER_URL_FILE", &browser_url_file)
    .env_remove("OPENSHELL_GATEWAY")
    .env_remove("OPENSHELL_GATEWAY_ENDPOINT")
    .env_remove("OPENSHELL_NO_BROWSER")
    .env_remove("OPENSHELL_OIDC_CLIENT_SECRET")
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    let child = cli.spawn().expect("start openshell PKCE login");
    let authorization_url = wait_for_browser_url(&browser_url_file).await;
    let redirect_uri = assert_pkce_authorization_url(&authorization_url, &issuer);

    let cookie_jar = temp.path().join("keycloak-cookies");
    let login_page = curl_get(&authorization_url, &cookie_jar).await;
    let login_action = extract_login_action(&login_page);
    let callback_page = curl_login(
        &login_action,
        &cookie_jar,
        identity.username,
        identity.password,
    )
    .await;
    assert!(
        callback_page.contains("Authentication successful"),
        "loopback callback did not return its success page:\n{callback_page}"
    );

    let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .expect("openshell did not finish after receiving the OIDC callback")
        .expect("wait for openshell PKCE login");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "openshell PKCE login failed:\n{combined}"
    );
    assert!(
        combined.contains("Authenticated successfully"),
        "missing successful authentication message:\n{combined}"
    );

    let subject = assert_persisted_login(
        temp.path(),
        &issuer,
        &redirect_uri,
        identity.gateway_name,
        identity.username,
        identity.expected_role,
    );

    LoginSession {
        config_home: temp,
        identity,
        subject,
    }
}

fn install_xdg_open_recorder(bin_dir: &Path) {
    let script = bin_dir.join("xdg-open");
    std::fs::write(
        &script,
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$1\" > \"$OPENSHELL_E2E_BROWSER_URL_FILE\"\n",
    )
    .expect("write xdg-open recorder");
    std::fs::set_permissions(&script, Permissions::from_mode(0o755))
        .expect("make xdg-open recorder executable");
}

fn prepend_path(bin_dir: &Path) -> OsString {
    let current = std::env::var_os("PATH").unwrap_or_default();
    std::env::join_paths(
        std::iter::once(bin_dir.to_path_buf()).chain(std::env::split_paths(&current)),
    )
    .expect("construct PATH with xdg-open recorder")
}

async fn wait_for_browser_url(path: &Path) -> String {
    for _ in 0..200 {
        if let Ok(contents) = tokio::fs::read_to_string(path).await {
            let url = contents.trim();
            if !url.is_empty() {
                return url.to_string();
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "xdg-open did not receive an authorization URL within 10 seconds ({})",
        path.display()
    );
}

fn assert_pkce_authorization_url(authorization_url: &str, issuer: &str) -> String {
    let url = Url::parse(authorization_url).expect("authorization URL is valid");
    let expected_path = format!(
        "{}/protocol/openid-connect/auth",
        Url::parse(issuer)
            .expect("issuer URL is valid")
            .path()
            .trim_end_matches('/')
    );
    assert_eq!(url.path(), expected_path);

    let params: HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(
        params.get("response_type").map(String::as_str),
        Some("code")
    );
    assert_eq!(
        params.get("client_id").map(String::as_str),
        Some("openshell-cli")
    );
    assert_eq!(
        params.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    let challenge = params
        .get("code_challenge")
        .expect("authorization URL has a PKCE challenge");
    assert_eq!(challenge.len(), 43, "S256 challenge is base64url encoded");
    assert!(
        challenge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "PKCE challenge must use unpadded base64url"
    );
    assert!(
        params.get("state").is_some_and(|state| !state.is_empty()),
        "authorization URL must contain CSRF state"
    );

    let scopes: Vec<_> = params
        .get("scope")
        .expect("authorization URL has scopes")
        .split_whitespace()
        .collect();
    for expected in ["openid", "profile", "email", "openshell:all"] {
        assert!(scopes.contains(&expected), "missing OIDC scope {expected}");
    }

    let redirect_uri = params
        .get("redirect_uri")
        .expect("authorization URL has a redirect URI");
    let redirect = Url::parse(redirect_uri).expect("redirect URI is valid");
    assert_eq!(redirect.scheme(), "http");
    assert_eq!(redirect.host_str(), Some("127.0.0.1"));
    assert!(
        redirect.port().is_some(),
        "redirect URI has a callback port"
    );
    assert_eq!(redirect.path(), "/callback");
    redirect_uri.clone()
}

async fn curl_get(url: &str, cookie_jar: &Path) -> String {
    let output = Command::new("curl")
        .args(["--fail", "--silent", "--show-error", "--cookie-jar"])
        .arg(cookie_jar)
        .arg(url)
        .output()
        .await
        .expect("run curl for Keycloak login page");
    assert!(
        output.status.success(),
        "failed to load Keycloak login page: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("Keycloak login page is UTF-8")
}

async fn curl_login(action: &str, cookie_jar: &Path, username: &str, password: &str) -> String {
    let output = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--cookie",
        ])
        .arg(cookie_jar)
        .arg("--cookie-jar")
        .arg(cookie_jar)
        .arg("--data-urlencode")
        .arg(format!("username={username}"))
        .arg("--data-urlencode")
        .arg(format!("password={password}"))
        .arg("--data-urlencode")
        .arg("credentialId=")
        .arg(action)
        .output()
        .await
        .expect("run curl for Keycloak credentials submission");
    assert!(
        output.status.success(),
        "Keycloak login submission failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("OIDC callback page is UTF-8")
}

fn extract_login_action(html: &str) -> String {
    let form_id = html
        .find("id=\"kc-form-login\"")
        .expect("Keycloak page has the login form");
    let form_start = html[..form_id]
        .rfind("<form")
        .expect("Keycloak login form has a start tag");
    let form_end = form_id
        + html[form_id..]
            .find('>')
            .expect("Keycloak login form start tag is closed");
    let form = &html[form_start..form_end];
    let action_start = form
        .find("action=\"")
        .map(|index| index + "action=\"".len())
        .expect("Keycloak login form has an action");
    let action_end = action_start
        + form[action_start..]
            .find('"')
            .expect("Keycloak login action is quoted");
    form[action_start..action_end]
        .replace("&amp;", "&")
        .replace("&#38;", "&")
}

fn assert_persisted_login(
    config_home: &Path,
    issuer: &str,
    redirect_uri: &str,
    gateway_name: &str,
    username: &str,
    expected_role: &str,
) -> String {
    let gateway_dir = config_home
        .join("openshell")
        .join("gateways")
        .join(gateway_name);
    let metadata: Value = read_json(&gateway_dir.join("metadata.json"));
    assert_eq!(metadata["auth_mode"], "oidc");
    assert_eq!(metadata["oidc_issuer"], issuer);
    assert_eq!(metadata["oidc_client_id"], "openshell-cli");
    assert_eq!(metadata["oidc_scopes"], "profile email openshell:all");

    let token: Value = read_json(&gateway_dir.join("oidc_token.json"));
    let access_token = token["access_token"]
        .as_str()
        .expect("stored access token is a string");
    assert!(!access_token.is_empty());
    assert!(
        token["refresh_token"]
            .as_str()
            .is_some_and(|refresh| !refresh.is_empty()),
        "browser flow should persist a refresh token"
    );
    assert_eq!(token["issuer"], issuer);
    assert_eq!(token["client_id"], "openshell-cli");

    let claims = decode_jwt_claims(access_token);
    assert!(jwt_audience_contains(&claims["aud"], "openshell-cli"));
    assert_eq!(claims["azp"], "openshell-cli");
    assert_eq!(claims["preferred_username"], username);
    let subject = claims["sub"]
        .as_str()
        .filter(|subject| !subject.is_empty())
        .expect("access token should contain a non-empty subject")
        .to_string();
    assert!(
        claims["realm_access"]["roles"]
            .as_array()
            .is_some_and(|roles| roles.iter().any(|role| role == expected_role)),
        "access token should contain the {expected_role} realm role"
    );

    let redirect = Url::parse(redirect_uri).expect("saved redirect URI remains valid");
    assert_eq!(redirect.host_str(), Some("127.0.0.1"));
    subject
}

async fn assert_allowed(session: &LoginSession, args: &[&str], action: &str) -> Output {
    let output = run_session_cli(session, args).await;
    assert!(
        output.status.success(),
        "{} should be allowed to {action}:\n{}",
        session.identity.username,
        combined_output(&output)
    );
    output
}

async fn assert_workspace_allowed(
    session: &LoginSession,
    workspace: &str,
    args: &[&str],
    action: &str,
) -> Output {
    let output = run_workspace_cli(session, workspace, args).await;
    assert!(
        output.status.success(),
        "{} should be allowed to {action} in workspace {workspace}:\n{}",
        session.identity.username,
        combined_output(&output)
    );
    output
}

async fn prepare_workspace(
    admin: &LoginSession,
    member: &LoginSession,
    workspace: &str,
    role: &str,
) {
    let _ = run_session_cli(admin, &["workspace", "delete", workspace]).await;
    assert_allowed(
        admin,
        &["workspace", "create", "--name", workspace],
        "create a workspace fixture",
    )
    .await;
    assert_allowed(
        admin,
        &[
            "workspace",
            "member",
            "add",
            "--workspace",
            workspace,
            "--subject",
            &member.subject,
            "--role",
            role,
        ],
        "add a workspace member",
    )
    .await;
}

async fn prepare_isolated_workspaces(
    workspace_a: &str,
    workspace_b: &str,
) -> (LoginSession, LoginSession, LoginSession) {
    let admin = login_identity(ADMIN).await;
    let user_a = login_identity(USER).await;
    let user_b = login_identity(USER_B).await;
    prepare_workspace(&admin, &user_a, workspace_a, "user").await;
    prepare_workspace(&admin, &user_b, workspace_b, "user").await;
    (admin, user_a, user_b)
}

async fn prepare_isolated_workspaces_with_admin(
    workspace_a: &str,
    workspace_b: &str,
) -> (LoginSession, LoginSession, LoginSession) {
    let admin = login_identity(ADMIN).await;
    let workspace_admin = login_identity(USER).await;
    let user_b = login_identity(USER_B).await;
    prepare_workspace(&admin, &workspace_admin, workspace_a, "admin").await;
    prepare_workspace(&admin, &user_b, workspace_b, "user").await;
    (admin, workspace_admin, user_b)
}

async fn delete_workspace(admin: &LoginSession, workspace: &str) {
    for attempt in 0..30 {
        let output = run_session_cli(admin, &["workspace", "delete", workspace]).await;
        if output.status.success() {
            return;
        }
        let stderr = combined_output(&output);
        if !stderr.contains("still contains") {
            panic!(
                "{} should be allowed to delete workspace {workspace}:\n{stderr}",
                admin.identity.username
            );
        }
        if attempt == 29 {
            panic!("workspace {workspace} still contains resources after 30 retries:\n{stderr}");
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

// Keep RBAC fixtures running until cleanup so authorization checks do not also
// exercise fast canonical-process completion. That lifecycle belongs to the
// dedicated sandbox_lifecycle suite.
async fn assert_can_create_sandbox(session: &LoginSession, workspace: &str, sandbox_name: &str) {
    let create = run_workspace_cli(
        session,
        workspace,
        &[
            "sandbox",
            "create",
            "--name",
            sandbox_name,
            "--no-tty",
            "--detach",
            "--",
            "sleep",
            "infinity",
        ],
    )
    .await;
    let create_output = combined_output(&create);

    if !create.status.success() {
        let _ = run_workspace_cli(session, workspace, &["sandbox", "delete", sandbox_name]).await;
        panic!(
            "{} should be allowed to create sandbox {sandbox_name}:\n{create_output}",
            session.identity.username
        );
    }

    let list =
        run_workspace_cli(session, workspace, &["sandbox", "list", "--output", "json"]).await;
    let list_output = combined_output(&list);
    let cleanup = run_workspace_cli(session, workspace, &["sandbox", "delete", sandbox_name]).await;

    assert!(
        list.status.success() && list_output.contains(sandbox_name),
        "created sandbox {sandbox_name} should appear in the sandbox list:\n{list_output}"
    );
    assert!(
        cleanup.status.success(),
        "failed to clean up created sandbox {sandbox_name}:\n{}",
        combined_output(&cleanup)
    );
}

async fn assert_can_delete_sandbox(session: &LoginSession, workspace: &str, sandbox_name: &str) {
    let create = run_workspace_cli(
        session,
        workspace,
        &[
            "sandbox",
            "create",
            "--name",
            sandbox_name,
            "--no-tty",
            "--detach",
            "--",
            "sleep",
            "infinity",
        ],
    )
    .await;
    let create_output = combined_output(&create);
    if !create.status.success() {
        let _ = run_workspace_cli(session, workspace, &["sandbox", "delete", sandbox_name]).await;
        panic!("failed to create sandbox deletion target {sandbox_name}:\n{create_output}");
    }

    let delete = run_workspace_cli(session, workspace, &["sandbox", "delete", sandbox_name]).await;
    let delete_output = combined_output(&delete);
    if !delete.status.success() {
        let _ = run_workspace_cli(session, workspace, &["sandbox", "delete", sandbox_name]).await;
        panic!(
            "{} should be allowed to delete sandbox {sandbox_name}:\n{delete_output}",
            session.identity.username
        );
    }

    if let Err(last_list) = wait_for_sandbox_absence(session, workspace, sandbox_name).await {
        panic!(
            "deleted sandbox {sandbox_name} should disappear from the sandbox list:\n{last_list}"
        );
    }
}

async fn wait_for_sandbox_absence(
    session: &LoginSession,
    workspace: &str,
    sandbox_name: &str,
) -> Result<(), String> {
    const TIMEOUT: Duration = Duration::from_secs(30);
    const POLL_INTERVAL: Duration = Duration::from_millis(250);

    let deadline = Instant::now() + TIMEOUT;
    loop {
        let list =
            run_workspace_cli(session, workspace, &["sandbox", "list", "--output", "json"]).await;
        let list_output = combined_output(&list);
        if !list.status.success() {
            return Err(list_output);
        }

        let present = list_output.contains(sandbox_name);
        if !present {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(list_output);
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn run_session_cli(session: &LoginSession, args: &[&str]) -> Output {
    let mut command_args = Vec::with_capacity(args.len() + 2);
    command_args.extend(["--gateway", session.identity.gateway_name]);
    command_args.extend_from_slice(args);
    run_cli(session.config_home.path(), &command_args).await
}

async fn run_workspace_cli(session: &LoginSession, workspace: &str, args: &[&str]) -> Output {
    let mut command_args = Vec::with_capacity(args.len() + 4);
    command_args.extend([
        "--gateway",
        session.identity.gateway_name,
        "--workspace",
        workspace,
    ]);
    command_args.extend_from_slice(args);
    run_cli(session.config_home.path(), &command_args).await
}

fn assert_admin_role_denial(output: &Output, action: &str) {
    let denied = combined_output(output);
    let compact_denial: String = denied
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '│')
        .collect();
    assert!(
        !output.status.success() && compact_denial.contains("openshell-admin"),
        "standard user unexpectedly authorized to {action}, or denial omitted the admin role:\n{denied}"
    );
}

fn assert_workspace_admin_denial(
    output: &Output,
    session: &LoginSession,
    workspace: &str,
    action: &str,
) {
    let denied = combined_output(output);
    let remediation = format!(
        "openshell workspace member add --workspace '{workspace}' --subject '{}' --role admin",
        session.subject
    );
    let compact_denial: String = denied
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '│')
        .collect();
    let compact_remediation: String = remediation
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    assert!(
        !output.status.success()
            && compact_denial
                .to_ascii_lowercase()
                .contains("workspacerole'admin'")
            && compact_denial.contains(&compact_remediation),
        "workspace user unexpectedly authorized to {action}, or denial omitted the admin remediation command:\n{denied}"
    );
}

fn assert_platform_admin_denial(output: &Output, action: &str) {
    let denied = combined_output(output);
    assert!(
        !output.status.success() && denied.to_ascii_lowercase().contains("platform admin"),
        "non-platform-admin unexpectedly authorized to {action}, or denial omitted the required platform role:\n{denied}"
    );
}

fn assert_non_member_denial(output: &Output, action: &str) {
    let denied = combined_output(output);
    let compact_denial: String = denied
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '│')
        .collect();
    assert!(
        !output.status.success()
            && compact_denial
                .to_ascii_lowercase()
                .contains("notamemberofworkspace"),
        "non-member unexpectedly authorized to {action}, or denial omitted membership context:\n{denied}"
    );
}

async fn run_cli(config_home: &Path, args: &[&str]) -> Output {
    openshell_cmd()
        .arg("--gateway-insecure")
        .args(args)
        .env("XDG_CONFIG_HOME", config_home)
        .env("HOME", config_home)
        .env("OPENSHELL_GATEWAY_INSECURE", "true")
        .env_remove("OPENSHELL_GATEWAY")
        .env_remove("OPENSHELL_GATEWAY_ENDPOINT")
        .env_remove("OPENSHELL_OIDC_CLIENT_SECRET")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("run openshell authorization action")
}

fn combined_output(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn read_json(path: &Path) -> Value {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("parse {} as JSON: {error}", path.display()))
}

fn decode_jwt_claims(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("access token is a JWT");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("decode JWT claims");
    serde_json::from_slice(&bytes).expect("parse JWT claims")
}

fn jwt_audience_contains(audience: &Value, expected: &str) -> bool {
    audience.as_str() == Some(expected)
        || audience
            .as_array()
            .is_some_and(|values| values.iter().any(|value| value == expected))
}
