// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OIDC sign-in and workspace authorization against Keycloak.
//!
//! The gateway trusts the environment's Keycloak realm. Each test signs realm
//! users in with the password grant and checks what the gateway lets them
//! do, by gRPC status code and message. testkit's own connection is an mTLS
//! operator, which sets up and cleans up. The browser login runs once, and
//! a few checks run through the CLI, for what the CLI itself reports.

use std::collections::HashMap;
use std::fmt;

use keycloak_support::{BrowserLogin, KeycloakContext, OPENSHELL_SCOPES, Session, User};
use serde_json::Value;
use testkit::sdk::raw::{AuthedGrpcClient, proto};
use testkit::sdk::{DeleteOptions, ListOptions, OpenShellClient, SandboxSpec};
use testkit::{
    Context, Credential, DELETE_TIMEOUT, Error, GrpcCode, Profile, Result, ResultExt as _, YamlFile,
};
use url::Url;

const ADMIN_ROLE_REQUIRED: &str = "role 'openshell-admin' required";
const ONLY_PLATFORM_ADMINS: &str = "only platform admins can assign the workspace admin role";
/// The provider credential the test profile defines.
const CREDENTIAL_ENV: &str = "API_KEY";
const CREDENTIAL_VALUE: &str = "oidc-auth-test-value";
/// A subject no realm user has.
const FAKE_SUBJECT: &str = "oidc-fake-member";

/// The browser (PKCE) login: the CLI opens Keycloak's authorization page
/// with a PKCE challenge, receives the code on its loopback callback, and
/// saves a session the gateway accepts.
#[testkit::test]
async fn pkce_browser_login_persists_session(cx: &mut Context) -> Result {
    let kc = setup(cx).await?;
    let login = keycloak_support::browser_login(
        &kc,
        kc.keycloak(),
        User::User,
        "profile email openshell:all",
    )
    .await?;
    check_authorization_url(&login.authorization_url, kc.keycloak().issuer())?;
    let report = format!("{}{}", login.output.stdout, login.output.stderr);
    testkit::ensure!(
        report.contains("Authenticated successfully"),
        "gateway add did not report the login:\n{report}"
    );
    let subject = check_saved_session(&login, &kc)?;

    let whoami = login
        .cli(&kc)?
        .run(["whoami", "--output", "json"])
        .await?
        .success()?;
    let identity = json_object(&whoami.stdout)?;
    testkit::ensure!(
        identity["subject"] == subject.as_str(),
        "whoami with the saved session reported {identity}, expected subject {subject}"
    );
    Ok(())
}

/// `whoami` reports the identity the gateway validated from the token.
#[testkit::test]
async fn user_reports_gateway_validated_identity(cx: &mut Context) -> Result {
    let kc = setup(cx).await?;
    let user = kc.session(User::User).await?;
    let output = user
        .cli()
        .run(["whoami", "--output", "json"])
        .await?
        .success()?;
    let identity = json_object(&output.stdout)?;
    testkit::ensure!(
        identity["subject"] == user.subject()
            && identity["identity_provider"] == "oidc"
            && identity["roles"]
                .as_array()
                .is_some_and(|roles| roles.iter().any(|role| role == "openshell-user")),
        "whoami reported {identity}, expected subject {}, provider oidc and role openshell-user",
        user.subject()
    );
    Ok(())
}

/// A platform admin lists sandboxes and providers in a workspace it isn't a
/// member of, reads gateway info, manages a provider, and creates a
/// workspace.
#[testkit::test]
async fn platform_admin_smoke(cx: &mut Context) -> Result {
    let kc = setup(cx).await?;
    let ws = kc.workspace("adm").await?;
    let profile = ws.import_profile(&test_profile(&kc.name("pf"))?).await?;
    let admin = kc.session(User::Admin).await?;
    let mut grpc = raw(&admin).await?;

    admin
        .client()
        .workspace(ws.name())
        .list_all_sandboxes(ListOptions::default())
        .await
        .context("list sandboxes as platform admin")?;
    grpc.list_providers(list_providers(ws.name()))
        .await
        .context("list providers as platform admin")?;

    let info = grpc
        .get_gateway_info(proto::GetGatewayInfoRequest {})
        .await
        .context("get gateway info as platform admin")?
        .into_inner();
    let driver = kc.compute_driver().await?;
    testkit::ensure!(
        info.compute_drivers.iter().any(|d| d.name == driver),
        "gateway info for the platform admin lists drivers {:?}, expected {driver}",
        info.compute_drivers
            .iter()
            .map(|d| d.name.as_str())
            .collect::<Vec<_>>()
    );

    let provider = kc.name("prov");
    ws.track_provider(&provider);
    grpc.create_provider(provider_request(ws.name(), &provider, &profile))
        .await
        .context("create a provider as platform admin")?;
    let got = grpc
        .get_provider(proto::GetProviderRequest {
            workspace_scope: Some(proto::workspace_selector(ws.name())),
            name: provider.clone(),
        })
        .await
        .context("get the provider as platform admin")?
        .into_inner();
    let got_name = got
        .provider
        .and_then(|p| p.metadata)
        .map(|m| m.name)
        .unwrap_or_default();
    testkit::ensure!(
        got_name == provider,
        "provider get returned {got_name:?}, expected {provider}"
    );
    grpc.delete_provider(delete_provider(ws.name(), &provider))
        .await
        .context("delete the provider as platform admin")?;

    let created = kc.name("admw");
    delete_workspace_on_cleanup(&kc, admin.client(), &created);
    admin
        .client()
        .create_workspace(&created, HashMap::new())
        .await
        .context("create a workspace as platform admin")?;
    let got = admin.client().get_workspace(&created).await?;
    testkit::ensure!(
        got.name == created,
        "workspace get returned {}, expected {created}",
        got.name
    );
    Ok(())
}

/// Neither a plain user nor a workspace admin may read gateway info, or
/// create or delete workspaces.
#[testkit::test]
async fn non_admins_denied_platform_actions(cx: &mut Context) -> Result {
    let kc = setup(cx).await?;
    let ws = kc.workspace("pla").await?;
    let admin = kc.session(User::Admin).await?;
    let user = kc.session(User::User).await?;
    let ws_admin = kc.session(User::UserB).await?;
    ws.add_member(ws_admin.subject(), proto::WorkspaceRole::Admin)
        .await?;

    for (who, session) in [("user", &user), ("workspace admin", &ws_admin)] {
        let mut grpc = raw(session).await?;
        expect_denied(
            grpc.get_gateway_info(proto::GetGatewayInfoRequest {}).await,
            ADMIN_ROLE_REQUIRED,
            format!("get gateway info as {who}"),
        )?;
        let created = kc.name(if who == "user" { "nwu" } else { "nwa" });
        delete_workspace_on_cleanup(&kc, admin.client(), &created);
        expect_denied(
            session
                .client()
                .create_workspace(&created, HashMap::new())
                .await,
            ADMIN_ROLE_REQUIRED,
            format!("create a workspace as {who}"),
        )?;
        expect_denied(
            session
                .client()
                .delete_workspace(ws.name(), DeleteOptions::default())
                .await,
            ADMIN_ROLE_REQUIRED,
            format!("delete workspace {} as {who}", ws.name()),
        )?;
    }
    admin.client().get_workspace(ws.name()).await?;
    Ok(())
}

/// Members, as users or admins, read their workspace, its members, its
/// sandboxes and its providers, and see it in their workspace list.
#[testkit::test]
async fn workspace_user_read_access(cx: &mut Context) -> Result {
    let kc = setup(cx).await?;
    let user = kc.session(User::User).await?;
    for (suffix, role) in [
        ("rdu", proto::WorkspaceRole::User),
        ("rda", proto::WorkspaceRole::Admin),
    ] {
        let ws = kc.workspace(suffix).await?;
        ws.add_member(user.subject(), role).await?;
        let action = |what: &str| format!("{what} as a workspace {}", role.as_str_name());

        let got = user
            .client()
            .get_workspace(ws.name())
            .await
            .context(action("get the workspace"))?;
        testkit::ensure!(got.name == ws.name(), "workspace get returned {}", got.name);
        let listed = user
            .client()
            .list_all_workspaces(ListOptions::default())
            .await
            .context(action("list workspaces"))?;
        testkit::ensure!(
            listed.iter().any(|w| w.name == ws.name()),
            "{} is missing from the member's workspace list",
            ws.name()
        );
        let members = members(&mut raw(&user).await?, ws.name())
            .await
            .context(action("list members"))?;
        testkit::ensure!(
            members.iter().any(|m| m == user.subject()),
            "the member list of {} is missing {}: {members:?}",
            ws.name(),
            user.subject()
        );
        user.client()
            .workspace(ws.name())
            .list_all_sandboxes(ListOptions::default())
            .await
            .context(action("list sandboxes"))?;
        raw(&user)
            .await?
            .list_providers(list_providers(ws.name()))
            .await
            .context(action("list providers"))?;
    }
    Ok(())
}

/// A platform admin and a workspace user each create a sandbox in the
/// workspace, see it listed, and delete it.
#[testkit::test]
async fn sandbox_create_delete_by_role(cx: &mut Context) -> Result {
    let kc = setup(cx).await?;
    let ws = kc.workspace("sbx").await?;
    let admin = kc.session(User::Admin).await?;
    let user = kc.session(User::User).await?;
    ws.add_member(user.subject(), proto::WorkspaceRole::User)
        .await?;

    for (suffix, session) in [("sba", &admin), ("sbu", &user)] {
        let name = kc.name(suffix);
        let client = session.client().workspace(ws.name());
        let who = session.username();
        ws.track_sandbox(&name);
        // Keep the sandbox running, so this checks authorization rather
        // than how fast a finished command's sandbox goes.
        client
            .create_sandbox(SandboxSpec {
                name: Some(name.clone()),
                command: vec!["sleep".to_string(), "infinity".to_string()],
                ..SandboxSpec::default()
            })
            .await
            .context(format!("create sandbox {name} as {who}"))?;
        let listed = sandbox_names(&client.list_all_sandboxes(ListOptions::default()).await?);
        testkit::ensure!(
            listed.contains(&name),
            "{who}'s sandbox list is missing {name}: {listed:?}"
        );
        client
            .delete_sandbox(&name, DeleteOptions::default())
            .await
            .context(format!("delete sandbox {name} as {who}"))?;
        client.wait_deleted(&name, DELETE_TIMEOUT, None).await?;
        let listed = sandbox_names(&client.list_all_sandboxes(ListOptions::default()).await?);
        testkit::ensure!(
            !listed.contains(&name),
            "{name} is still listed after {who} deleted it: {listed:?}"
        );
    }
    Ok(())
}

/// A workspace user may not create or delete providers, or manage members.
/// The CLI tells them how to get the admin role.
#[testkit::test]
async fn workspace_user_denied_management(cx: &mut Context) -> Result {
    let kc = setup(cx).await?;
    let ws = kc.workspace("wum").await?;
    let profile = ws.import_profile(&test_profile(&kc.name("pf"))?).await?;
    let admin = kc.session(User::Admin).await?;
    let user = kc.session(User::User).await?;
    ws.add_member(user.subject(), proto::WorkspaceRole::User)
        .await?;
    let target = kc.name("tgt");
    ws.track_provider(&target);
    raw(&admin)
        .await?
        .create_provider(provider_request(ws.name(), &target, &profile))
        .await
        .context("create the provider to delete")?;

    let needs_admin = format!(
        "workspace role 'admin' required in workspace '{}'",
        ws.name()
    );
    let mut grpc = raw(&user).await?;
    let created = kc.name("new");
    ws.track_provider(&created);
    expect_denied(
        grpc.create_provider(provider_request(ws.name(), &created, &profile))
            .await,
        &needs_admin,
        "create a provider as a workspace user",
    )?;
    expect_denied(
        grpc.delete_provider(delete_provider(ws.name(), &target))
            .await,
        &needs_admin,
        "delete a provider as a workspace user",
    )?;
    expect_denied(
        grpc.add_workspace_member(add_member(
            ws.name(),
            FAKE_SUBJECT,
            proto::WorkspaceRole::User,
        ))
        .await,
        &needs_admin,
        "add a member as a workspace user",
    )?;
    raw(&admin)
        .await?
        .get_provider(proto::GetProviderRequest {
            workspace_scope: Some(proto::workspace_selector(ws.name())),
            name: target.clone(),
        })
        .await
        .context("the denied delete left the provider")?;

    let denied = user
        .cli_in(ws.name())
        .run([
            "workspace",
            "member",
            "add",
            "--workspace",
            ws.name(),
            "--subject",
            FAKE_SUBJECT,
            "--role",
            "user",
        ])
        .await?
        .failure()?;
    let report = compact(&denied.report_text());
    let remediation = compact(&format!(
        "openshell workspace member add --workspace '{}' --subject '{}' --role admin",
        ws.name(),
        user.subject()
    ));
    testkit::ensure!(
        report.contains(&compact("workspace role 'admin'")) && report.contains(&remediation),
        "the denial does not tell the user how to get the admin role:\n{}",
        denied.report_text()
    );
    Ok(())
}

/// A workspace admin creates and deletes providers and adds and removes
/// members. A removed member, by the workspace admin or a platform admin,
/// loses access.
#[testkit::test]
async fn workspace_admin_manages_providers_and_members(cx: &mut Context) -> Result {
    let kc = setup(cx).await?;
    let ws = kc.workspace("wam").await?;
    let profile = ws.import_profile(&test_profile(&kc.name("pf"))?).await?;
    let admin = kc.session(User::Admin).await?;
    let ws_admin = kc.session(User::User).await?;
    let member = kc.session(User::UserB).await?;
    ws.add_member(ws_admin.subject(), proto::WorkspaceRole::Admin)
        .await?;
    let mut grpc = raw(&ws_admin).await?;

    let created = kc.name("own");
    ws.track_provider(&created);
    grpc.create_provider(provider_request(ws.name(), &created, &profile))
        .await
        .context("create a provider as workspace admin")?;
    let target = kc.name("tgt");
    ws.track_provider(&target);
    raw(&admin)
        .await?
        .create_provider(provider_request(ws.name(), &target, &profile))
        .await
        .context("create the provider to delete")?;
    grpc.delete_provider(delete_provider(ws.name(), &target))
        .await
        .context("delete a provider as workspace admin")?;

    grpc.add_workspace_member(add_member(
        ws.name(),
        member.subject(),
        proto::WorkspaceRole::User,
    ))
    .await
    .context("add a member as workspace admin")?;
    let listed = members(&mut grpc, ws.name()).await?;
    testkit::ensure!(
        listed.iter().any(|m| m == member.subject()),
        "the added member is not listed: {listed:?}"
    );
    member
        .client()
        .get_workspace(ws.name())
        .await
        .context("get the workspace as the added member")?;

    let not_member = format!("not a member of workspace '{}'", ws.name());
    grpc.remove_workspace_member(remove_member(ws.name(), member.subject()))
        .await
        .context("remove a member as workspace admin")?;
    expect_denied(
        member.client().get_workspace(ws.name()).await,
        &not_member,
        "get the workspace after the workspace admin removed the member",
    )?;

    raw(&admin)
        .await?
        .add_workspace_member(add_member(
            ws.name(),
            member.subject(),
            proto::WorkspaceRole::User,
        ))
        .await
        .context("add the member back as platform admin")?;
    raw(&admin)
        .await?
        .remove_workspace_member(remove_member(ws.name(), member.subject()))
        .await
        .context("remove the member as platform admin")?;
    expect_denied(
        member.client().get_workspace(ws.name()).await,
        &not_member,
        "get the workspace after a platform admin removed the member",
    )?;
    Ok(())
}

/// Only a platform admin may make a member a workspace admin.
#[testkit::test]
async fn workspace_admin_cannot_grant_admin(cx: &mut Context) -> Result {
    let kc = setup(cx).await?;
    let ws = kc.workspace("wag").await?;
    let ws_admin = kc.session(User::User).await?;
    ws.add_member(ws_admin.subject(), proto::WorkspaceRole::Admin)
        .await?;
    let mut grpc = raw(&ws_admin).await?;
    expect_denied(
        grpc.add_workspace_member(add_member(
            ws.name(),
            FAKE_SUBJECT,
            proto::WorkspaceRole::Admin,
        ))
        .await,
        ONLY_PLATFORM_ADMINS,
        "grant the workspace admin role as workspace admin",
    )?;
    let listed = members(&mut grpc, ws.name()).await?;
    testkit::ensure!(
        !listed.iter().any(|m| m == FAKE_SUBJECT),
        "the denied grant added a member: {listed:?}"
    );
    Ok(())
}

/// Being an admin or a user of one workspace gives no access to another.
#[testkit::test]
async fn cross_workspace_access_denied(cx: &mut Context) -> Result {
    let kc = setup(cx).await?;
    let ws_a = kc.workspace("xa").await?;
    let ws_b = kc.workspace("xb").await?;
    let admin = kc.session(User::Admin).await?;
    let user = kc.session(User::User).await?;
    let user_b = kc.session(User::UserB).await?;
    ws_b.add_member(user_b.subject(), proto::WorkspaceRole::User)
        .await?;
    let b = ws_b.name();
    let not_member = format!("not a member of workspace '{b}'");

    for (suffix, role) in [
        ("xsa", proto::WorkspaceRole::Admin),
        ("xsu", proto::WorkspaceRole::User),
    ] {
        ws_a.add_member(user.subject(), role).await?;
        let who = format!("a workspace {} of {}", role.as_str_name(), ws_a.name());
        let mut grpc = raw(&user).await?;
        let client = user.client();

        expect_denied(
            client.get_workspace(b).await,
            &not_member,
            format!("get {b} as {who}"),
        )?;
        expect_denied(
            grpc.list_workspace_members(list_members(b)).await,
            &not_member,
            format!("list the members of {b} as {who}"),
        )?;
        expect_denied(
            grpc.add_workspace_member(add_member(b, FAKE_SUBJECT, proto::WorkspaceRole::User))
                .await,
            &not_member,
            format!("add a member to {b} as {who}"),
        )?;
        expect_denied(
            client
                .workspace(b)
                .list_all_sandboxes(ListOptions::default())
                .await,
            &not_member,
            format!("list the sandboxes in {b} as {who}"),
        )?;
        expect_denied(
            grpc.list_providers(list_providers(b)).await,
            &not_member,
            format!("list the providers in {b} as {who}"),
        )?;
        let sandbox = kc.name(suffix);
        ws_b.track_sandbox(&sandbox);
        expect_denied(
            client
                .workspace(b)
                .create_sandbox(SandboxSpec {
                    name: Some(sandbox.clone()),
                    command: vec!["sleep".to_string(), "infinity".to_string()],
                    ..SandboxSpec::default()
                })
                .await,
            &not_member,
            format!("create a sandbox in {b} as {who}"),
        )?;
        ws_a.remove_member(user.subject()).await?;
    }

    let listed = sandbox_names(
        &admin
            .client()
            .workspace(b)
            .list_all_sandboxes(ListOptions::default())
            .await?,
    );
    testkit::ensure!(
        listed.is_empty(),
        "the denied creates left sandboxes in {b}: {listed:?}"
    );
    Ok(())
}

/// A user's workspace list shows their own workspace and hides another
/// user's and `default`.
#[testkit::test]
async fn workspace_list_hides_other_workspaces(cx: &mut Context) -> Result {
    let kc = setup(cx).await?;
    let ws_a = kc.workspace("la").await?;
    let ws_b = kc.workspace("lb").await?;
    let user = kc.session(User::User).await?;
    let user_b = kc.session(User::UserB).await?;
    ws_a.add_member(user.subject(), proto::WorkspaceRole::User)
        .await?;
    ws_b.add_member(user_b.subject(), proto::WorkspaceRole::User)
        .await?;

    let names: Vec<String> = user
        .client()
        .list_all_workspaces(ListOptions::default())
        .await
        .context("list workspaces as a user")?
        .into_iter()
        .map(|w| w.name)
        .collect();
    testkit::ensure!(
        names.iter().any(|n| n == ws_a.name()),
        "the user's workspace list is missing {}: {names:?}",
        ws_a.name()
    );
    testkit::ensure!(
        !names.iter().any(|n| n == ws_b.name() || n == "default"),
        "the user's workspace list shows a workspace they aren't a member of: {names:?}"
    );
    Ok(())
}

/// A workspace admin can't create a provider in another workspace. The CLI
/// reports a permission denial without the credential, and the workspace
/// gets no provider.
#[testkit::test]
async fn workspace_admin_cannot_manage_another_workspace_providers(cx: &mut Context) -> Result {
    let kc = setup(cx).await?;
    let ws_a = kc.workspace("pa").await?;
    let ws_b = kc.workspace("pb").await?;
    let admin = kc.session(User::Admin).await?;
    let ws_admin = kc.session(User::User).await?;
    let user_b = kc.session(User::UserB).await?;
    ws_a.add_member(ws_admin.subject(), proto::WorkspaceRole::Admin)
        .await?;
    ws_b.add_member(user_b.subject(), proto::WorkspaceRole::User)
        .await?;
    let provider = kc.name("xprov");
    ws_b.track_provider(&provider);

    let credential = format!("OPENAI_API_KEY={CREDENTIAL_VALUE}");
    let denied = ws_admin
        .cli_in(ws_b.name())
        .run([
            "provider",
            "create",
            "--name",
            &provider,
            "--type",
            "openai",
            "--credential",
            &credential,
        ])
        .await?
        .failure()?;
    // The profile lookup redacts the gateway's membership details, so check
    // the code and the guidance.
    let report = compact(&denied.report_text());
    testkit::ensure!(
        report.contains("PERMISSION_DENIED")
            && report.contains("verifyworkspacemembershipandrequiredpermissions"),
        "the cross-workspace provider create did not report a permission denial:\n{}",
        denied.report_text()
    );
    testkit::ensure!(
        !denied.stdout.contains(CREDENTIAL_VALUE) && !denied.stderr.contains(CREDENTIAL_VALUE),
        "the denial printed the credential value"
    );

    // Ask as another identity, so a provider created before the denial
    // can't hide behind the failed command.
    let listing = raw(&admin)
        .await?
        .list_providers(list_providers(ws_b.name()))
        .await
        .context("list providers as platform admin")?
        .into_inner();
    testkit::ensure!(
        listing.providers.is_empty() && listing.next_page_token.is_empty(),
        "the denied create left providers in {}: {:?}",
        ws_b.name(),
        listing
            .providers
            .iter()
            .filter_map(|p| p.metadata.as_ref().map(|m| m.name.as_str()))
            .collect::<Vec<_>>()
    );
    Ok(())
}

/// A workspace user naming a platform provider profile with `--provider`
/// gets past the profile lookup without a platform-admin check.
#[testkit::test]
async fn user_can_resolve_provider_profile_for_sandbox(cx: &mut Context) -> Result {
    let kc = setup(cx).await?;
    let ws = kc.workspace("rp").await?;
    let user = kc.session(User::User).await?;
    ws.add_member(user.subject(), proto::WorkspaceRole::User)
        .await?;
    let profile = import_platform_profile(&kc, &kc.name("gpf")).await?;
    let sandbox = kc.name("rps");
    ws.track_sandbox(&sandbox);

    // No provider of the profile's type exists, and without a terminal the
    // CLI can't offer to create one, so it stops there. That error means
    // the lookup worked; a permission error would mean the user was kept
    // out of the catalog.
    let output = user
        .cli_in(ws.name())
        .run([
            "sandbox",
            "create",
            "--name",
            &sandbox,
            "--no-tty",
            "--provider",
            &profile,
        ])
        .await?;
    let report = output.report_text();
    testkit::ensure!(
        !report.to_ascii_lowercase().contains("platform admin"),
        "the workspace user hit a platform-admin check resolving the profile:\n{report}"
    );
    testkit::ensure!(
        report.contains("missing required provider"),
        "expected the missing-provider error, got:\n{report}"
    );
    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Read the Keycloak configuration and check testkit connects as an
/// operator, which the tests' setup and cleanup need.
async fn setup(cx: &mut Context) -> Result<KeycloakContext<'_>> {
    let kc = KeycloakContext::new(cx).await?;
    let operator = kc.cli_handle().gateway().connect().await?;
    match operator
        .raw_grpc_fresh()
        .await?
        .get_current_user(proto::GetCurrentUserRequest {})
        .await
    {
        Err(status) if status.code() == GrpcCode::PermissionDenied => Ok(kc),
        Err(status) => Err(Error::from(status).context("check testkit connects as an operator")),
        Ok(user) => Err(Error::msg(format!(
            "testkit's client certificate signs in as user {:?} ({}), not as an operator; \
             the <base>-oidc environment makes it an operator's (roles/oidc_gateway)",
            user.get_ref().subject,
            user.get_ref().identity_provider
        ))),
    }
}

async fn raw(session: &Session) -> Result<AuthedGrpcClient> {
    Ok(session.client().raw_grpc_fresh().await?)
}

/// Fail unless `result` is a permission denial whose message contains
/// `message`.
fn expect_denied<T, E: Into<Error>>(
    result: std::result::Result<T, E>,
    message: &str,
    action: impl fmt::Display,
) -> Result {
    let error = match result {
        Ok(_) => return Err(Error::msg(format!("{action}: allowed, expected a denial"))),
        Err(error) => error.into(),
    };
    testkit::ensure!(
        error.grpc_code() == Some(GrpcCode::PermissionDenied)
            && error.to_string().contains(message),
        "{action}: expected PERMISSION_DENIED with {message:?}, got {:?}: {error}",
        error.grpc_code()
    );
    Ok(())
}

/// A profile whose providers need one credential.
fn test_profile(id: &str) -> Result<String> {
    Profile::new(id)
        .credential(
            Credential::new("api_key")
                .env_var(CREDENTIAL_ENV)
                .required(),
        )
        .to_yaml()
}

/// Import a profile at platform scope as the operator, with cleanup.
async fn import_platform_profile(cx: &Context, id: &str) -> Result<String> {
    let cli = cx.cli_handle();
    let owned = id.to_string();
    cx.on_cleanup(format!("delete platform profile {id}"), async move || {
        cli.run(["profile", "delete", "--global", &owned])
            .await?
            .success()?;
        Ok(())
    });
    let file = YamlFile::new(&test_profile(id)?)?;
    cx.cli(["profile", "import", "--global", "--file", file.path()?])
        .await?
        .success()
        .context(format!("import platform profile {id}"))?;
    Ok(id.to_string())
}

/// Delete workspace `name`, which a test asks the gateway to create, when
/// the test ends, as `admin`.
fn delete_workspace_on_cleanup(cx: &Context, admin: &OpenShellClient, name: &str) {
    let admin = admin.clone();
    let owned = name.to_string();
    cx.on_cleanup(format!("delete workspace {name}"), async move || {
        admin
            .delete_workspace(
                &owned,
                DeleteOptions {
                    allow_missing: true,
                },
            )
            .await?;
        Ok(())
    });
}

fn provider_request(workspace: &str, name: &str, profile: &str) -> proto::CreateProviderRequest {
    proto::CreateProviderRequest {
        workspace_scope: Some(proto::workspace_selector(workspace)),
        provider: Some(proto::Provider {
            metadata: Some(proto::ObjectMeta {
                name: name.to_string(),
                workspace: workspace.to_string(),
                ..Default::default()
            }),
            r#type: profile.to_string(),
            credentials: [(CREDENTIAL_ENV.to_string(), CREDENTIAL_VALUE.to_string())].into(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn delete_provider(workspace: &str, name: &str) -> proto::DeleteProviderRequest {
    proto::DeleteProviderRequest {
        workspace_scope: Some(proto::workspace_selector(workspace)),
        name: name.to_string(),
        ..Default::default()
    }
}

fn list_providers(workspace: &str) -> proto::ListProvidersRequest {
    proto::ListProvidersRequest {
        workspace_scope: Some(proto::workspace_selector(workspace)),
        ..Default::default()
    }
}

fn add_member(
    workspace: &str,
    subject: &str,
    role: proto::WorkspaceRole,
) -> proto::AddWorkspaceMemberRequest {
    proto::AddWorkspaceMemberRequest {
        workspace_scope: Some(proto::workspace_selector(workspace)),
        principal_subject: subject.to_string(),
        role: role.into(),
        ..Default::default()
    }
}

fn remove_member(workspace: &str, subject: &str) -> proto::RemoveWorkspaceMemberRequest {
    proto::RemoveWorkspaceMemberRequest {
        workspace_scope: Some(proto::workspace_selector(workspace)),
        principal_subject: subject.to_string(),
        ..Default::default()
    }
}

fn list_members(workspace: &str) -> proto::ListWorkspaceMembersRequest {
    proto::ListWorkspaceMembersRequest {
        workspace_scope: Some(proto::workspace_selector(workspace)),
        ..Default::default()
    }
}

/// The subjects of `workspace`'s members. The test workspaces have a few
/// members, so the first page holds them all.
async fn members(grpc: &mut AuthedGrpcClient, workspace: &str) -> Result<Vec<String>> {
    let response = grpc
        .list_workspace_members(list_members(workspace))
        .await
        .context(format!("list the members of {workspace}"))?
        .into_inner();
    testkit::ensure!(
        response.next_page_token.is_empty(),
        "the members of {workspace} span more than one page"
    );
    Ok(response
        .members
        .into_iter()
        .map(|m| m.principal_subject)
        .collect())
}

fn sandbox_names(sandboxes: &[testkit::sdk::SandboxRef]) -> Vec<String> {
    sandboxes.iter().map(|s| s.name.clone()).collect()
}

/// `text` without whitespace, for matching an error report the CLI may wrap
/// inside a word, such as a quoted command.
fn compact(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// The JSON object in `stdout`. The CLI may print startup notices before
/// it.
fn json_object(stdout: &str) -> Result<Value> {
    let start = stdout.find('{');
    let end = stdout.rfind('}');
    let (Some(start), Some(end)) = (start, end) else {
        return Err(Error::msg(format!(
            "no JSON object in the output:\n{stdout}"
        )));
    };
    serde_json::from_str(&stdout[start..=end]).context("parse the CLI's JSON output")
}

/// Check the URL the CLI opened asks Keycloak for a PKCE (S256) code with
/// the requested scopes, returned to the CLI's loopback callback.
fn check_authorization_url(url: &Url, issuer: &str) -> Result {
    let issuer = Url::parse(issuer).map_err(|e| Error::msg(format!("parse {issuer}: {e}")))?;
    let expected_path = format!(
        "{}/protocol/openid-connect/auth",
        issuer.path().trim_end_matches('/')
    );
    testkit::ensure!(
        url.path() == expected_path,
        "authorization URL {url} is not {expected_path}"
    );
    let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
    let param = |name: &str| params.get(name).map(String::as_str).unwrap_or_default();
    testkit::ensure!(
        param("response_type") == "code"
            && param("client_id") == "openshell-cli"
            && param("code_challenge_method") == "S256",
        "authorization URL {url} does not ask for a PKCE code for openshell-cli"
    );
    let challenge = param("code_challenge");
    testkit::ensure!(
        challenge.len() == 43
            && challenge
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
        "PKCE challenge {challenge:?} is not an unpadded base64url SHA-256"
    );
    testkit::ensure!(
        !param("state").is_empty(),
        "authorization URL {url} has no state"
    );
    let scopes: Vec<&str> = param("scope").split_whitespace().collect();
    for scope in OPENSHELL_SCOPES.split_whitespace() {
        testkit::ensure!(
            scopes.contains(&scope),
            "authorization URL scopes {scopes:?} lack {scope}"
        );
    }
    let redirect = Url::parse(param("redirect_uri"))
        .map_err(|e| Error::msg(format!("parse the redirect URI in {url}: {e}")))?;
    testkit::ensure!(
        redirect.scheme() == "http"
            && redirect.host_str() == Some("127.0.0.1")
            && redirect.port().is_some()
            && redirect.path() == "/callback",
        "redirect URI {redirect} is not the CLI's loopback callback"
    );
    Ok(())
}

/// Check the CLI saved the OIDC registration and the user's tokens, and
/// return the token's subject.
fn check_saved_session(login: &BrowserLogin, kc: &KeycloakContext<'_>) -> Result<String> {
    let keycloak = kc.keycloak();
    let dir = login.gateway_dir();
    let metadata = read_json(&dir.join("metadata.json"))?;
    testkit::ensure!(
        metadata["auth_mode"] == "oidc"
            && metadata["oidc_issuer"] == keycloak.issuer()
            && metadata["oidc_client_id"] == keycloak.client_id()
            && metadata["oidc_scopes"] == "profile email openshell:all",
        "the saved registration is not the OIDC one: {metadata}"
    );
    let token = read_json(&dir.join("oidc_token.json"))?;
    let access_token = token["access_token"].as_str().unwrap_or_default();
    testkit::ensure!(
        !access_token.is_empty()
            && token["refresh_token"]
                .as_str()
                .is_some_and(|t| !t.is_empty())
            && token["issuer"] == keycloak.issuer()
            && token["client_id"] == keycloak.client_id(),
        "the saved token file lacks the access token, refresh token, issuer or client"
    );
    let (username, _) = keycloak.credentials(User::User)?;
    let claims = keycloak_support::claims(access_token)?;
    testkit::ensure!(
        keycloak_support::audience_contains(&claims, "openshell-cli")
            && claims["azp"] == "openshell-cli"
            && claims["preferred_username"] == username.as_str()
            && keycloak_support::has_realm_role(&claims, "openshell-user"),
        "the saved access token's claims are not the user's: {claims}"
    );
    keycloak_support::subject(access_token)
}

fn read_json(path: &std::path::Path) -> Result<Value> {
    let text = std::fs::read_to_string(path).context(format!("read {}", path.display()))?;
    serde_json::from_str(&text).context(format!("parse {}", path.display()))
}
