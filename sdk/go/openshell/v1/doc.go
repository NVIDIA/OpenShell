// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package v1 provides a Go SDK for interacting with OpenShell servers.
//
// The SDK follows the Kubernetes client-go sub-client pattern: a single Client
// provides typed accessors for each resource domain (Sandboxes, Providers, Exec,
// Files, Health, Services, SSH, TCP, Config, Policy, Workspaces, Inference). All operations accept a context.Context and return idiomatic
// Go types. Proto-generated types never appear in the public API.
//
// # Quick Start
//
//	client, err := v1.NewClient(v1.Config{
//	    Address: "gateway.example.com:443",
//	    Auth:    v1.StaticToken("my-token"),
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
// # Sandbox Lifecycle
//
//	sandbox, err := client.Sandboxes().Create(ctx, "default", "my-sandbox", &v1.SandboxSpec{
//	    Template: &v1.SandboxTemplate{Image: "python:3.12"},
//	    Environment: map[string]string{"LANG": "en_US.UTF-8"},
//	}, nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	sandbox, err = client.Sandboxes().WaitReady(ctx, "default", sandbox.Name)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Command Execution
//
//	result, err := client.Exec().Run(ctx, "default", sandbox.Name, []string{"echo", "hello"}, v1.ExecOptions{})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(string(result.Stdout)) // "hello\n"
//
// # Error Handling
//
//	_, err = client.Sandboxes().Get(ctx, "default", "missing")
//	if v1.IsNotFound(err) {
//	    // handle not found
//	}
//
// # Watching
//
//	watcher, err := client.Sandboxes().Watch(ctx, "default", sandbox.Name)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer watcher.Stop()
//	for event := range watcher.ResultChan() {
//	    fmt.Printf("%s: %s\n", event.Type, event.Object.Name)
//	}
//
// # Watching with StopOnTerminal
//
// Use StopOnTerminal to auto-close the watcher when the sandbox reaches a
// terminal phase (Ready or Error):
//
//	watcher, err := client.Sandboxes().Watch(ctx, "default", sandbox.Name,
//	    v1.WatchOptions{StopOnTerminal: true},
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for event := range watcher.ResultChan() {
//	    fmt.Printf("phase: %s\n", event.Object.Status.Phase)
//	}
//	// channel closes automatically after Ready or Error
//
// # Service Exposure
//
// Expose an HTTP service running inside a sandbox and retrieve its public URL:
//
//	endpoint, err := client.Services().Expose(ctx, "default", "my-sandbox", "api", 8080, true)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Service URL: %s\n", endpoint.URL)
//
//	endpoints, err := client.Services().List(ctx, "default", "my-sandbox")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, ep := range endpoints {
//	    fmt.Printf("  %s → port %d (URL: %s)\n", ep.ServiceName, ep.TargetPort, ep.URL)
//	}
//
// # Provider Profiles
//
// List available provider profiles and import new ones:
//
//	profiles, err := client.Providers().Profiles().List(ctx, "default")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, p := range profiles {
//	    fmt.Printf("%s (%s): %s\n", p.DisplayName, p.Category, p.Description)
//	}
//
//	result, err := client.Providers().Profiles().Import(ctx, "default", []v1.ProfileImportItem{
//	    {Source: "openai-profile.yaml", Profile: v1.ProviderProfile{
//	        DisplayName: "OpenAI",
//	        Category:    v1.ProfileCategoryInference,
//	    }},
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, d := range result.Diagnostics {
//	    fmt.Printf("[%s] %s: %s\n", d.Severity, d.Field, d.Message)
//	}
//
// # Credential Refresh
//
// Configure gateway-owned credential refresh for a provider:
//
//	status, err := client.Providers().Refresh().Configure(ctx, "default", &v1.RefreshConfig{
//	    Provider:      "openai",
//	    CredentialKey:  "api-key",
//	    Strategy:      v1.RefreshStrategyOAuth2ClientCredentials,
//	    Material:      map[string]string{"client_id": "xxx", "client_secret": "yyy"},
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Refresh status: %s (next: %s)\n", status.Status, status.NextRefreshAt)
//
// # Token Refresh
//
// Use RefreshableToken for automatic OAuth2 token caching and refresh.
// Concurrent callers share a single refresh call:
//
//	tokenSource := oauth2Config.TokenSource(ctx, initialToken)
//	auth, err := v1.RefreshableToken(tokenSource,
//	    v1.WithLeeway(30*time.Second),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	client, err := v1.NewClient(v1.Config{
//	    Address: "gateway.example.com:443",
//	    Auth:    auth,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
// # Extra Headers
//
// Use WithExtraHeaders to attach additional per-RPC headers to any auth
// provider. This is useful for edge proxies, API gateways, or any middleware
// that requires custom headers alongside standard authentication:
//
//	base := v1.StaticToken("my-token")
//	auth, err := v1.WithExtraHeaders(base, map[string]string{
//	    "x-proxy-key": "proxy-secret",
//	    "x-tenant-id": "acme-corp",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	client, err := v1.NewClient(v1.Config{
//	    Address: "gateway.example.com:443",
//	    Auth:    auth,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
// Keys are normalized to lowercase (per HTTP/2 RFC 9113). On key collision,
// extra headers take precedence over base auth headers. Empty-string values
// are silently dropped. WithExtraHeaders composes with any AuthProvider,
// including RefreshableToken:
//
//	tokenSource := oauth2Config.TokenSource(ctx, initialToken)
//	refreshAuth, err := v1.RefreshableToken(tokenSource)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	auth, err := v1.WithExtraHeaders(refreshAuth, map[string]string{
//	    "x-proxy-key": "proxy-secret",
//	})
//
// # SSH Session Management
//
// Create an SSH session for a sandbox and use the returned connection details.
// Note: CreateSession accepts a sandbox ID, not a name. For name-based access
// with automatic session cleanup, prefer SSH().Tunnel() instead.
//
//	session, err := client.SSH().CreateSession(ctx, "default", sandbox.ID)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("SSH to %s:%d (scheme: %s)\n",
//	    session.GatewayHost, session.GatewayPort, session.GatewayScheme)
//	fmt.Printf("Host key: %s\n", session.HostKeyFingerprint)
//	// Use session.Token to authenticate the SSH connection.
//
//	revoked, err := client.SSH().RevokeSession(ctx, "default", session.Token)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Session revoked: %v\n", revoked)
//
// # TCP Port Forwarding
//
// Forward a local connection to a port inside a sandbox:
//
//	conn, err := client.TCP().Forward(ctx, "default", "my-sandbox", 5432)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer conn.Close()
//
//	// conn implements io.ReadWriteCloser, use it like a net.Conn.
//	_, err = conn.Write([]byte("PING\n"))
//	if err != nil {
//	    log.Fatal(err)
//	}
//	buf := make([]byte, 1024)
//	n, err := conn.Read(buf)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Response: %s\n", buf[:n])
//
// Use WithForwardServiceID to tag the forwarding session with a service
// identifier for audit logging:
//
//	conn, err := client.TCP().Forward(ctx, "default", "my-sandbox", 5432,
//	    v1.WithForwardServiceID("billing-db"),
//	)
//
// # SSH Tunneling
//
// Create an SSH tunnel to a sandbox port in a single call. Tunnel combines
// session creation, TCP forwarding with an SSH relay target, and automatic
// session cleanup into one operation:
//
//	tunnel, err := client.SSH().Tunnel(ctx, "default", "my-sandbox", 22)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer tunnel.Close()
//
//	// tunnel implements io.ReadWriteCloser. The underlying SSH session
//	// is automatically revoked when Close is called.
//	_, err = tunnel.Write([]byte("SSH-2.0-client\r\n"))
//	if err != nil {
//	    log.Fatal(err)
//	}
//	buf := make([]byte, 256)
//	n, err := tunnel.Read(buf)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Server banner: %s\n", buf[:n])
//
// Use WithTunnelServiceID to associate a service identifier with the tunnel:
//
//	tunnel, err := client.SSH().Tunnel(ctx, "default", "my-sandbox", 22,
//	    v1.WithTunnelServiceID("dev-ssh"),
//	)
//
// # Sandbox Policy
//
// Set an initial security policy when creating a sandbox:
//
//	sandbox, err := client.Sandboxes().Create(ctx, "default", "secure-sandbox", &v1.SandboxSpec{
//	    Template: &v1.SandboxTemplate{Image: "python:3.12"},
//	    Policy: &v1.SandboxPolicy{
//	        Version: 1,
//	        Filesystem: &v1.FilesystemPolicy{
//	            IncludeWorkdir: true,
//	            ReadOnly:       []string{"/usr", "/lib"},
//	        },
//	        Process: &v1.ProcessPolicy{
//	            RunAsUser:  "sandbox",
//	            RunAsGroup: "sandbox",
//	        },
//	        NetworkPolicies: map[string]v1.NetworkPolicyRule{
//	            "allow-api": {
//	                Name: "allow-api",
//	                Endpoints: []v1.PolicyNetworkEndpoint{
//	                    {Host: "api.example.com", Port: 443, Protocol: "tcp"},
//	                },
//	            },
//	        },
//	    },
//	}, nil)
//
// Replace the full policy at runtime via configuration update:
//
//	result, err := client.Config().Update(ctx, "default", &v1.ConfigUpdate{
//	    Name: "secure-sandbox",
//	    Policy: &v1.SandboxPolicy{
//	        Version: 2,
//	        NetworkPolicies: map[string]v1.NetworkPolicyRule{
//	            "allow-all": {Name: "allow-all"},
//	        },
//	    },
//	})
//
// Read a policy back from revision history:
//
//	revisions, err := client.Policy().List(ctx, "default")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, rev := range revisions {
//	    if rev.Policy != nil {
//	        fmt.Printf("v%d: %d network rules\n", rev.Version, len(rev.Policy.NetworkPolicies))
//	    }
//	}
//
// # Global Policy
//
// List gateway-global policy revisions (no sandbox name or workspace needed):
//
//	revisions, err := client.Policy().List(ctx, "", v1.WithListGlobal(true))
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, rev := range revisions {
//	    fmt.Printf("Global v%d: %s\n", rev.Version, rev.Status)
//	}
//
// Get the status of a specific global policy version:
//
//	status, err := client.Policy().GetStatus(ctx, "", "",
//	    v1.WithStatusGlobal(true), v1.WithVersion(3),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Version %d status: %s\n", status.Revision.Version, status.Revision.Status)
//
// # Workspace Management
//
// Create and manage workspaces for multi-tenant resource isolation:
//
//	ws, err := client.Workspaces().Create(ctx, "team-alpha", map[string]string{
//	    "team": "alpha",
//	    "env":  "production",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Workspace %s created (phase: %s)\n", ws.Name, ws.Phase)
//
//	workspaces, err := client.Workspaces().List(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, w := range workspaces {
//	    fmt.Printf("  %s (phase: %s)\n", w.Name, w.Phase)
//	}
//
// # Workspace Members
//
// Manage workspace membership with role-based access:
//
//	member, err := client.Workspaces().AddMember(ctx, "team-alpha",
//	    "alice@example.com", v1.WorkspaceRoleAdmin)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Added %s as %s\n", member.PrincipalSubject, member.Role)
//
//	members, err := client.Workspaces().ListMembers(ctx, "team-alpha")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, m := range members {
//	    fmt.Printf("  %s (%s)\n", m.PrincipalSubject, m.Role)
//	}
//
// # Gateway Info
//
// Query gateway metadata and compute driver capabilities:
//
//	info, err := client.Health().GetGatewayInfo(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Gateway %s (status: %s)\n", info.Version, info.Status)
//	for _, d := range info.ComputeDrivers {
//	    fmt.Printf("  Driver: %s %s\n", d.DriverName, d.DriverVersion)
//	}
//
// # Current User
//
// Determine the identity of the authenticated caller:
//
//	user, err := client.Health().GetCurrentUser(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Logged in as %s (%s)\n", user.DisplayName, user.Subject)
//	fmt.Printf("Roles: %v, Scopes: %v\n", user.Roles, user.Scopes)
//
// # Configuration Management
//
// Read sandbox and gateway configuration, and update settings:
//
//	sbCfg, err := client.Config().GetSandbox(ctx, "default", "my-sandbox")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Config revision: %d\n", sbCfg.ConfigRevision)
//	for name, setting := range sbCfg.Settings {
//	    fmt.Printf("  %s = %v (scope: %s)\n", name, setting.Value, setting.Scope)
//	}
//
//	gwCfg, err := client.Config().GetGateway(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Gateway settings revision: %d\n", gwCfg.SettingsRevision)
//
//	result, err := client.Config().Update(ctx, "default", &v1.ConfigUpdate{
//	    Name:       "my-sandbox",
//	    SettingKey:  "max_tokens",
//	    SettingValue: &v1.SettingValue{
//	        Type:   v1.SettingValueInt,
//	        IntVal: 8192,
//	    },
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("New settings revision: %d\n", result.SettingsRevision)
//
// # Inference Route Management
//
// Configure workspace-scoped inference routing to control how inference
// requests are forwarded to upstream providers:
//
//	route, err := client.Inference().SetRoute(ctx, "my-workspace", &v1.InferenceRouteConfig{
//	    ProviderName: "openai",
//	    ModelID:      "gpt-4",
//	    RouteName:    "",  // empty string = default route
//	    TimeoutSecs:  120,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Route v%d: %s/%s\n", route.Version, route.ProviderName, route.ModelID)
//
//	route, err = client.Inference().GetRoute(ctx, "my-workspace", "")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Provider: %s, Model: %s\n", route.ProviderName, route.ModelID)
//
//	err = client.Inference().DeleteRoute(ctx, "my-workspace", "")
//	if err != nil {
//	    log.Fatal(err)
//	}
package v1
