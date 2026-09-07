// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package edge provides utilities for connecting to OpenShell gateways
// through edge proxies such as Cloudflare Access. It includes convenience
// constructors for common edge auth patterns and a WebSocket tunnel proxy
// for gRPC transport through HTTP/1.1-only proxies.
//
// # Cloudflare Access
//
// CloudflareAccess wraps any AuthProvider with the headers required by
// Cloudflare Access (cf-access-jwt-assertion and CF_Authorization cookie).
// The edge token is typically a service token or application token obtained
// from Cloudflare:
//
//	base := v1.StaticToken("my-gateway-token")
//	auth, err := edge.CloudflareAccess(base, os.Getenv("CF_ACCESS_TOKEN"))
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
// CloudflareAccess composes with any auth provider, including RefreshableToken
// for automatic token refresh:
//
//	tokenSource := oauth2Config.TokenSource(ctx, initialToken)
//	refreshAuth, err := v1.RefreshableToken(tokenSource)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	auth, err := edge.CloudflareAccess(refreshAuth, cfToken)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # WebSocket Tunnel
//
// TunnelProxy bridges gRPC connections over a WebSocket tunnel for edge
// proxies that reject standard HTTP/2 POST requests. The tunnel carries
// its own edge token for proxy authentication, independent of the
// application-level auth provider.
//
// Create a tunnel proxy pointed at the gateway, then dial the proxy's
// local address from the gRPC client:
//
//	tunnel, err := edge.NewTunnelProxy(
//	    "wss://gateway.example.com/ws",
//	    os.Getenv("CF_ACCESS_TOKEN"),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer tunnel.Close()
//
//	auth := v1.StaticToken("my-gateway-token")
//	client, err := v1.NewClient(v1.Config{
//	    Address: tunnel.Addr(),
//	    Auth:    auth,
//	    TLS:     &v1.TLSConfig{Insecure: true}, // local tunnel
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
// Use functional options to configure TLS, logging, and close timeout:
//
//	tunnel, err := edge.NewTunnelProxy(
//	    "wss://gateway.example.com/ws",
//	    cfToken,
//	    edge.WithTunnelTLS(&tls.Config{RootCAs: customCertPool}),
//	    edge.WithTunnelLogger(myLogger),
//	    edge.WithCloseTimeout(10*time.Second),
//	)
//
// Close drains in-flight connections gracefully. If draining exceeds the
// configured timeout (default 5 seconds), remaining connections are
// force-closed:
//
//	err := tunnel.Close() // safe to call multiple times
package edge
