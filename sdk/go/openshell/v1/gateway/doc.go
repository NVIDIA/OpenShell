// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package gateway reads on-disk gateway configurations created by the
// OpenShell Rust CLI and constructs fully wired SDK clients.
//
// The package resolves XDG config paths, validates gateway names, loads
// tokens lazily, maps auth modes to existing auth providers, and provides
// one-call convenience constructors. This eliminates 20+ lines of
// boilerplate for Go programs connecting to gateways managed by the CLI.
//
// # Quick Start
//
// Connect to a named gateway:
//
//	client, err := gateway.NewClient("prod")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
// Connect to the active gateway (set via `openshell gateway use`):
//
//	client, err := gateway.NewClient("")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
// Inspect configuration without creating a client:
//
//	cfg, err := gateway.LoadConfig("staging")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Endpoint: %s, Auth: %s\n", cfg.Endpoint, cfg.AuthMode)
//
// List all configured gateways:
//
//	gateways, err := gateway.ListGateways()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, gw := range gateways {
//	    fmt.Printf("%s (active=%v, source=%s)\n", gw.Name, gw.Active, gw.Source)
//	}
//
// # On-Disk Layout
//
// The package reads gateway metadata from the following locations:
//
//	$XDG_CONFIG_HOME/openshell/gateways/<name>/metadata.json   (user)
//	/etc/openshell/gateways/<name>/metadata.json                (system)
//
// Token files (edge_token, cf_token, oidc_token.json) sit alongside
// metadata.json and are loaded lazily on first authentication attempt.
//
// # Error Handling
//
// The package provides typed errors for precise failure classification:
//
//   - [ErrGatewayNotFound]: no gateway directory found
//   - [ErrConfigParse]: metadata.json missing or malformed
//   - [ErrTokenLoad]: token file missing or unreadable
//   - [ErrUnsupportedAuthMode]: unrecognized auth_mode value
//   - [ErrInvalidGatewayName]: name fails validation
//   - [ErrNoActiveGateway]: no active gateway configured
//
// All errors support [errors.Is] for classification.
//
// # Thread Safety
//
// All exported functions are safe for concurrent use from multiple
// goroutines.
package gateway
