// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import "fmt"

// SSHSession represents an SSH session created for a sandbox.
// The Token field is sensitive and MUST NOT be logged or included in error messages.
// The String() method redacts the token to prevent accidental exposure via fmt or logging.
type SSHSession struct {
	// SandboxID is the sandbox this session connects to.
	SandboxID string
	// Token is the session token for gateway tunnel authentication.
	// This is a sensitive credential — treat it like an API key.
	Token string
	// GatewayHost is the host for SSH proxy connection.
	GatewayHost string
	// GatewayPort is the gateway port (1-65535).
	GatewayPort uint32
	// GatewayScheme is the gateway protocol scheme ("http" or "https").
	GatewayScheme string
	// HostKeyFingerprint is the optional host key fingerprint.
	HostKeyFingerprint string
	// ExpiresAtMs is the session expiry in milliseconds since epoch.
	// Zero means no expiry.
	ExpiresAtMs int64
}

// String returns a human-readable representation with the Token redacted.
func (s SSHSession) String() string {
	return fmt.Sprintf("SSHSession{SandboxID:%s, GatewayHost:%s, GatewayPort:%d, GatewayScheme:%s, Token:[REDACTED]}",
		s.SandboxID, s.GatewayHost, s.GatewayPort, s.GatewayScheme)
}
