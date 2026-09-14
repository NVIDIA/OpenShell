// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"errors"
	"fmt"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
)

// CloudflareAccess returns an AuthProvider that adds Cloudflare Access
// headers to every RPC. It sets:
//   - cf-access-jwt-assertion: the edge JWT token
//   - cookie: CF_Authorization=<token>
//
// The edgeToken authenticates with the Cloudflare Access edge proxy.
// Returns an error if baseAuth is nil or edgeToken is empty.
func CloudflareAccess(baseAuth v1.AuthProvider, edgeToken string) (v1.AuthProvider, error) {
	if edgeToken == "" {
		return nil, errors.New("edge token must not be empty")
	}

	return v1.WithExtraHeaders(baseAuth, map[string]string{
		"cf-access-jwt-assertion": edgeToken,
		"cookie":                  fmt.Sprintf("CF_Authorization=%s", edgeToken),
	})
}
