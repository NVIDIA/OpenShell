// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// RefreshStrategy describes how credentials are refreshed.
type RefreshStrategy = types.RefreshStrategy

// RefreshStatus reports the current state of credential refresh for a provider credential.
type RefreshStatus = types.RefreshStatus

// RefreshConfig holds configuration parameters for credential refresh.
type RefreshConfig = types.RefreshConfig

// RefreshStrategy values.
const (
	RefreshStrategyStatic                  = types.RefreshStrategyStatic
	RefreshStrategyExternal                = types.RefreshStrategyExternal
	RefreshStrategyOAuth2RefreshToken      = types.RefreshStrategyOAuth2RefreshToken
	RefreshStrategyOAuth2ClientCredentials = types.RefreshStrategyOAuth2ClientCredentials
	RefreshStrategyGoogleServiceAccountJWT = types.RefreshStrategyGoogleServiceAccountJWT
)

// RefreshInterface defines operations for managing provider credential refresh.
type RefreshInterface interface {
	GetStatus(ctx context.Context, workspace, provider, credentialKey string) ([]*RefreshStatus, error)
	Configure(ctx context.Context, workspace string, config *RefreshConfig) (*RefreshStatus, error)
	Rotate(ctx context.Context, workspace, provider, credentialKey string) (*RefreshStatus, error)
	Delete(ctx context.Context, workspace, provider, credentialKey string) (bool, error)
}
