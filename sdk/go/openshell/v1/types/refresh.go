// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// RefreshStrategy describes how credentials are refreshed.
type RefreshStrategy string

// RefreshStrategy values.
const (
	RefreshStrategyStatic                  RefreshStrategy = "Static"
	RefreshStrategyExternal                RefreshStrategy = "External"
	RefreshStrategyOAuth2RefreshToken      RefreshStrategy = "OAuth2RefreshToken"
	RefreshStrategyOAuth2ClientCredentials RefreshStrategy = "OAuth2ClientCredentials"
	RefreshStrategyGoogleServiceAccountJWT RefreshStrategy = "GoogleServiceAccountJWT"
	RefreshStrategyAWSStsAssumeRole        RefreshStrategy = "AWSStsAssumeRole"
)

// RefreshStatus reports the current state of credential refresh for a specific
// provider credential.
type RefreshStatus struct {
	ProviderName  string
	ProviderID    string
	CredentialKey string
	Strategy      RefreshStrategy
	Status        string
	ExpiresAt     time.Time
	NextRefreshAt time.Time
	LastRefreshAt time.Time
	LastError     string
}

// RefreshConfig holds configuration parameters for gateway-owned credential
// refresh on a provider credential.
type RefreshConfig struct {
	Provider           string
	CredentialKey      string
	Strategy           RefreshStrategy
	Material           map[string]string
	SecretMaterialKeys []string
	ExpiresAt          *time.Time
}
