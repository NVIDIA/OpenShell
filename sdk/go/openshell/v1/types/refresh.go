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

// RefreshRecoveryAction describes the action required after a refresh failure.
type RefreshRecoveryAction int

const (
	// RefreshRecoveryActionUnspecified means no recovery action is required.
	RefreshRecoveryActionUnspecified RefreshRecoveryAction = iota
	// RefreshRecoveryActionRetry means OpenShell will retry automatically.
	RefreshRecoveryActionRetry
	// RefreshRecoveryActionReauthorize means the user must replace the OAuth grant.
	RefreshRecoveryActionReauthorize
	// RefreshRecoveryActionFixConfiguration means an operator must repair configuration.
	RefreshRecoveryActionFixConfiguration
	// RefreshRecoveryActionInvestigate means the failure is not recognized.
	RefreshRecoveryActionInvestigate
)

// String returns the provider-neutral recovery action name.
func (a RefreshRecoveryAction) String() string {
	switch a {
	case RefreshRecoveryActionUnspecified:
		return "unspecified"
	case RefreshRecoveryActionRetry:
		return "retry"
	case RefreshRecoveryActionReauthorize:
		return "reauthorize"
	case RefreshRecoveryActionFixConfiguration:
		return "fix_configuration"
	case RefreshRecoveryActionInvestigate:
		return "investigate"
	default:
		return "unknown"
	}
}

// RefreshStatus reports the current state of credential refresh for a specific
// provider credential.
type RefreshStatus struct {
	ProviderName  string
	ProviderID    string
	CredentialKey string
	Strategy      RefreshStrategy
	Status        string
	ExpiresAt     time.Time
	// NextRefreshAt is zero when no automatic refresh is scheduled. Use
	// RecoveryAction to distinguish a parked refresh from an unset timestamp.
	NextRefreshAt        time.Time
	LastRefreshAt        time.Time
	LastError            string
	RecoveryAction       RefreshRecoveryAction
	FailureCode          string
	ProviderErrorSubtype string
	LastErrorAt          time.Time
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
