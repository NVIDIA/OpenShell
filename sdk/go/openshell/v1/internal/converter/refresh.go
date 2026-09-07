// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"math"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
)

// --- RefreshStrategy enum mapping ---

// RefreshStrategyFromProto converts a proto ProviderCredentialRefreshStrategy to an SDK RefreshStrategy.
func RefreshStrategyFromProto(s pb.ProviderCredentialRefreshStrategy) types.RefreshStrategy {
	switch s {
	case pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_STATIC:
		return types.RefreshStrategyStatic
	case pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_EXTERNAL:
		return types.RefreshStrategyExternal
	case pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_REFRESH_TOKEN:
		return types.RefreshStrategyOAuth2RefreshToken
	case pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_CLIENT_CREDENTIALS:
		return types.RefreshStrategyOAuth2ClientCredentials
	case pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_GOOGLE_SERVICE_ACCOUNT_JWT:
		return types.RefreshStrategyGoogleServiceAccountJWT
	case pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_AWS_STS_ASSUME_ROLE:
		return types.RefreshStrategyAWSStsAssumeRole
	default:
		return types.RefreshStrategy("")
	}
}

// --- RefreshRecoveryAction enum mapping ---

// RefreshRecoveryActionFromProto converts a proto recovery action to the curated SDK type.
func RefreshRecoveryActionFromProto(a pb.ProviderCredentialRefreshRecoveryAction) types.RefreshRecoveryAction {
	switch a {
	case pb.ProviderCredentialRefreshRecoveryAction_PROVIDER_CREDENTIAL_REFRESH_RECOVERY_ACTION_RETRY:
		return types.RefreshRecoveryActionRetry
	case pb.ProviderCredentialRefreshRecoveryAction_PROVIDER_CREDENTIAL_REFRESH_RECOVERY_ACTION_REAUTHORIZE:
		return types.RefreshRecoveryActionReauthorize
	case pb.ProviderCredentialRefreshRecoveryAction_PROVIDER_CREDENTIAL_REFRESH_RECOVERY_ACTION_FIX_CONFIGURATION:
		return types.RefreshRecoveryActionFixConfiguration
	case pb.ProviderCredentialRefreshRecoveryAction_PROVIDER_CREDENTIAL_REFRESH_RECOVERY_ACTION_INVESTIGATE:
		return types.RefreshRecoveryActionInvestigate
	default:
		return types.RefreshRecoveryActionUnspecified
	}
}

func refreshNextTimeFromMillis(ms int64) time.Time {
	if ms == math.MaxInt64 {
		return time.Time{}
	}
	return TimeFromMillis(ms)
}

// RefreshStrategyToProto converts an SDK RefreshStrategy to a proto ProviderCredentialRefreshStrategy.
func RefreshStrategyToProto(s types.RefreshStrategy) pb.ProviderCredentialRefreshStrategy {
	switch s {
	case types.RefreshStrategyStatic:
		return pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_STATIC
	case types.RefreshStrategyExternal:
		return pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_EXTERNAL
	case types.RefreshStrategyOAuth2RefreshToken:
		return pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_REFRESH_TOKEN
	case types.RefreshStrategyOAuth2ClientCredentials:
		return pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_CLIENT_CREDENTIALS
	case types.RefreshStrategyGoogleServiceAccountJWT:
		return pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_GOOGLE_SERVICE_ACCOUNT_JWT
	case types.RefreshStrategyAWSStsAssumeRole:
		return pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_AWS_STS_ASSUME_ROLE
	default:
		return pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_UNSPECIFIED
	}
}

// --- RefreshStatus ---

// RefreshStatusFromProto converts a proto ProviderCredentialRefreshStatus to an SDK RefreshStatus.
func RefreshStatusFromProto(s *pb.ProviderCredentialRefreshStatus) *types.RefreshStatus {
	if s == nil {
		return nil
	}
	return &types.RefreshStatus{
		ProviderName:         s.GetProviderName(),
		ProviderID:           s.GetProviderId(),
		CredentialKey:        s.GetCredentialKey(),
		Strategy:             RefreshStrategyFromProto(s.GetStrategy()),
		Status:               s.GetStatus(),
		ExpiresAt:            TimeFromMillis(s.GetExpiresAtMs()),
		NextRefreshAt:        refreshNextTimeFromMillis(s.GetNextRefreshAtMs()),
		LastRefreshAt:        TimeFromMillis(s.GetLastRefreshAtMs()),
		LastError:            s.GetLastError(),
		RecoveryAction:       RefreshRecoveryActionFromProto(s.GetRecoveryAction()),
		FailureCode:          s.GetFailureCode(),
		ProviderErrorSubtype: s.GetProviderErrorSubtype(),
		LastErrorAt:          TimeFromMillis(s.GetLastErrorAtMs()),
	}
}

// --- RefreshConfig ---

// RefreshConfigToProto converts an SDK RefreshConfig to a proto ConfigureProviderRefreshRequest.
// Material and SecretMaterialKeys are deep-copied.
func RefreshConfigToProto(c *types.RefreshConfig) *pb.ConfigureProviderRefreshRequest {
	if c == nil {
		return nil
	}

	result := &pb.ConfigureProviderRefreshRequest{
		Provider:           c.Provider,
		CredentialKey:      c.CredentialKey,
		Strategy:           RefreshStrategyToProto(c.Strategy),
		Material:           CopyStringMap(c.Material),
		SecretMaterialKeys: CopyStringSlice(c.SecretMaterialKeys),
	}

	if c.ExpiresAt != nil {
		ms := MillisFromTime(*c.ExpiresAt)
		result.ExpiresAtMs = &ms
	}

	return result
}
