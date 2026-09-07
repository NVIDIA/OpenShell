// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"math"
	"testing"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- RefreshStrategy ---

func TestRefreshStrategyFromProto(t *testing.T) {
	tests := []struct {
		proto pb.ProviderCredentialRefreshStrategy
		want  v1.RefreshStrategy
	}{
		{pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_STATIC, v1.RefreshStrategyStatic},
		{pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_EXTERNAL, v1.RefreshStrategyExternal},
		{pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_REFRESH_TOKEN, v1.RefreshStrategyOAuth2RefreshToken},
		{pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_CLIENT_CREDENTIALS, v1.RefreshStrategyOAuth2ClientCredentials},
		{pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_GOOGLE_SERVICE_ACCOUNT_JWT, v1.RefreshStrategyGoogleServiceAccountJWT},
		{pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_AWS_STS_ASSUME_ROLE, v1.RefreshStrategyAWSStsAssumeRole},
		{pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_UNSPECIFIED, v1.RefreshStrategy("")},
	}
	for _, tt := range tests {
		t.Run(tt.proto.String(), func(t *testing.T) {
			assert.Equal(t, tt.want, RefreshStrategyFromProto(tt.proto))
		})
	}
}

func TestRefreshRecoveryActionFromProto(t *testing.T) {
	tests := []struct {
		proto pb.ProviderCredentialRefreshRecoveryAction
		want  v1.RefreshRecoveryAction
	}{
		{pb.ProviderCredentialRefreshRecoveryAction_PROVIDER_CREDENTIAL_REFRESH_RECOVERY_ACTION_UNSPECIFIED, v1.RefreshRecoveryActionUnspecified},
		{pb.ProviderCredentialRefreshRecoveryAction_PROVIDER_CREDENTIAL_REFRESH_RECOVERY_ACTION_RETRY, v1.RefreshRecoveryActionRetry},
		{pb.ProviderCredentialRefreshRecoveryAction_PROVIDER_CREDENTIAL_REFRESH_RECOVERY_ACTION_REAUTHORIZE, v1.RefreshRecoveryActionReauthorize},
		{pb.ProviderCredentialRefreshRecoveryAction_PROVIDER_CREDENTIAL_REFRESH_RECOVERY_ACTION_FIX_CONFIGURATION, v1.RefreshRecoveryActionFixConfiguration},
		{pb.ProviderCredentialRefreshRecoveryAction_PROVIDER_CREDENTIAL_REFRESH_RECOVERY_ACTION_INVESTIGATE, v1.RefreshRecoveryActionInvestigate},
		{pb.ProviderCredentialRefreshRecoveryAction(999), v1.RefreshRecoveryActionUnspecified},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, RefreshRecoveryActionFromProto(tt.proto))
	}
}

func TestRefreshStrategyToProto(t *testing.T) {
	tests := []struct {
		sdk  v1.RefreshStrategy
		want pb.ProviderCredentialRefreshStrategy
	}{
		{v1.RefreshStrategyStatic, pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_STATIC},
		{v1.RefreshStrategyExternal, pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_EXTERNAL},
		{v1.RefreshStrategyOAuth2RefreshToken, pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_REFRESH_TOKEN},
		{v1.RefreshStrategyOAuth2ClientCredentials, pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_CLIENT_CREDENTIALS},
		{v1.RefreshStrategyGoogleServiceAccountJWT, pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_GOOGLE_SERVICE_ACCOUNT_JWT},
		{v1.RefreshStrategyAWSStsAssumeRole, pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_AWS_STS_ASSUME_ROLE},
		{v1.RefreshStrategy(""), pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_UNSPECIFIED},
		{v1.RefreshStrategy("Unknown"), pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(string(tt.sdk), func(t *testing.T) {
			assert.Equal(t, tt.want, RefreshStrategyToProto(tt.sdk))
		})
	}
}

// --- RefreshStatus ---

func TestRefreshStatusFromProto(t *testing.T) {
	proto := &pb.ProviderCredentialRefreshStatus{
		ProviderName:         "anthropic",
		ProviderId:           "prov-1",
		CredentialKey:        "API_KEY",
		Strategy:             pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_REFRESH_TOKEN,
		Status:               "active",
		ExpiresAtMs:          1700000000000,
		NextRefreshAtMs:      1699999000000,
		LastRefreshAtMs:      1699998000000,
		LastError:            "none",
		RecoveryAction:       pb.ProviderCredentialRefreshRecoveryAction_PROVIDER_CREDENTIAL_REFRESH_RECOVERY_ACTION_REAUTHORIZE,
		FailureCode:          "oauth_invalid_grant",
		ProviderErrorSubtype: "invalid_rapt",
		LastErrorAtMs:        1699997000000,
	}

	status := RefreshStatusFromProto(proto)

	require.NotNil(t, status)
	assert.Equal(t, "anthropic", status.ProviderName)
	assert.Equal(t, "prov-1", status.ProviderID)
	assert.Equal(t, "API_KEY", status.CredentialKey)
	assert.Equal(t, v1.RefreshStrategyOAuth2RefreshToken, status.Strategy)
	assert.Equal(t, "active", status.Status)
	assert.Equal(t, TimeFromMillis(1700000000000), status.ExpiresAt)
	assert.Equal(t, TimeFromMillis(1699999000000), status.NextRefreshAt)
	assert.Equal(t, TimeFromMillis(1699998000000), status.LastRefreshAt)
	assert.Equal(t, "none", status.LastError)
	assert.Equal(t, v1.RefreshRecoveryActionReauthorize, status.RecoveryAction)
	assert.Equal(t, "oauth_invalid_grant", status.FailureCode)
	assert.Equal(t, "invalid_rapt", status.ProviderErrorSubtype)
	assert.Equal(t, TimeFromMillis(1699997000000), status.LastErrorAt)
}

func TestRefreshStatusFromProto_Nil(t *testing.T) {
	status := RefreshStatusFromProto(nil)
	assert.Nil(t, status)
}

func TestRefreshStatusFromProto_ZeroTimestamps(t *testing.T) {
	proto := &pb.ProviderCredentialRefreshStatus{
		ProviderName:  "test",
		CredentialKey: "KEY",
		Strategy:      pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_STATIC,
	}

	status := RefreshStatusFromProto(proto)

	require.NotNil(t, status)
	assert.Equal(t, v1.RefreshStrategyStatic, status.Strategy)
	assert.True(t, status.ExpiresAt.IsZero())
	assert.True(t, status.NextRefreshAt.IsZero())
	assert.True(t, status.LastRefreshAt.IsZero())
	assert.True(t, status.LastErrorAt.IsZero())
	assert.Equal(t, v1.RefreshRecoveryActionUnspecified, status.RecoveryAction)
}

func TestRefreshStatusFromProto_ParkedRefreshHasNoNextTime(t *testing.T) {
	proto := &pb.ProviderCredentialRefreshStatus{
		ProviderName:    "test",
		CredentialKey:   "KEY",
		NextRefreshAtMs: math.MaxInt64,
		RecoveryAction:  pb.ProviderCredentialRefreshRecoveryAction_PROVIDER_CREDENTIAL_REFRESH_RECOVERY_ACTION_REAUTHORIZE,
	}

	status := RefreshStatusFromProto(proto)

	require.NotNil(t, status)
	assert.True(t, status.NextRefreshAt.IsZero())
	assert.Equal(t, v1.RefreshRecoveryActionReauthorize, status.RecoveryAction)
	assert.False(t, TimeFromMillis(math.MaxInt64).IsZero())
}

// --- RefreshConfig ---

func TestRefreshConfigToProto(t *testing.T) {
	expiresAt := time.Unix(1700000000, 0)
	config := &v1.RefreshConfig{
		Provider:      "anthropic",
		CredentialKey: "API_KEY",
		Strategy:      v1.RefreshStrategyOAuth2ClientCredentials,
		Material: map[string]string{
			"client_id":     "my-id",
			"client_secret": "my-secret",
		},
		SecretMaterialKeys: []string{"client_secret"},
		ExpiresAt:          &expiresAt,
	}

	proto := RefreshConfigToProto(config)

	require.NotNil(t, proto)
	assert.Equal(t, "anthropic", proto.Provider)
	assert.Equal(t, "API_KEY", proto.CredentialKey)
	assert.Equal(t, pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_CLIENT_CREDENTIALS, proto.Strategy)

	// Material is deep-copied
	require.Len(t, proto.Material, 2)
	assert.Equal(t, "my-id", proto.Material["client_id"])
	assert.Equal(t, "my-secret", proto.Material["client_secret"])

	// Verify deep copy by mutating original
	config.Material["client_id"] = "mutated"
	assert.Equal(t, "my-id", proto.Material["client_id"], "material must be deep copied")

	assert.Equal(t, []string{"client_secret"}, proto.SecretMaterialKeys)

	// Verify SecretMaterialKeys deep copy
	config.SecretMaterialKeys[0] = "mutated"
	assert.Equal(t, "client_secret", proto.SecretMaterialKeys[0], "secret keys must be deep copied")

	// ExpiresAt conversion
	require.NotNil(t, proto.ExpiresAtMs)
	assert.Equal(t, MillisFromTime(expiresAt), *proto.ExpiresAtMs)
}

func TestRefreshConfigToProto_NilExpiresAt(t *testing.T) {
	config := &v1.RefreshConfig{
		Provider:      "test",
		CredentialKey: "KEY",
		Strategy:      v1.RefreshStrategyStatic,
	}

	proto := RefreshConfigToProto(config)

	require.NotNil(t, proto)
	assert.Nil(t, proto.ExpiresAtMs)
}

func TestRefreshConfigToProto_Nil(t *testing.T) {
	proto := RefreshConfigToProto(nil)
	assert.Nil(t, proto)
}
