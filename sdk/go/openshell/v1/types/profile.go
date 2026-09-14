// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

// ProfileCategory classifies a provider profile.
type ProfileCategory string

// ProfileCategory values.
const (
	ProfileCategoryOther         ProfileCategory = "Other"
	ProfileCategoryInference     ProfileCategory = "Inference"
	ProfileCategoryAgent         ProfileCategory = "Agent"
	ProfileCategorySourceControl ProfileCategory = "SourceControl"
	ProfileCategoryMessaging     ProfileCategory = "Messaging"
	ProfileCategoryData          ProfileCategory = "Data"
	ProfileCategoryKnowledge     ProfileCategory = "Knowledge"
)

// ProviderProfile defines a provider type template with credentials schema,
// endpoints, binaries, and discovery configuration.
type ProviderProfile struct {
	ID               string
	DisplayName      string
	Description      string
	Category         ProfileCategory
	Credentials      []ProfileCredential
	Endpoints        []NetworkEndpoint
	Binaries         []NetworkBinary
	InferenceCapable bool
	Discovery        ProfileDiscovery
	ResourceVersion  uint64
	Annotations      map[string]string
	Source           string
	Scope            string
}

// ProfileCredential defines a single credential required by a provider profile.
type ProfileCredential struct {
	Name         string
	Description  string
	EnvVars      []string
	Required     bool
	Secret       bool
	Refresh      *ProfileCredentialRefresh
	AuthStyle    string
	HeaderName   string
	QueryParam   string
	PathTemplate string
	TokenGrant   *CredentialTokenGrant
}

// ProfileCredentialRefresh declares how a profile credential is refreshed.
type ProfileCredentialRefresh struct {
	Strategy             RefreshStrategy
	TokenURL             string
	Scopes               []string
	RefreshBeforeSeconds int64
	MaxLifetimeSeconds   int64
	Material             []ProfileCredentialRefreshMaterial
	AdditionalOutputs    []ProfileCredentialRefreshOutput
}

// ProfileCredentialRefreshMaterial declares one input required by a refresh strategy.
type ProfileCredentialRefreshMaterial struct {
	Name        string
	Description string
	Required    bool
	Secret      bool
}

// ProfileCredentialRefreshOutput maps a minted output to another credential.
type ProfileCredentialRefreshOutput struct {
	Output     string
	Credential string
}

// CredentialTokenGrantType describes which OAuth2 grant type to use for dynamic credentials.
type CredentialTokenGrantType string

// CredentialTokenGrantType values.
const (
	CredentialTokenGrantTypeClientCredentials CredentialTokenGrantType = "ClientCredentials"
	CredentialTokenGrantTypeTokenExchange     CredentialTokenGrantType = "TokenExchange"
)

// CredentialTokenGrant configures dynamic credential acquisition via OAuth2 grant.
type CredentialTokenGrant struct {
	TokenEndpoint       string
	Audience            string
	JWTSVIDAudience     string
	Scopes              []string
	CacheTTLSeconds     int64
	AudienceOverrides   []TokenGrantAudienceOverride
	ClientAssertionType string
	GrantType           CredentialTokenGrantType
	SubjectToken        *TokenGrantSubjectToken
	RequestedTokenType  string
}

// TokenGrantSubjectToken configures the subject token for token exchange grants.
type TokenGrantSubjectToken struct {
	Source           string
	Credential       string
	SubjectTokenType string
}

// TokenGrantAudienceOverride selects an endpoint-specific resource audience.
type TokenGrantAudienceOverride struct {
	Host     string
	Port     uint32
	Path     string
	Audience string
	Scopes   []string
}

// NetworkEndpoint describes a network endpoint provided by a profile.
type NetworkEndpoint struct {
	Host     string
	Port     uint32
	Protocol string
}

// NetworkBinary describes a binary artifact provided by a profile.
type NetworkBinary struct {
	Path string
}

// ProfileDiscovery holds local discovery configuration for a profile.
type ProfileDiscovery struct {
	Credentials []string
}

// ProfileImportItem is an item submitted for profile import or lint validation.
type ProfileImportItem struct {
	Profile ProviderProfile
	Source  string
}

// ProfileDiagnostic is a validation finding from Import, Update, or Lint.
type ProfileDiagnostic struct {
	Source    string
	ProfileID string
	Field     string
	Message   string
	Severity  string
}

// ImportResult holds the result of a profile import operation.
type ImportResult struct {
	Diagnostics []ProfileDiagnostic
	Profiles    []ProviderProfile
	Imported    bool
}

// UpdateResult holds the result of a profile update operation.
type UpdateResult struct {
	Diagnostics []ProfileDiagnostic
	Profile     *ProviderProfile
	Updated     bool
}

// LintResult holds the result of a profile lint operation.
type LintResult struct {
	Diagnostics []ProfileDiagnostic
	Valid       bool
}
