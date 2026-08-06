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
}

// ProfileCredential defines a single credential required by a provider profile.
type ProfileCredential struct {
	Name        string
	Description string
	Required    bool
	Secret      bool
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
