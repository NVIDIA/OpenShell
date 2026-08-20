// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// ProviderProfile represents a provider type template.
type ProviderProfile = types.ProviderProfile

// ProfileCredential defines a single credential required by a provider profile.
type ProfileCredential = types.ProfileCredential

// ProfileCategory classifies a provider profile.
type ProfileCategory = types.ProfileCategory

// NetworkEndpoint describes a network endpoint provided by a profile.
type NetworkEndpoint = types.NetworkEndpoint

// NetworkBinary describes a binary artifact provided by a profile.
type NetworkBinary = types.NetworkBinary

// ProfileDiscovery holds local discovery configuration for a profile.
type ProfileDiscovery = types.ProfileDiscovery

// ProfileImportItem is an item submitted for profile import or lint validation.
type ProfileImportItem = types.ProfileImportItem

// ProfileDiagnostic is a validation finding from Import, Update, or Lint.
type ProfileDiagnostic = types.ProfileDiagnostic

// ImportResult holds the result of a profile import operation.
type ImportResult = types.ImportResult

// UpdateResult holds the result of a profile update operation.
type UpdateResult = types.UpdateResult

// LintResult holds the result of a profile lint operation.
type LintResult = types.LintResult

// ProfileCategory values.
const (
	ProfileCategoryOther         = types.ProfileCategoryOther
	ProfileCategoryInference     = types.ProfileCategoryInference
	ProfileCategoryAgent         = types.ProfileCategoryAgent
	ProfileCategorySourceControl = types.ProfileCategorySourceControl
	ProfileCategoryMessaging     = types.ProfileCategoryMessaging
	ProfileCategoryData          = types.ProfileCategoryData
	ProfileCategoryKnowledge     = types.ProfileCategoryKnowledge
)

// ProfileInterface defines operations for managing provider profiles.
type ProfileInterface interface {
	List(ctx context.Context, workspace string, opts ...ListOptions) ([]*ProviderProfile, error)
	Get(ctx context.Context, workspace, id string) (*ProviderProfile, error)
	Import(ctx context.Context, workspace string, items []ProfileImportItem) (*ImportResult, error)
	Update(ctx context.Context, workspace, id string, expectedResourceVersion uint64, item ProfileImportItem) (*UpdateResult, error)
	Lint(ctx context.Context, workspace string, items []ProfileImportItem) (*LintResult, error)
	Delete(ctx context.Context, workspace, id string) (bool, error)
}
