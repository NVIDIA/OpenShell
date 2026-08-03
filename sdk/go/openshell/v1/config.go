// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// SandboxConfig represents the full configuration state of a sandbox.
type SandboxConfig = types.SandboxConfig

// GatewayConfig represents gateway-global settings.
type GatewayConfig = types.GatewayConfig

// ConfigUpdate represents a configuration mutation request.
type ConfigUpdate = types.ConfigUpdate

// ConfigUpdateResult holds the result of a configuration update operation.
type ConfigUpdateResult = types.ConfigUpdateResult

// SettingValue is a typed setting value (string, bool, int64, or bytes).
type SettingValue = types.SettingValue

// SettingValueType identifies which typed field of a SettingValue is active.
type SettingValueType = types.SettingValueType

// EffectiveSetting is a setting value paired with its resolved scope.
type EffectiveSetting = types.EffectiveSetting

// SettingScope indicates whether a setting is sandbox or global.
type SettingScope = types.SettingScope

// PolicySource indicates the source of a policy payload.
type PolicySource = types.PolicySource

// SettingValueType constants re-exported from types package.
const (
	SettingValueString = types.SettingValueString
	SettingValueBool   = types.SettingValueBool
	SettingValueInt    = types.SettingValueInt
	SettingValueBytes  = types.SettingValueBytes
)

// SettingScope constants re-exported from types package.
const (
	SettingScopeUnspecified = types.SettingScopeUnspecified
	SettingScopeSandbox     = types.SettingScopeSandbox
	SettingScopeGlobal      = types.SettingScopeGlobal
)

// PolicySource constants re-exported from types package.
const (
	PolicySourceUnspecified = types.PolicySourceUnspecified
	PolicySourceSandbox     = types.PolicySourceSandbox
	PolicySourceGlobal      = types.PolicySourceGlobal
)

// ConfigInterface defines operations for reading and updating gateway and
// sandbox configuration.
type ConfigInterface interface {
	// GetSandbox retrieves the full configuration state for a sandbox,
	// including policy, effective settings, and revision metadata.
	// The sandbox is identified by name; the SDK resolves it to an ID internally.
	GetSandbox(ctx context.Context, workspace, sandboxName string) (*SandboxConfig, error)

	// GetGateway retrieves gateway-global settings.
	GetGateway(ctx context.Context) (*GatewayConfig, error)

	// Update applies a configuration mutation. For sandbox-scoped updates,
	// set ConfigUpdate.Name to the sandbox name. For global-scoped updates,
	// set ConfigUpdate.Global to true.
	Update(ctx context.Context, workspace string, update *ConfigUpdate) (*ConfigUpdateResult, error)
}
