// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

// SettingValueType identifies which typed field of a SettingValue is active.
type SettingValueType string

// SettingValueType constants.
const (
	SettingValueString SettingValueType = "string"
	SettingValueBool   SettingValueType = "bool"
	SettingValueInt    SettingValueType = "int"
	SettingValueBytes  SettingValueType = "bytes"
)

// SettingValue is a typed setting value supporting string, bool, int64, and bytes variants.
// The Type field indicates which value field is populated.
type SettingValue struct {
	Type      SettingValueType
	StringVal string
	BoolVal   bool
	IntVal    int64
	BytesVal  []byte
}

// SettingScope indicates whether a setting is controlled at sandbox or global level.
type SettingScope string

// SettingScope constants.
const (
	SettingScopeUnspecified SettingScope = ""
	SettingScopeSandbox     SettingScope = "sandbox"
	SettingScopeGlobal      SettingScope = "global"
)

// PolicySource indicates the source of the policy payload in a SandboxConfig response.
type PolicySource string

// PolicySource constants.
const (
	PolicySourceUnspecified PolicySource = ""
	PolicySourceSandbox     PolicySource = "sandbox"
	PolicySourceGlobal      PolicySource = "global"
)

// EffectiveSetting is a setting value paired with the scope it was resolved from.
type EffectiveSetting struct {
	Value SettingValue
	Scope SettingScope
}

// SandboxConfig represents the full configuration state of a sandbox,
// including policy, effective settings, and revision metadata.
type SandboxConfig struct {
	// Policy is the typed security policy for this sandbox. Nil means no policy in the response.
	Policy *SandboxPolicy
	// PolicyVersion is monotonically increasing per sandbox.
	PolicyVersion uint32
	// PolicyHash is the SHA-256 of the serialized policy payload.
	PolicyHash string
	// Settings is the effective settings resolved for this sandbox.
	Settings map[string]EffectiveSetting
	// ConfigRevision is the fingerprint for effective config (policy + settings).
	ConfigRevision uint64
	// PolicySource indicates where the policy came from (sandbox or global).
	PolicySource PolicySource
	// GlobalPolicyVersion is the global policy version (0 if not applicable).
	GlobalPolicyVersion uint32
	// ProviderEnvRevision is the fingerprint for provider credential inputs.
	ProviderEnvRevision uint64
	// PolicyValidationFailureMode is the gateway-configured posture for rejected
	// policy generations ("fail_closed" or "retain_last_valid").
	PolicyValidationFailureMode string
}

// GatewayConfig represents gateway-global settings.
type GatewayConfig struct {
	// Settings is the global settings map.
	Settings map[string]SettingValue
	// SettingsRevision is a monotonically increasing revision for gateway-global settings.
	SettingsRevision uint64
}

// ConfigUpdate represents a configuration mutation request.
// For sandbox-scoped updates, set Name to the sandbox name.
// For global-scoped updates, set Global to true.
type ConfigUpdate struct {
	// Name is the sandbox name (required for sandbox-scoped updates).
	Name string
	// Policy is the typed security policy for a full policy replacement. Nil means no policy change.
	Policy *SandboxPolicy
	// SettingKey is a single setting key to mutate.
	SettingKey string
	// SettingValue is the setting value for upsert. Nil means no value change.
	SettingValue *SettingValue
	// DeleteSetting deletes the setting key when true.
	DeleteSetting bool
	// Global applies the update at gateway-global scope when true.
	Global bool
	// MergeOperations is a list of typed policy merge operations.
	MergeOperations []PolicyMergeOperation
	// ExpectedResourceVersion is for optimistic concurrency (0 = skip check).
	ExpectedResourceVersion uint64
	// Annotations is caller-provided metadata for sandbox-scoped updates.
	Annotations map[string]string
}

// ConfigUpdateResult holds the result of a configuration update operation.
// Named ConfigUpdateResult to avoid collision with profile.UpdateResult.
type ConfigUpdateResult struct {
	// Version is the assigned policy version.
	Version uint32
	// PolicyHash is the SHA-256 of the serialized policy.
	PolicyHash string
	// SettingsRevision is the settings revision for the modified scope.
	SettingsRevision uint64
	// Deleted is true when a setting delete removed an existing key.
	Deleted bool
	// Annotations contains sandbox metadata annotations after the update.
	Annotations map[string]string
}
