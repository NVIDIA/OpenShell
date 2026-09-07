// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

// InferenceRouteConfig holds parameters for setting an inference route.
// ProviderName and ModelID are required; the SDK validates them before
// sending the request to the gateway.
type InferenceRouteConfig struct {
	// ProviderName is the provider record name for credentials and endpoint mapping.
	ProviderName string

	// ModelID is the model identifier to force on generation calls.
	ModelID string

	// RouteName is the route name to target. An empty string represents the
	// default user-facing route.
	RouteName string

	// NoVerify skips synchronous endpoint validation before persistence when true.
	NoVerify bool

	// TimeoutSecs is the per-route request timeout in seconds. 0 means use the
	// default (60s).
	TimeoutSecs uint64
}

// InferenceRoute represents a configured inference route as returned by the
// gateway. For SetRoute responses, ValidationPerformed and ValidatedEndpoints
// contain verification metadata; for GetRoute responses they are zero-valued.
type InferenceRoute struct {
	// ProviderName is the provider record name.
	ProviderName string

	// ModelID is the model identifier.
	ModelID string

	// Version is the server-assigned version for the route.
	Version uint64

	// RouteName is the route name that was configured or queried.
	RouteName string

	// TimeoutSecs is the per-route request timeout in seconds.
	TimeoutSecs uint64

	// Workspace is the workspace the route belongs to.
	Workspace string

	// ValidationPerformed indicates whether endpoint verification ran during
	// this request. Only populated for SetRoute responses.
	ValidationPerformed bool

	// ValidatedEndpoints lists endpoints probed during validation, if any.
	// Only populated for SetRoute responses.
	ValidatedEndpoints []ValidatedEndpoint
}

// ValidatedEndpoint represents an endpoint that was probed during route
// validation.
type ValidatedEndpoint struct {
	// URL is the endpoint URL that was validated.
	URL string

	// Protocol is the protocol used (e.g., "openai", "vertex").
	Protocol string
}
