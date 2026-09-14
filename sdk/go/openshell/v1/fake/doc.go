// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package fake provides an in-memory fake implementation of the OpenShell SDK
// client interfaces for use in consumer test suites.
//
// The fake client follows the client-go/kubernetes/fake pattern: it maintains
// in-memory stores for sandboxes and providers, supports watch event broadcasting,
// and returns the same StatusError codes as the real client for equivalent error
// conditions (NotFound, AlreadyExists, Unavailable, Unimplemented).
//
// All operations are safe for concurrent use from multiple goroutines.
//
// # Usage
//
// Create a FakeClient, exercise the sandbox lifecycle, and assert results:
//
//	func TestSandboxLifecycle(t *testing.T) {
//	    client := fake.NewClient()
//	    defer client.Close()
//
//	    ctx := context.Background()
//
//	    // Create a sandbox — starts in Provisioning phase
//	    sb, err := client.Sandboxes().Create(ctx, "my-sandbox", &v1.SandboxSpec{}, nil)
//	    require.NoError(t, err)
//	    assert.Equal(t, types.SandboxProvisioning, sb.Status.Phase)
//
//	    // Wait until ready — transitions synchronously in the fake
//	    sb, err = client.Sandboxes().WaitReady(ctx, "my-sandbox")
//	    require.NoError(t, err)
//	    assert.Equal(t, types.SandboxReady, sb.Status.Phase)
//
//	    // Clean up
//	    require.NoError(t, client.Sandboxes().Delete(ctx, "my-sandbox"))
//	}
package fake
