// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1_test

import (
	"context"
	"fmt"
	"log"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/fake"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// ExampleNewClient_addSandbox demonstrates pre-seeding a fake client with
// a sandbox fixture.
func ExampleNewClient_addSandbox() {
	client := fake.NewClient()
	defer client.Close() //nolint:errcheck

	// Pre-seed a sandbox that already exists in Ready state
	client.AddSandbox("default", &types.Sandbox{
		Name: "pre-existing",
		Status: types.SandboxStatus{
			Phase: types.SandboxReady,
		},
		ResourceVersion: 5,
	})

	ctx := context.Background()

	sb, err := client.Sandboxes().Get(ctx, "default", "pre-existing")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Name:", sb.Name)
	fmt.Println("Phase:", sb.Status.Phase)
	// Output:
	// Name: pre-existing
	// Phase: Ready
}

// ExampleNewClient_addProvider demonstrates pre-seeding a fake client with
// a provider fixture.
func ExampleNewClient_addProvider() {
	client := fake.NewClient()
	defer client.Close() //nolint:errcheck

	// Pre-seed a provider
	client.AddProvider("default", &types.Provider{
		Name: "seeded-provider",
		Type: "openai",
	})

	ctx := context.Background()

	providers, err := client.Providers().List(ctx, "default")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Count:", len(providers))
	fmt.Println("Name:", providers[0].Name)
	// Output:
	// Count: 1
	// Name: seeded-provider
}

// ExampleNewClient_withHealthResult demonstrates configuring the fake
// health sub-client to return a custom result.
func ExampleNewClient_withHealthResult() {
	client := fake.NewClient(fake.WithHealthResult(&types.HealthResult{
		Healthy: false,
		Version: "1.2.3",
	}))
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	result, err := client.Health().Check(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Healthy:", result.Healthy)
	fmt.Println("Version:", result.Version)
	// Output:
	// Healthy: false
	// Version: 1.2.3
}

// ExampleNewClient_watchEvents demonstrates watching for sandbox events
// using the fake client.
func ExampleNewClient_watchEvents() {
	client := fake.NewClient()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	// Start watching before creating
	watcher, err := client.Sandboxes().Watch(ctx, "default", "my-sandbox")
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Stop()

	// Create triggers an ADDED event
	_, err = client.Sandboxes().Create(ctx, "default", "my-sandbox", &v1.SandboxSpec{}, nil)
	if err != nil {
		log.Fatal(err)
	}

	event := <-watcher.ResultChan()
	fmt.Println("Type:", event.Type)
	fmt.Println("Name:", event.Object.Name)
	// Output:
	// Type: ADDED
	// Name: my-sandbox
}

// ExampleNewClient_stopOnTerminal demonstrates the StopOnTerminal watch
// option that automatically closes the watcher when a sandbox reaches a
// terminal phase.
func ExampleNewClient_stopOnTerminal() {
	client := fake.NewClient()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	// Watch with StopOnTerminal
	watcher, err := client.Sandboxes().Watch(ctx, "default", "my-sandbox", v1.WatchOptions{
		StopOnTerminal: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Create and transition to Ready
	_, err = client.Sandboxes().Create(ctx, "default", "my-sandbox", &v1.SandboxSpec{}, nil)
	if err != nil {
		log.Fatal(err)
	}
	_, err = client.Sandboxes().WaitReady(ctx, "default", "my-sandbox")
	if err != nil {
		log.Fatal(err)
	}

	// Drain events, channel closes after terminal phase
	var count int
	for range watcher.ResultChan() {
		count++
	}
	fmt.Println("Events received:", count)
	// Output:
	// Events received: 2
}

// ExampleNewClient_inferenceRoute demonstrates setting and retrieving an
// inference route using the fake client.
func ExampleNewClient_inferenceRoute() {
	client := fake.NewClient()
	defer client.Close() //nolint:errcheck

	ctx := context.Background()

	// Set an inference route for a workspace
	route, err := client.Inference().SetRoute(ctx, "my-workspace", &v1.InferenceRouteConfig{
		ProviderName: "openai",
		ModelID:      "gpt-4",
		RouteName:    "",
		TimeoutSecs:  120,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Set route v%d: %s/%s\n", route.Version, route.ProviderName, route.ModelID)

	// Retrieve the route
	route, err = client.Inference().GetRoute(ctx, "my-workspace", "")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Got route: %s/%s (timeout: %ds)\n", route.ProviderName, route.ModelID, route.TimeoutSecs)

	// Delete the route
	err = client.Inference().DeleteRoute(ctx, "my-workspace", "")
	if err != nil {
		log.Fatal(err)
	}

	// Verify deletion
	_, err = client.Inference().GetRoute(ctx, "my-workspace", "")
	fmt.Println("After delete:", v1.IsNotFound(err))
	// Output:
	// Set route v1: openai/gpt-4
	// Got route: openai/gpt-4 (timeout: 120s)
	// After delete: true
}
