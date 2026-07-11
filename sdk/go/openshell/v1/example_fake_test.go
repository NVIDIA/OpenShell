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
	client.AddSandbox(&types.Sandbox{
		Name: "pre-existing",
		Status: types.SandboxStatus{
			Phase: types.SandboxReady,
		},
		ResourceVersion: 5,
	})

	ctx := context.Background()

	sb, err := client.Sandboxes().Get(ctx, "pre-existing")
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
	client.AddProvider(&types.Provider{
		Name: "seeded-provider",
		Type: "openai",
	})

	ctx := context.Background()

	providers, err := client.Providers().List(ctx)
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
	watcher, err := client.Sandboxes().Watch(ctx, "my-sandbox")
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Stop()

	// Create triggers an ADDED event
	_, err = client.Sandboxes().Create(ctx, "my-sandbox", &v1.SandboxSpec{}, nil)
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
	watcher, err := client.Sandboxes().Watch(ctx, "my-sandbox", v1.WatchOptions{
		StopOnTerminal: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Create and transition to Ready
	_, err = client.Sandboxes().Create(ctx, "my-sandbox", &v1.SandboxSpec{}, nil)
	if err != nil {
		log.Fatal(err)
	}
	_, err = client.Sandboxes().WaitReady(ctx, "my-sandbox")
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
