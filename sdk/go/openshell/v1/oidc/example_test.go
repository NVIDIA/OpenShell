// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// These examples demonstrate OIDC package usage but are guarded from
// execution during `go test` because they require real network access
// and user interaction. The guard `if false` keeps the code type-checked
// by the compiler without executing during tests.

package oidc_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/oidc"
)

func ExampleLogin_gateway() {
	if false {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		token, err := oidc.Login(ctx, "my-gateway")
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Authenticated. Token expires at %s\n", token.Expiry.Format(time.RFC3339))
	}

	fmt.Println("ok")
	// Output: ok
}

func ExampleLogin_standalone() {
	if false {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		token, err := oidc.Login(ctx, "",
			oidc.WithIssuer("https://auth.example.com"),
			oidc.WithClientID("my-app"),
			oidc.WithInMemory(),
		)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Access token: %s...\n", token.AccessToken[:10])
	}

	fmt.Println("ok")
	// Output: ok
}

func ExampleLogin_keyboard() {
	if false {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		token, err := oidc.Login(ctx, "my-gateway",
			oidc.WithKeyboardFlow(),
		)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Authenticated via keyboard flow. Token type: %s\n", token.TokenType)
	}

	fmt.Println("ok")
	// Output: ok
}

func ExampleDeviceLogin() {
	if false {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		token, err := oidc.DeviceLogin(ctx,
			oidc.WithIssuer("https://auth.example.com"),
			oidc.WithClientID("my-device-app"),
		)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Device authorized. Token expires at %s\n", token.Expiry.Format(time.RFC3339))
	}

	fmt.Println("ok")
	// Output: ok
}

func ExampleDeviceLogin_customDisplay() {
	if false {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		token, err := oidc.DeviceLogin(ctx,
			oidc.WithIssuer("https://auth.example.com"),
			oidc.WithClientID("my-tui-app"),
			oidc.WithDisplayFunc(func(verificationURL, userCode string) {
				fmt.Printf("Please visit: %s\n", verificationURL)
				fmt.Printf("Enter code:   %s\n", userCode)
			}),
		)
		if err != nil {
			log.Fatal(err)
		}

		_ = token
	}

	fmt.Println("ok")
	// Output: ok
}

func ExampleClientCredentials() {
	if false {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		token, err := oidc.ClientCredentials(ctx,
			oidc.WithIssuer("https://auth.example.com"),
			oidc.WithClientID("my-service"),
			oidc.WithClientSecret("service-secret"),
		)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Service authenticated. Token type: %s\n", token.TokenType)
	}

	fmt.Println("ok")
	// Output: ok
}

func ExampleClientCredentials_gateway() {
	if false {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		token, err := oidc.ClientCredentials(ctx,
			oidc.WithGateway("my-gateway"),
			oidc.WithClientSecret("service-secret"),
		)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Service authenticated via gateway. Token type: %s\n", token.TokenType)
	}

	fmt.Println("ok")
	// Output: ok
}
