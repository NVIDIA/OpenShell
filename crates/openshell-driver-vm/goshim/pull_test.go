// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestSelectManifestForPlatformPicksExactMatch(t *testing.T) {
	index := ocispec.Index{
		Manifests: []ocispec.Descriptor{
			{Digest: "sha256:amd64", Platform: &ocispec.Platform{OS: "linux", Architecture: "amd64"}},
			{Digest: "sha256:arm64", Platform: &ocispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}},
		},
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}

	matcher := platforms.OnlyStrict(ocispec.Platform{OS: "linux", Architecture: "arm64"})
	desc, err := selectManifestForPlatform(indexBytes, matcher)
	if err != nil {
		t.Fatalf("select manifest: %v", err)
	}
	if desc.Digest != "sha256:arm64" {
		t.Fatalf("expected arm64 manifest, got %s", desc.Digest)
	}
}

func TestSelectManifestForPlatformRejectsNoMatch(t *testing.T) {
	index := ocispec.Index{
		Manifests: []ocispec.Descriptor{
			{Digest: "sha256:amd64", Platform: &ocispec.Platform{OS: "linux", Architecture: "amd64"}},
		},
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}

	matcher := platforms.OnlyStrict(ocispec.Platform{OS: "linux", Architecture: "arm64"})
	if _, err := selectManifestForPlatform(indexBytes, matcher); err == nil {
		t.Fatal("expected an error when no manifest matches the platform")
	}
}

func TestWriteOCILayoutSetsRefNameAnnotation(t *testing.T) {
	dir := t.TempDir()
	desc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    "sha256:deadbeef",
		Size:      42,
	}

	if err := writeOCILayout(dir, desc); err != nil {
		t.Fatalf("write OCI layout: %v", err)
	}

	layoutBytes, err := os.ReadFile(filepath.Join(dir, "oci-layout"))
	if err != nil {
		t.Fatalf("read oci-layout: %v", err)
	}
	var layout ocispec.ImageLayout
	if err := json.Unmarshal(layoutBytes, &layout); err != nil {
		t.Fatalf("decode oci-layout: %v", err)
	}
	if layout.Version != "1.0.0" {
		t.Fatalf("unexpected layout version %q", layout.Version)
	}

	indexBytes, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatalf("read index.json: %v", err)
	}
	var index ocispec.Index
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		t.Fatalf("decode index.json: %v", err)
	}
	if len(index.Manifests) != 1 {
		t.Fatalf("expected exactly one manifest, got %d", len(index.Manifests))
	}
	if got := index.Manifests[0].Annotations[ocispec.AnnotationRefName]; got != ociLayoutRefName {
		t.Fatalf("expected ref.name annotation %q, got %q", ociLayoutRefName, got)
	}
}
