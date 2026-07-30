// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/plugins/content/local"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func writeBlob(t *testing.T, ctx context.Context, store content.Store, mediaType string, data []byte) ocispec.Descriptor {
	t.Helper()
	dgst := digest.FromBytes(data)
	desc := ocispec.Descriptor{MediaType: mediaType, Digest: dgst, Size: int64(len(data))}
	ref := "test-" + dgst.String()
	if err := content.WriteBlob(ctx, store, ref, bytes.NewReader(data), desc); err != nil {
		t.Fatalf("write blob %s: %v", mediaType, err)
	}
	return desc
}

// buildLayoutWithSingleFileLayer writes a minimal single-manifest OCI Image
// Layout at dir whose one layer contains a single regular file, exercising
// the same layout shape pullImage produces without touching the network.
func buildLayoutWithSingleFileLayer(t *testing.T, dir string) {
	t.Helper()
	ctx := context.Background()

	store, err := local.NewStore(dir)
	if err != nil {
		t.Fatalf("open content store: %v", err)
	}

	var layerBuf bytes.Buffer
	gz := gzip.NewWriter(&layerBuf)
	tw := tar.NewWriter(gz)
	contents := []byte("hello from a layer\n")
	if err := tw.WriteHeader(&tar.Header{
		Name: "hello.txt",
		Mode: 0o644,
		Size: int64(len(contents)),
	}); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := tw.Write(contents); err != nil {
		t.Fatalf("write tar contents: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	layerDesc := writeBlob(t, ctx, store, ocispec.MediaTypeImageLayerGzip, layerBuf.Bytes())

	configDesc := writeBlob(t, ctx, store, ocispec.MediaTypeImageConfig, []byte(`{}`))

	manifest := ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    configDesc,
		Layers:    []ocispec.Descriptor{layerDesc},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	manifestDesc := writeBlob(t, ctx, store, ocispec.MediaTypeImageManifest, manifestBytes)

	if err := writeOCILayout(dir, manifestDesc); err != nil {
		t.Fatalf("write OCI layout: %v", err)
	}
}

func TestUnpackLayoutAppliesLayerOntoRootfs(t *testing.T) {
	layoutDir := t.TempDir()
	rootfsDir := filepath.Join(t.TempDir(), "rootfs")
	buildLayoutWithSingleFileLayer(t, layoutDir)

	if err := unpackLayout(context.Background(), layoutDir, rootfsDir); err != nil {
		t.Fatalf("unpack layout: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(rootfsDir, "hello.txt"))
	if err != nil {
		t.Fatalf("read unpacked file: %v", err)
	}
	if string(got) != "hello from a layer\n" {
		t.Fatalf("unexpected unpacked contents: %q", got)
	}
}

func TestUnpackLayoutRejectsEmptyIndex(t *testing.T) {
	layoutDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(layoutDir, "index.json"), []byte(`{"schemaVersion":2,"manifests":[]}`), 0o644); err != nil {
		t.Fatalf("write index.json: %v", err)
	}

	err := unpackLayout(context.Background(), layoutDir, filepath.Join(t.TempDir(), "rootfs"))
	if err == nil {
		t.Fatal("expected an error for a layout with no manifests")
	}
}
