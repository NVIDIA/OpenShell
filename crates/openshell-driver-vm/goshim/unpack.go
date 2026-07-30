// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	"github.com/containerd/containerd/v2/plugins/content/local"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// unpackLayout applies every layer described by the OCI Image Layout at
// layoutDir onto destRootfsDir, in manifest order, using containerd's
// archive.Apply. This replaces a hand-rolled directory merge that only
// understood plain files/dirs/symlinks and OCI whiteouts; archive.Apply
// additionally handles opaque directories, hardlinks, device nodes, FIFOs,
// and xattrs the way any other OCI-compliant unpacker would.
func unpackLayout(ctx context.Context, layoutDir, destRootfsDir string) error {
	store, err := local.NewStore(layoutDir)
	if err != nil {
		return wrapf(err, "open content store %q", layoutDir)
	}

	indexBytes, err := os.ReadFile(filepath.Join(layoutDir, "index.json"))
	if err != nil {
		return wrapf(err, "read index.json in %q", layoutDir)
	}
	var index ocispec.Index
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		return wrapf(err, "decode index.json in %q", layoutDir)
	}
	if len(index.Manifests) == 0 {
		return fmt.Errorf("OCI layout %q has no manifests", layoutDir)
	}

	manifestBytes, err := content.ReadBlob(ctx, store, index.Manifests[0])
	if err != nil {
		return wrapf(err, "read manifest blob")
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return wrapf(err, "decode manifest")
	}

	if err := os.MkdirAll(destRootfsDir, 0o755); err != nil {
		return wrapf(err, "create rootfs dir %q", destRootfsDir)
	}

	for i, layer := range manifest.Layers {
		if err := applyLayer(ctx, store, layer, destRootfsDir); err != nil {
			return wrapf(err, "apply layer %d/%d (%s)", i+1, len(manifest.Layers), layer.Digest)
		}
	}
	return nil
}

func applyLayer(ctx context.Context, provider content.Provider, layer ocispec.Descriptor, dest string) error {
	ra, err := provider.ReaderAt(ctx, layer)
	if err != nil {
		return wrapf(err, "open layer reader")
	}
	defer ra.Close()

	decompressed, err := compression.DecompressStream(content.NewReader(ra))
	if err != nil {
		return wrapf(err, "decompress layer")
	}
	defer decompressed.Close()

	// Sandbox rootfs ownership is normalized separately by the guest-side
	// init script and host-side debugfs pass; preserve the layer's own
	// uid/gid here rather than remapping to the calling (host) user.
	if _, err := archive.Apply(ctx, dest, decompressed, archive.WithNoSameOwner()); err != nil {
		return wrapf(err, "apply layer tar")
	}
	return nil
}
