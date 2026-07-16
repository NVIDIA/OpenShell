// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// ociLayoutRefName is the "org.opencontainers.image.ref.name" annotation
// value written into index.json for every pulled image. The guest-side
// `openshell-vm-sandbox-init.sh` unpacks images via
// `umoci raw unpack --image "$dir:openshell"`, so this value must stay in
// sync with that script.
const ociLayoutRefName = "openshell"

func resolveDigest(ctx context.Context, imageRef, platformOS, platformArch string) (string, error) {
	resolver := docker.NewResolver(newResolver())
	_, desc, err := resolver.Resolve(ctx, imageRef)
	if err != nil {
		return "", wrapf(err, "resolve image %q", imageRef)
	}

	if !images.IsIndexType(desc.MediaType) {
		return desc.Digest.String(), nil
	}

	// The top-level descriptor is a multi-platform index; resolving the
	// per-platform manifest digest (rather than the index digest) keeps
	// cache identity aligned with what actually gets unpacked, matching
	// the previous oci-client based behavior.
	fetcher, err := resolver.Fetcher(ctx, imageRef)
	if err != nil {
		return "", wrapf(err, "create fetcher for %q", imageRef)
	}
	rc, err := fetcher.Fetch(ctx, desc)
	if err != nil {
		return "", wrapf(err, "fetch index for %q", imageRef)
	}
	indexBytes, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		return "", wrapf(err, "read index for %q", imageRef)
	}
	platform := platforms.OnlyStrict(ocispec.Platform{OS: platformOS, Architecture: platformArch})
	manifestDesc, err := selectManifestForPlatform(indexBytes, platform)
	if err != nil {
		return "", wrapf(err, "select platform manifest for %q", imageRef)
	}
	return manifestDesc.Digest.String(), nil
}

func pullImage(ctx context.Context, imageRef, destLayoutDir, platformOS, platformArch string) error {
	resolver := docker.NewResolver(newResolver())

	name, desc, err := resolver.Resolve(ctx, imageRef)
	if err != nil {
		return wrapf(err, "resolve image %q", imageRef)
	}
	fetcher, err := resolver.Fetcher(ctx, name)
	if err != nil {
		return wrapf(err, "create fetcher for %q", imageRef)
	}

	if err := os.MkdirAll(destLayoutDir, 0o755); err != nil {
		return wrapf(err, "create OCI layout dir %q", destLayoutDir)
	}
	store, err := local.NewStore(destLayoutDir)
	if err != nil {
		return wrapf(err, "open content store %q", destLayoutDir)
	}

	platform := platforms.OnlyStrict(ocispec.Platform{OS: platformOS, Architecture: platformArch})

	// Recursively fetch the descriptor tree (index -> manifest -> config +
	// layers), restricted to the requested platform so multi-arch images
	// only download the bytes this sandbox actually needs. Digest
	// verification happens automatically: the content store's writer
	// commits each blob against its expected descriptor digest.
	handler := remotes.FilterManifestByPlatformHandler(
		images.Handlers(
			remotes.FetchHandler(store, fetcher),
			images.ChildrenHandler(store),
		),
		platform,
	)
	if err := images.Dispatch(ctx, handler, nil, desc); err != nil {
		return wrapf(err, "pull image content for %q", imageRef)
	}

	manifestDesc, err := resolveManifestDescriptor(ctx, store, desc, platform)
	if err != nil {
		return wrapf(err, "resolve manifest for %q", imageRef)
	}

	if err := writeOCILayout(destLayoutDir, manifestDesc); err != nil {
		return wrapf(err, "write OCI layout at %q", destLayoutDir)
	}

	// local.NewStore scratch state; harmless to leave but unnecessary in a
	// layout that gets copied verbatim into a guest disk image.
	_ = os.RemoveAll(filepath.Join(destLayoutDir, "ingest"))
	return nil
}

// resolveManifestDescriptor returns the descriptor of the single-platform
// manifest to record as the sole entry of index.json. If desc already
// refers to a manifest (not a multi-platform index), it is returned as-is.
func resolveManifestDescriptor(
	ctx context.Context,
	provider content.Provider,
	desc ocispec.Descriptor,
	platform platforms.MatchComparer,
) (ocispec.Descriptor, error) {
	if !images.IsIndexType(desc.MediaType) {
		return desc, nil
	}

	indexBytes, err := content.ReadBlob(ctx, provider, desc)
	if err != nil {
		return ocispec.Descriptor{}, wrapf(err, "read index blob")
	}
	return selectManifestForPlatform(indexBytes, platform)
}

func selectManifestForPlatform(indexBytes []byte, matcher platforms.MatchComparer) (ocispec.Descriptor, error) {
	var index ocispec.Index
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		return ocispec.Descriptor{}, wrapf(err, "decode image index")
	}

	for _, candidate := range index.Manifests {
		if candidate.Platform == nil || matcher.Match(*candidate.Platform) {
			return candidate, nil
		}
	}
	return ocispec.Descriptor{}, fmt.Errorf("no manifest in image index matches the requested platform")
}

func writeOCILayout(layoutDir string, manifestDesc ocispec.Descriptor) error {
	layout := ocispec.ImageLayout{Version: "1.0.0"}
	layoutBytes, err := json.Marshal(layout)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(layoutDir, "oci-layout"), layoutBytes, 0o644); err != nil {
		return err
	}

	if manifestDesc.Annotations == nil {
		manifestDesc.Annotations = map[string]string{}
	} else {
		// Copy before mutating; the caller's descriptor may be reused.
		annotations := make(map[string]string, len(manifestDesc.Annotations)+1)
		for k, v := range manifestDesc.Annotations {
			annotations[k] = v
		}
		manifestDesc.Annotations = annotations
	}
	manifestDesc.Annotations[ocispec.AnnotationRefName] = ociLayoutRefName

	index := ocispec.Index{
		Versioned: struct {
			SchemaVersion int `json:"schemaVersion"`
		}{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{manifestDesc},
	}
	indexBytes, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(layoutDir, "index.json"), indexBytes, 0o644)
}
