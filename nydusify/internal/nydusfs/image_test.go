/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydusfs

import (
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

func TestRAFSVersion(t *testing.T) {
	bootstrap := ocispec.Descriptor{Annotations: map[string]string{
		nydus.LayerAnnotationNydusFsVersion: "7",
	}}
	if got := (&Image{Kind: KindNydus, Bootstrap: &bootstrap}).RAFSVersion(); got != "7" {
		t.Fatalf("RAFS version = %q, want 7", got)
	}
	if got := (&Image{Kind: KindNydus, Bootstrap: &ocispec.Descriptor{}}).RAFSVersion(); got != "unknown" {
		t.Fatalf("missing RAFS version = %q, want unknown", got)
	}
	if got := (&Image{Kind: KindOCI}).RAFSVersion(); got != "" {
		t.Fatalf("OCI RAFS version = %q, want empty", got)
	}
}
