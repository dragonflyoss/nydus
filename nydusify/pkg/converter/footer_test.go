/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestHasBootstrapDistinguishesDataOnlyBlobs(t *testing.T) {
	for _, tc := range []struct {
		name            string
		bootstrapBlocks uint32
		want            bool
	}{
		{"layer blob", 4, true},
		{"ondemand blob", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blob := append(make([]byte, 1024), syntheticFooter(tc.bootstrapBlocks)...)
			got, err := HasBootstrap(bytes.NewReader(blob), int64(len(blob)))
			if err != nil {
				t.Fatalf("HasBootstrap: %v", err)
			}
			if got != tc.want {
				t.Errorf("HasBootstrap = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHasBootstrapRejectsNonNydusBlobs(t *testing.T) {
	blob := make([]byte, NydusBlobFooterSize)
	if _, err := HasBootstrap(bytes.NewReader(blob), int64(len(blob))); err == nil {
		t.Error("expected an error for a blob without the footer magic")
	}
}

func syntheticFooter(bootstrapBlocks uint32) []byte {
	footer := make([]byte, NydusBlobFooterSize)
	copy(footer, NydusBlobFooterMagic)
	binary.LittleEndian.PutUint32(footer[bootstrapBlocksField:], bootstrapBlocks)
	return footer
}
