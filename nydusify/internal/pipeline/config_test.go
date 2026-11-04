/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

import (
	"encoding/json"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

func TestPatchImageConfig(t *testing.T) {
	assert := assert.New(t)
	created := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := patchImageConfig(json.RawMessage(`{}`), nil, func([]ocispec.History, bool) ([]ocispec.History, bool) {
		return []ocispec.History{{Created: &created}}, true
	})
	assert.ErrorContains(err, "marshal image config history")
}
