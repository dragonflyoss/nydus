/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/label"
)

func TestFromLabels(t *testing.T) {
	labels := map[string]string{
		label.ImagePullUsername: "mock",
		label.ImagePullSecret:   "mock",
	}
	kc := FromLabels(labels)
	assert.Equal(t, kc.Username, "mock")
	assert.Equal(t, kc.Password, "mock")
	assert.Equal(t, "bW9jazptb2Nr", kc.ToBase64())

	kc1, err := FromBase64("bW9jazptb2Nr")
	assert.Nil(t, err)
	assert.Equal(t, kc1.Username, "mock")
	assert.Equal(t, kc1.Password, "mock")

	labels = map[string]string{}
	kc = FromLabels(labels)
	assert.Nil(t, kc)

	labels = map[string]string{
		label.ImagePullSecret: "mock",
	}
	kc = FromLabels(labels)
	assert.Nil(t, kc)
}
