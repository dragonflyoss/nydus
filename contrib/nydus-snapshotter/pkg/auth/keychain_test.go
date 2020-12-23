/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/label"
)

func TestFromLabels(t *testing.T) {
	labels := map[string]string{
		label.ImagePullUsername: "mock",
		label.ImagePullSecret:   "mock",
	}
	kc, err := FromLabels(labels)
	assert.Nil(t, err)
	assert.Equal(t, kc.Username, "mock")
	assert.Equal(t, kc.Password, "mock")
	assert.Equal(t, "bW9jazptb2Nr", kc.ToBase64())

	kc, err = FromBase64("bW9jazptb2Nr")
	assert.Nil(t, err)
	assert.Equal(t, kc.Username, "mock")
	assert.Equal(t, kc.Password, "mock")

	labels = map[string]string{}
	kc, err = FromLabels(labels)
	assert.Nil(t, err)
	assert.Equal(t, "", kc.ToBase64())
}
