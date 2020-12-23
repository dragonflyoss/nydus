/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithNydusdBinaryPath(t *testing.T) {
	var fs filesystem
	opt := WithNydusdBinaryPath("/bin/nydusd")
	err := opt(&fs)
	assert.Nil(t, err)
	assert.Equal(t, "/bin/nydusd", fs.nydusdBinaryPath)
}
