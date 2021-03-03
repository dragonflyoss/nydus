// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPackTargzInfo(t *testing.T) {
	file, err := ioutil.TempFile("", "nydusify-archive-test")
	assert.Nil(t, err)
	defer os.RemoveAll(file.Name())

	err = ioutil.WriteFile(file.Name(), make([]byte, 1024*200), 0666)
	assert.Nil(t, err)

	digest, size, err := PackTargzInfo(file.Name(), "test", true)
	assert.Nil(t, err)

	assert.Equal(t, "sha256:6cdd1b26d54d5852fbea95a81cbb25383975b70b4ffad9f9b6d25c7a434a51eb", digest.String())
	assert.Equal(t, size, int64(315))
}
