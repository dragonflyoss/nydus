// Copyright 2020 Ant Group. All rights reserved.
// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackTargzInfo(t *testing.T) {
	file, err := os.CreateTemp("", "nydusify-archive-test")
	assert.Nil(t, err)
	defer os.RemoveAll(file.Name())

	err = os.WriteFile(file.Name(), make([]byte, 1024*200), 0666)
	assert.Nil(t, err)

	digest, size, err := PackTargzInfo(file.Name(), "test", true)
	assert.Nil(t, err)

	assert.Equal(t, "sha256:6cdd1b26d54d5852fbea95a81cbb25383975b70b4ffad9f9b6d25c7a434a51eb", digest.String())
	assert.Equal(t, size, int64(315))
}

func TestUnpackTargz(t *testing.T) {
	file, err := os.CreateTemp("", "nydusify-test")
	defer os.RemoveAll(file.Name())
	require.NoError(t, err)
	err = os.WriteFile(file.Name(), []byte("123456789"), 0666)
	require.NoError(t, err)
	reader, err := PackTargz(file.Name(), file.Name(), true)
	require.NoError(t, err)

	err = UnpackTargz(context.Background(), "test", io.Reader(reader), false)
	defer os.RemoveAll("test")
	require.NoError(t, err)
	err = UnpackTargz(context.Background(), "test", io.Reader(reader), true)
	require.NoError(t, err)
}
