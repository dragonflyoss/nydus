// Copyright 2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsPossibleValue(t *testing.T) {
	value := "qwe"
	list := []string{"abc", "qwe", "xyz"}
	require.True(t, isPossibleValue(list, value))

	// Failure situation
	value2 := "vdf"
	require.False(t, isPossibleValue(list, value2))
}

func TestAddReferenceSuffix(t *testing.T) {
	source := "localhost:5000/nginx:latest"
	suffix := "-suffix"
	target, err := addReferenceSuffix(source, suffix)
	require.NoError(t, err)
	require.Equal(t, target, "localhost:5000/nginx:latest-suffix")

	// Failure situation
	source = "localhost:5000\nginx:latest"
	suffix = "-suffix"
	_, err = addReferenceSuffix(source, suffix)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid source image reference")
}

func TestParseBackendConfig(t *testing.T) {
	configJSON := `
	{
		"bucket_name": "test",
		"endpoint": "region.oss.com",
		"access_key_id": "testAK",
		"access_key_secret": "testSK",
		"meta_prefix": "meta",
		"blob_prefix": "blob"
	}`
	require.True(t, json.Valid([]byte(configJSON)))

	file, err := os.CreateTemp("", "nydusify-backend-config-test.json")
	require.NoError(t, err)
	defer os.RemoveAll(file.Name())

	_, err = file.WriteString(configJSON)
	require.NoError(t, err)
	file.Sync()

	resultJSON, err := parseBackendConfig("", file.Name())
	require.NoError(t, err)
	require.True(t, json.Valid([]byte(resultJSON)))
	require.Equal(t, configJSON, resultJSON)

	// Failure situation
	_, err = parseBackendConfig(configJSON, file.Name())
	require.Error(t, err)
}
