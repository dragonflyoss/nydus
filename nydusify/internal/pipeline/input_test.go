/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateConvertInputs(t *testing.T) {
	tests := []struct {
		name   string
		input  ConvertInput
		expect func(t *testing.T, artifact bool, err error)
	}{
		{
			name:  "normal source mode",
			input: ConvertInput{Sources: []string{"localhost:5000/repo/image:tag"}},
			expect: func(t *testing.T, artifact bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.False(artifact)
			},
		},
		{
			name:  "artifact with local blob",
			input: ConvertInput{BootstrapPath: "/tmp/image.boot", BlobPaths: []string{"/tmp/blob"}},
			expect: func(t *testing.T, artifact bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(artifact)
			},
		},
		{
			name:  "artifact with parent image only",
			input: ConvertInput{BootstrapPath: "/tmp/image.boot", ParentImages: []string{"localhost:5000/repo/image:parent"}},
			expect: func(t *testing.T, artifact bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(artifact)
			},
		},
		{
			name: "reject missing inputs",
			expect: func(t *testing.T, artifact bool, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "either --source or --bootstrap is required")
			},
		},
		{
			name: "reject source mixed with artifact input",
			input: ConvertInput{
				Sources:       []string{"localhost:5000/repo/image:tag"},
				BootstrapPath: "/tmp/image.boot",
				BlobPaths:     []string{"/tmp/blob"},
			},
			expect: func(t *testing.T, artifact bool, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "--source cannot be combined with artifact inputs (--bootstrap/--blob/--blob-dir/--parent-image)")
			},
		},
		{
			name:  "reject artifact without bootstrap",
			input: ConvertInput{BlobPaths: []string{"/tmp/blob"}},
			expect: func(t *testing.T, artifact bool, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "--bootstrap is required when using --blob, --blob-dir, or --parent-image")
			},
		},
		{
			name:  "defer payload validation of bootstrap only artifact",
			input: ConvertInput{BootstrapPath: "/tmp/image.boot"},
			expect: func(t *testing.T, artifact bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(artifact)
			},
		},
		{
			name: "reject multiple parent images",
			input: ConvertInput{
				BootstrapPath: "/tmp/image.boot",
				ParentImages: []string{
					"localhost:5000/repo/image:parent-a",
					"localhost:5000/repo/image:parent-b",
				},
			},
			expect: func(t *testing.T, artifact bool, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "only one --parent-image is supported")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			artifact, err := ValidateConvertInputs(tc.input)
			tc.expect(t, artifact, err)
		})
	}
}
