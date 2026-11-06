/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseReference(t *testing.T) {
	tests := []struct {
		name   string
		ref    string
		expect func(t *testing.T, ref *Reference, err error)
	}{
		{
			name: "docker hub official image",
			ref:  "ubuntu:24.04",
			expect: func(t *testing.T, ref *Reference, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&Reference{Name: "docker.io/library/ubuntu:24.04", Host: "docker.io", Repository: "library/ubuntu"}, ref)
			},
		},
		{
			name: "private registry with port",
			ref:  "registry.example.com:5000/team/app:v1-nydus-v3",
			expect: func(t *testing.T, ref *Reference, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("registry.example.com:5000", ref.Host)
				assert.Equal("team/app", ref.Repository)
			},
		},
		{
			name: "invalid reference",
			ref:  "Invalid:Ref",
			expect: func(t *testing.T, ref *Reference, err error) {
				assert.Error(t, err)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ref, err := ParseReference(tc.ref)
			tc.expect(t, ref, err)
		})
	}
}
