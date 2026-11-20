/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestString(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		commit    string
		buildTime string
		expect    func(t *testing.T, s string)
	}{
		{
			name:      "released build",
			version:   "v3.0.0",
			commit:    "1a2b3c4d",
			buildTime: "2026-01-02T03:04:05Z",
			expect: func(t *testing.T, s string) {
				assert := assert.New(t)
				assert.Equal("v3.0.0 (commit 1a2b3c4d, built 2026-01-02T03:04:05Z)", s)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func(version, commit, buildTime string) {
				GitVersion, GitCommit, BuildTime = version, commit, buildTime
			}(GitVersion, GitCommit, BuildTime)
			GitVersion, GitCommit, BuildTime = tc.version, tc.commit, tc.buildTime
			tc.expect(t, String())
		})
	}
}
