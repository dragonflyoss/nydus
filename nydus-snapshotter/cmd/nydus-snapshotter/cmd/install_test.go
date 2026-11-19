/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/installer"
)

func TestInstallCmd(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		expect func(t *testing.T, err error)
	}{
		{
			name: "refuse an invalid sync interval",
			args: []string{"--sync-interval", "0s"},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "invalid sync interval 0s")
			},
		},
		{
			name: "payload that is missing",
			args: []string{"--rootfs-dir", "testdata/host", "--payload-dir", "testdata/missing"},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.Error(err)
			},
		},
		{
			name: "refuse an argument",
			args: []string{"now"},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unknown command")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := executeCommand(t, append([]string{"install"}, tc.args...)...)
			tc.expect(t, err)
		})
	}
}

func TestInstallCmd_flags(t *testing.T) {
	tests := []struct {
		name   string
		flag   string
		expect func(t *testing.T, value string)
	}{
		{
			name: "rootfs dir",
			flag: "rootfs-dir",
			expect: func(t *testing.T, value string) {
				assert := assert.New(t)
				assert.Equal(installer.DefaultRootfsDir, value)
			},
		},
		{
			name: "payload dir",
			flag: "payload-dir",
			expect: func(t *testing.T, value string) {
				assert := assert.New(t)
				assert.Equal(installer.DefaultPayloadDir, value)
			},
		},
		{
			name: "token dir",
			flag: "token-dir",
			expect: func(t *testing.T, value string) {
				assert := assert.New(t)
				assert.Equal(installer.DefaultTokenDir, value)
			},
		},
		{
			name: "sync interval",
			flag: "sync-interval",
			expect: func(t *testing.T, value string) {
				assert := assert.New(t)
				assert.Equal(installer.DefaultSyncInterval.String(), value)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			flag := installCmd.Flags().Lookup(tc.flag)
			if !assert.NotNil(t, flag) {
				return
			}

			tc.expect(t, flag.DefValue)
		})
	}
}
