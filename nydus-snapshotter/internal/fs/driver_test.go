/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
)

func TestNewDriver(t *testing.T) {
	tests := []struct {
		name   string
		driver string
		expect func(t *testing.T, driver Driver, err error)
	}{
		{
			name:   "fuse driver",
			driver: config.DriverFUSE,
			expect: func(t *testing.T, driver Driver, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(config.DriverFUSE, driver.Name())
			},
		},
		{
			name:   "unsupported driver",
			driver: "virtiofs",
			expect: func(t *testing.T, driver Driver, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `unsupported driver "virtiofs"`)
				assert.Nil(driver)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			driver, err := newDriver(tc.driver)
			tc.expect(t, driver, err)
		})
	}
}
