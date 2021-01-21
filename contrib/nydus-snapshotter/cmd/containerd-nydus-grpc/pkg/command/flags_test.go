/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package command

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewFlags(t *testing.T) {
	set := flag.NewFlagSet("test", 0)
	flags := NewFlags()
	for _, i := range flags.F {
		i.Apply(set)
	}
	err := set.Parse([]string{"--config-path", "/etc/testconfig", "--root", "/root"})
	assert.Nil(t, err)
	assert.Equal(t, flags.Args.ConfigPath, "/etc/testconfig")
	assert.Equal(t, flags.Args.LogLevel, "info")
	assert.Equal(t, flags.Args.RootDir, "/root")
}
