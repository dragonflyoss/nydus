// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"github.com/pkg/errors"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/build"
)

// Bootstrap in Nydus image
type Bootstrap struct {
	BootstrapPath  string
	NydusImagePath string
}

func (bootstrap *Bootstrap) Name() string {
	return "Bootstrap"
}

func (bootstrap *Bootstrap) Save() error {

	// `nydus-image chunkdict save` command
	builder := build.NewBuilder(bootstrap.NydusImagePath)
	if err := builder.Save(build.SaveOption{
		BootstrapPath: bootstrap.BootstrapPath,
	}); err != nil {
		return errors.Wrap(err, "invalid nydus bootstrap format")
	}

	return nil
}
