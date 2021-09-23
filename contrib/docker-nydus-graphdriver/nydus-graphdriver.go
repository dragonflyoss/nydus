// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

package main

import (
	"github.com/docker/go-plugins-helpers/graphdriver/shim"
	"github.com/dragonflyoss/image-service/contrib/nydus_graphdriver/plugin/nydus"
)

func main() {
	handler := shim.NewHandlerFromGraphDriver(nydus.Init)
	handler.ServeUnix("plugin", 0)
}
