/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import (
	"contrib/nydus-snapshotter/pkg/filesystem/nydus"
)

type Config struct {
	Address              string
	ConvertVpcRegistry   bool
	DaemonCfg            nydus.DaemonConfig
	PublicKeyFile        string
	RootDir              string
	ValidateSignature    bool
	NydusdBinaryPath     string
	NydusImageBinaryPath string
	SharedDaemon         bool
}

