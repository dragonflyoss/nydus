// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"github.com/goharbor/acceleration-service/pkg/remote"
)

func hosts(opt Opt) remote.HostFunc {
	maps := map[string]bool{
		opt.Source:       opt.SourceInsecure,
		opt.Target:       opt.TargetInsecure,
		opt.ChunkDictRef: opt.ChunkDictInsecure,
		opt.CacheRef:     opt.CacheInsecure,
	}
	return func(ref string) (remote.CredentialFunc, bool, error) {
		return remote.NewDockerConfigCredFunc(), maps[ref], nil
	}
}
