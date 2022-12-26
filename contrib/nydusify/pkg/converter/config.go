// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import "strconv"

func getConfig(opt Opt) map[string]string {
	cfg := map[string]string{}

	cfg["backend_type"] = opt.BackendType
	cfg["backend_config"] = opt.BackendConfig
	cfg["fs_version"] = opt.FsVersion
	cfg["compressor"] = opt.Compressor
	cfg["merge_manifest"] = strconv.FormatBool(opt.MultiPlatform)
	cfg["work_dir"] = opt.WorkDir
	cfg["builder"] = opt.NydusImagePath
	cfg["chunk_dict_ref"] = opt.ChunkDictRef

	// FIXME: still needs to be supported by acceld converter package.
	cfg["backend_force_push"] = strconv.FormatBool(opt.BackendForcePush)
	cfg["docker2oci"] = strconv.FormatBool(!opt.DockerV2Format)
	cfg["platform"] = opt.TargetPlatform
	cfg["fs_align_chunk"] = strconv.FormatBool(opt.FsAlignChunk)
	cfg["prefetch_patterns"] = opt.PrefetchPatterns
	cfg["chunk_size"] = opt.ChunkSize

	cfg["cache_ref"] = opt.CacheRef
	cfg["cache_version"] = opt.CacheVersion
	cfg["cache_max_records"] = strconv.FormatUint(uint64(opt.CacheMaxRecords), 10)

	return cfg
}
