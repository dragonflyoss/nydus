// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"strconv"
)

func getConfig(opt Opt) map[string]string {
	cfg := map[string]string{}

	cfg["work_dir"] = opt.WorkDir
	cfg["builder"] = opt.NydusImagePath

	cfg["backend_type"] = opt.BackendType
	cfg["backend_config"] = opt.BackendConfig
	cfg["backend_force_push"] = strconv.FormatBool(opt.BackendForcePush)

	cfg["chunk_dict_ref"] = opt.ChunkDictRef
	cfg["docker2oci"] = strconv.FormatBool(opt.Docker2OCI)
	cfg["merge_manifest"] = strconv.FormatBool(opt.MergePlatform)
	cfg["oci_ref"] = strconv.FormatBool(opt.OCIRef)
	cfg["with_referrer"] = strconv.FormatBool(opt.WithReferrer)

	cfg["prefetch_patterns"] = opt.PrefetchPatterns
	cfg["compressor"] = opt.Compressor
	cfg["fs_version"] = opt.FsVersion
	cfg["fs_align_chunk"] = strconv.FormatBool(opt.FsAlignChunk)
	cfg["fs_chunk_size"] = opt.ChunkSize
	cfg["batch_size"] = opt.BatchSize

	cfg["cache_ref"] = opt.CacheRef
	cfg["cache_version"] = opt.CacheVersion
	cfg["cache_max_records"] = strconv.FormatUint(uint64(opt.CacheMaxRecords), 10)

	return cfg
}
