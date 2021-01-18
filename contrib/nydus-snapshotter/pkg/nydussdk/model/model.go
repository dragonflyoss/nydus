/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package model

type BuildTimeInfo struct {
	PackageVer string `json:"package_ver"`
	GitCommit  string `json:"git_commit"`
	BuildTime  string `json:"build_time"`
	Profile    string `json:"profile"`
	Rustc      string `json:"rustc"`
}

type DaemonInfo struct {
	ID      string        `json:"id"`
	Version BuildTimeInfo `json:"version"`
	State   string        `json:"state"`
}

type ErrorMessage struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type MountRequest struct {
	FsType string `json:"fs_type"`
	Source string `json:"source"`
	Config string `json:"config"`
}

func NewMountRequest(source, config string) MountRequest {
	return MountRequest{
		FsType: "rafs",
		Source: source,
		Config: config,
	}
}
