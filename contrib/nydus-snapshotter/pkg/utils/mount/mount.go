/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package mount

type Interface interface {
	Umount(target string) error
	IsLikelyNotMountPoint(file string) (bool, error)
}

var _ Interface = &Mounter{}
