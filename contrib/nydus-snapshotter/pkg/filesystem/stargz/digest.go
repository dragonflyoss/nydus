/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package stargz

import "strings"

type digest string

func (d digest) String() string {
	return string(d)
}

func (d digest) Sha256() string {
	pair := strings.Split(string(d), ":")
	return pair[1]
}
