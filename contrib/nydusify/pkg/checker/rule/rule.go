// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package rule

type Rule interface {
	Validate() error
	Name() string
}
