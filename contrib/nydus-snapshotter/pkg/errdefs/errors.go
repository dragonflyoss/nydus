/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package errdefs

import (
	"net"

	"github.com/pkg/errors"
)

var (
	ErrAlreadyExists = errors.New("already exists")
)

// IsAlreadyExists returns true if the error is due to already exists
func IsAlreadyExists(err error) bool {
	return errors.Is(err, ErrAlreadyExists)
}

// IsConnectionClosed returns true if error is due to connection closed
// this is used when snapshotter closed by sig term
func IsConnectionClosed(err error) bool {
	switch err.(type) {
	case *net.OpError:
		err := err.(*net.OpError)
		return err.Err.Error() == "use of closed network connection"
	default:
		return false
	}
}
