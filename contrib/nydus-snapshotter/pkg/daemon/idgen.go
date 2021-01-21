/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package daemon

import (
	"encoding/base64"

	"github.com/google/uuid"
)

func newID() string {
	id := uuid.New()
	b := [16]byte(id)
	return base64.RawURLEncoding.EncodeToString(b[:])
}
