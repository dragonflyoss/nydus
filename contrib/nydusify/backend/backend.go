// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/pkg/errors"
)

type Backend interface {
	Put(blobID string, reader io.Reader, progress func(cur int)) error
}

func NewBackend(backendType, backendConfig string) (Backend, error) {
	switch backendType {
	case "registry":
		return nil, nil
	case "oss":
		var config map[string]string
		if err := json.Unmarshal([]byte(backendConfig), &config); err != nil {
			return nil, errors.Wrap(err, "parse backend config")
		}
		return newOSSBackend(
			config["endpoint"],
			config["bucket_name"],
			config["access_key_id"],
			config["access_key_secret"],
		)
	default:
		return nil, fmt.Errorf("unsupported backend type: %s", backendType)
	}

}
