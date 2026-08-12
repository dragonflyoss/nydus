/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

import (
	"encoding/json"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// patchImageConfig replaces only the `rootfs` diff ids of a raw image config
// and lets historyFn rewrite the `history` field, keeping every other field
// byte-for-byte intact.
//
// Decoding the whole config into ocispec.Image and re-marshaling it would drop
// empty-but-present fields via `omitempty` (e.g. `"Cmd": []` is re-encoded as
// absent and then decodes back as a nil slice). The nydus config would then no
// longer be reflect.DeepEqual to the untouched source OCI config, and
// `nydusify check` would fail the manifest config-consistency rule.
func patchImageConfig(configJSON json.RawMessage, diffIDs []digest.Digest, historyFn func(history []ocispec.History, present bool) ([]ocispec.History, bool)) (json.RawMessage, error) {
	var rawConfig map[string]json.RawMessage
	if err := json.Unmarshal(configJSON, &rawConfig); err != nil {
		return nil, errors.Wrap(err, "unmarshal image config")
	}

	var rootFS ocispec.RootFS
	if raw, ok := rawConfig["rootfs"]; ok {
		if err := json.Unmarshal(raw, &rootFS); err != nil {
			return nil, errors.Wrap(err, "unmarshal image config rootfs")
		}
	}
	if rootFS.Type == "" {
		rootFS.Type = "layers"
	}
	rootFS.DiffIDs = diffIDs
	rootFSRaw, err := json.Marshal(rootFS)
	if err != nil {
		return nil, errors.Wrap(err, "marshal image config rootfs")
	}
	rawConfig["rootfs"] = rootFSRaw

	var history []ocispec.History
	rawHistory, present := rawConfig["history"]
	if present {
		if err := json.Unmarshal(rawHistory, &history); err != nil {
			return nil, errors.Wrap(err, "unmarshal image config history")
		}
	}
	if newHistory, write := historyFn(history, present); write {
		historyRaw, err := json.Marshal(newHistory)
		if err != nil {
			return nil, errors.Wrap(err, "marshal image config history")
		}
		rawConfig["history"] = historyRaw
	}

	out, err := json.Marshal(rawConfig)
	if err != nil {
		return nil, errors.Wrap(err, "marshal image config")
	}
	return out, nil
}
