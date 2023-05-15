// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/goharbor/acceleration-service/pkg/converter"
	"github.com/pkg/errors"
)

func dumpMetric(metric *converter.Metric, workDir string) error {
	file, err := os.Create(filepath.Join(workDir, "output.json"))
	if err != nil {
		return errors.Wrap(err, "Create file for metric")
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(metric); err != nil {
		return errors.Wrap(err, "Encode JSON from metric")
	}
	return nil
}
