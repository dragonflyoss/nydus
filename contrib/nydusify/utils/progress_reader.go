// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"io"
)

type ProgressReader struct {
	total    int
	reader   io.ReadCloser
	callback func(int)
}

func NewProgressReader(reader io.ReadCloser, callback func(int)) *ProgressReader {
	return &ProgressReader{
		callback: callback,
		reader:   reader,
	}
}

func (pr *ProgressReader) Read(p []byte) (count int, err error) {
	count, err = pr.reader.Read(p)
	pr.total += len(p)
	pr.callback(pr.total)
	return
}

func (pr *ProgressReader) Close() error {
	pr.callback(0)
	return pr.reader.Close()
}
