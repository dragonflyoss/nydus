// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"fmt"
	"sync"

	"github.com/dustin/go-humanize"
	"github.com/gosuri/uiprogress"
)

const (
	StatusPulling = iota
	StatusBuilding
	StatusPushing
	StatusPushed
)

type Progress struct {
	status int
	id     string
	bar    *uiprogress.Bar
}

var onceInit sync.Once

func NewProgress(id string, name string, initStatus int, initTotal int) (*Progress, error) {
	bar := uiprogress.AddBar(initTotal).AppendCompleted().PrependElapsed()

	progress := Progress{
		status: initStatus,
		id:     id,
		bar:    bar,
	}

	bar.PrependFunc(func(bar *uiprogress.Bar) string {
		switch progress.status {
		case StatusPulling:
			return fmt.Sprintf("[%s %s] Pulling", name, progress.id)
		case StatusBuilding:
			return fmt.Sprintf("[%s %s] Building", name, progress.id)
		case StatusPushing:
			return fmt.Sprintf("[%s %s] Pushing", name, progress.id)
		case StatusPushed:
			return fmt.Sprintf("[%s %s] Pushed", name, progress.id)
		}

		return ""
	})

	bar.AppendFunc(func(bar *uiprogress.Bar) string {
		current := humanize.Bytes(uint64(bar.Current()))
		total := humanize.Bytes(uint64(bar.Total))

		switch progress.status {
		case StatusPulling:
			return fmt.Sprintf("%s/%s", current, total)
		case StatusPushing:
			return fmt.Sprintf("%s/%s", current, total)
		case StatusPushed:
			return fmt.Sprintf("%s/%s", current, total)
		}
		return ""
	})

	return &progress, nil
}

func (progress *Progress) SetStatus(status int) {
	progress.status = status
	cur := progress.bar.Current()

	progress.bar.Set(0)
	progress.bar.Set(cur)

	switch progress.status {
	case StatusBuilding:
		progress.bar.Total = 100
		progress.bar.Set(100)
	}
}

func (progress *Progress) SetTotal(value int) {
	progress.bar.Total = value
}

func (progress *Progress) SetCurrent(value int) {
	progress.bar.Set(value)
}

func (progress *Progress) SetFinish() {
	progress.bar.Set(progress.bar.Total)
}
