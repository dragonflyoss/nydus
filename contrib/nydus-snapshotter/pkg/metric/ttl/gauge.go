/*
 * Copyright (c) 2021. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package ttl

import (
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	defaultCleanUpPeriod = 10 * time.Minute
)

type LabelWithValue struct {
	name  string
	value string
}

type GaugeVec struct {
	labelName     []string
	ttl           time.Duration
	labelValueMap map[LabelWithValue]time.Time
	mu            sync.Mutex
	*prometheus.GaugeVec
}

type GaugeWithTTL struct {
	labelValue []string
	vec        *GaugeVec
	gauge      prometheus.Gauge
}

func NewGaugeVecWithTTL(opts prometheus.GaugeOpts, labelNames []string, ttl time.Duration) *GaugeVec {
	gaugeVec := prometheus.NewGaugeVec(opts, labelNames)
	res := &GaugeVec{
		labelName:     labelNames,
		ttl:           ttl,
		GaugeVec:      gaugeVec,
		labelValueMap: make(map[LabelWithValue]time.Time),
	}
	go res.cleanUpExpired()
	return res
}

func (gv *GaugeVec) cleanUpExpired() {
	timer := time.NewTicker(defaultCleanUpPeriod)
	for {
		select {
		case <-timer.C:
			gv.mu.Lock()
			for k, v := range gv.labelValueMap {
				if time.Now().After(v) {
					gv.DeleteLabelValues(k.value)
					delete(gv.labelValueMap, k)
				}
			}
			gv.mu.Unlock()
		}
	}
}

func (gv *GaugeVec) WithLabelValues(val ...string) *GaugeWithTTL {
	gauge := gv.GaugeVec.WithLabelValues(val...)
	return &GaugeWithTTL{
		vec:        gv,
		labelValue: val,
		gauge:      gauge,
	}
}

func (gwt *GaugeWithTTL) Set(val float64) {
	gwt.vec.mu.Lock()
	gwt.vec.labelValueMap[LabelWithValue{
		name:  strings.Join(gwt.vec.labelName, ","),
		value: strings.Join(gwt.labelValue, ","),
	}] = time.Now().Add(gwt.vec.ttl)
	gwt.vec.mu.Unlock()
	gwt.gauge.Set(val)
}
