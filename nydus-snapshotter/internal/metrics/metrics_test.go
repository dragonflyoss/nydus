/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package metrics

import (
	"strconv"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestNewCounterVec(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		expect func(t *testing.T, counter *prometheus.CounterVec)
	}{
		{
			name:   "known values start at zero",
			values: []string{"foo", "bar"},
			expect: func(t *testing.T, counter *prometheus.CounterVec) {
				assert := assert.New(t)
				assert.Equal(2, testutil.CollectAndCount(counter))
				assert.Zero(testutil.ToFloat64(counter.WithLabelValues("foo")))
				assert.Zero(testutil.ToFloat64(counter.WithLabelValues("bar")))
			},
		},
		{
			name: "no known value",
			expect: func(t *testing.T, counter *prometheus.CounterVec) {
				assert := assert.New(t)
				assert.Zero(testutil.CollectAndCount(counter))
			},
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			counter := newCounterVec(prometheus.CounterOpts{Name: "nydus_snapshotter_test_" + strconv.Itoa(i) + "_total", Help: "test"}, "label", tc.values...)
			defer prometheus.Unregister(counter)
			tc.expect(t, counter)
		})
	}
}
