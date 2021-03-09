// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type queueJob struct {
	err    error
	before int
	after  int
}

func (job *queueJob) Do() error {
	if job.before == 1500 {
		job.err = fmt.Errorf("Job error")
		return job.err
	}
	time.Sleep(time.Microsecond * 1)
	job.after = job.before
	return nil
}

func (job *queueJob) Err() error {
	return job.err
}

func TestQueueWorkerPool1(t *testing.T) {
	pool := NewQueueWorkerPool(47, 1000)

	for i := 0; i < 1000; i++ {
		job := &queueJob{
			before: i,
			after:  -1,
		}
		pool.Put(job)
	}

	for idx, job := range pool.Waiter() {
		ret := (<-job).(*queueJob)
		assert.Equal(t, ret.after, idx)
	}
}

func TestQueueWorkerPool2(t *testing.T) {
	pool := NewQueueWorkerPool(47, 2000)

	for i := 0; i < 2000; i++ {
		job := &queueJob{
			before: i,
			after:  -1,
		}
		pool.Put(job)
	}

	for idx, _job := range pool.Waiter() {
		job := <-_job
		ret := job.(*queueJob)
		if job.Err() != nil {
			assert.Equal(t, ret.before, 1500)
			break
		}
		assert.Equal(t, ret.after, idx)
	}
}

func TestWorkerPool1(t *testing.T) {
	pool := NewWorkerPool(20, 50)

	for i := 0; i < 50; i++ {
		pool.Put(func() error {
			time.Sleep(time.Millisecond * 10)
			return nil
		})
	}

	assert.Nil(t, pool.Wait())
}

func TestWorkerPool2(t *testing.T) {
	pool := NewWorkerPool(2, 2)

	pool.Put(func() error {
		time.Sleep(time.Millisecond * 20)
		return fmt.Errorf("Job error")
	})

	time.Sleep(time.Millisecond * 10)

	pool.Put(func() error {
		time.Sleep(time.Millisecond * 30)
		return nil
	})

	assert.NotNil(t, pool.Wait())
}

func TestWorkerPool3(t *testing.T) {
	pool := NewWorkerPool(20, 50)

	for i := 0; i < 50; i++ {
		pool.Put(func() error {
			time.Sleep(time.Millisecond * 10)
			return fmt.Errorf("Job error")
		})
	}

	assert.NotNil(t, pool.Wait())
}

func TestWorkerPool4(t *testing.T) {
	pool := NewWorkerPool(100, 50)

	for i := 0; i < 50; i++ {
		pool.Put(func() error {
			time.Sleep(time.Millisecond * 10)
			return nil
		})
	}

	assert.Nil(t, pool.Wait())
}

func TestWorkerPool5(t *testing.T) {
	pool := NewWorkerPool(20, 51)

	for i := 0; i < 50; i++ {
		pool.Put(func() error {
			time.Sleep(time.Millisecond * 10)
			return fmt.Errorf("Job error")
		})
	}

	pool.Put(func() error {
		time.Sleep(time.Second * 10)
		return nil
	})

	assert.NotNil(t, pool.Wait())
}
