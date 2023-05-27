// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"sync"
	"sync/atomic"
)

type Job = func() error

type RJob interface {
	Do() error
	Err() error
}

// QueueWorkerPool creates a worker pool with fixed count, caller
// puts some jobs to the pool by a fixed order and then wait all
// jobs finish by the previous order
type QueueWorkerPool struct {
	err  atomic.Value
	jobs chan RJob
	rets []chan RJob
}

// NewQueueWorkerPool creates a queued worker pool, `worker` is worker
// count, `total` is expected job count
func NewQueueWorkerPool(worker, total uint) *QueueWorkerPool {
	pool := &QueueWorkerPool{
		jobs: make(chan RJob, total),
		rets: make([]chan RJob, total),
	}

	for idx := range pool.rets {
		pool.rets[idx] = make(chan RJob, 1)
	}

	current := uint(0)
	var lock sync.Mutex

	for count := uint(0); count < worker; count++ {
		go func() {
			for {
				lock.Lock()
				current++
				if current > total {
					lock.Unlock()
					break
				}
				index := current - 1
				job, ok := <-pool.jobs
				if !ok {
					lock.Unlock()
					break
				}
				lock.Unlock()

				err := job.Do()
				pool.rets[index] <- job
				if err != nil {
					pool.err.Store(err)
					break
				}
			}
		}()
	}

	return pool
}

func (pool *QueueWorkerPool) Put(_job RJob) error {
	e := pool.err.Load()
	if e != nil {
		return e.(error)
	}

	pool.jobs <- _job
	return nil
}

func (pool *QueueWorkerPool) Waiter() []chan RJob {
	return pool.rets
}

type Once int32

func NewOnce() Once {
	return Once(0)
}

func (o *Once) Do(callback func()) {
	if atomic.CompareAndSwapInt32((*int32)(o), 0, 1) {
		callback()
	}
}

// WorkerPool creates a worker pool with fixed count, caller
// puts some jobs to the pool and then wait all jobs finish
type WorkerPool struct {
	err   chan error
	wg    sync.WaitGroup
	queue chan Job
}

// NewWorkerPool creates a worker pool, `worker` is worker
// count, `total` is expected job count
func NewWorkerPool(worker, total uint) *WorkerPool {
	pool := &WorkerPool{
		queue: make(chan Job, total),
		err:   make(chan error, 1),
	}

	once := NewOnce()

	for count := uint(0); count < worker; count++ {
		pool.wg.Add(1)
		go func() {
			defer pool.wg.Done()
			for {
				job, ok := <-pool.queue
				if !ok {
					break
				}
				if err := job(); err != nil {
					once.Do(func() {
						pool.err <- err
					})
					break
				}
			}
		}()
	}

	return pool
}

func (pool *WorkerPool) Put(job Job) {
	pool.queue <- job
}

func (pool *WorkerPool) Err() chan error {
	return pool.err
}

func (pool *WorkerPool) Waiter() chan error {
	close(pool.queue)
	pool.wg.Wait()
	close(pool.err)
	return pool.err
}
