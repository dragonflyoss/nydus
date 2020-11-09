// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"sync/atomic"
)

type Job interface {
	Do(method int) error
}

type JobRet struct {
	idx int
	Job Job
	Err error
}

func NewQueueWorkerPool(jobs []Job, worker uint, method int) []chan JobRet {
	count := len(jobs)

	if count <= 0 {
		return nil
	}

	remain := uint64(count)
	queue := make(chan JobRet, count)
	results := []chan JobRet{}

	for idx, job := range jobs {
		jobRet := JobRet{
			idx: idx,
			Job: job,
			Err: nil,
		}
		queue <- jobRet
		results = append(results, make(chan JobRet))
	}

	for count := uint(0); count < worker; count++ {
		go func() {
			for {
				jobRet, ok := <-queue
				if !ok {
					return
				}
				err := jobRet.Job.Do(method)
				jobRet.Err = err
				results[jobRet.idx] <- jobRet
				if err != nil {
					close(queue)
					return
				}
				if atomic.AddUint64(&remain, ^uint64(0)) == 0 {
					close(queue)
				}
			}
		}()
	}

	return results
}

type WorkerPool struct {
	err   error
	queue chan JobRet
}

func NewWorkerPool(worker uint, method int) *WorkerPool {
	queue := make(chan JobRet, worker)

	workerPool := WorkerPool{
		queue: queue,
	}

	for count := uint(0); count < worker; count++ {
		go func() {
			for {
				jobRet, ok := <-queue
				if !ok {
					return
				}
				err := jobRet.Job.Do(method)
				jobRet.Err = err
				if err != nil {
					workerPool.err = err
					close(queue)
					return
				}
			}
		}()
	}

	return &workerPool
}

func (pool *WorkerPool) AddJob(job Job) error {
	if pool.err != nil {
		return pool.err
	}
	pool.queue <- JobRet{
		idx: 0,
		Job: job,
		Err: nil,
	}
	return nil
}

func (pool *WorkerPool) Wait() error {
	close(pool.queue)
	for jobRet := range pool.queue {
		if jobRet.Err != nil {
			return jobRet.Err
		}
	}
	return nil
}
