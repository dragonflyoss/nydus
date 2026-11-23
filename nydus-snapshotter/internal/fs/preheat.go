/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/continuity"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"golang.org/x/sync/semaphore"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/kmutex"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/metrics"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/registry"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd"
)

const (
	// preheatRecordFile is what the snapshotter keeps of a preheat.
	preheatRecordFile = "preheat.json"

	// preheatConfigFile is the rendered config of a preheat process. It holds
	// the credential and is removed once the process exits.
	preheatConfigFile = "config.yaml"

	// preheatStateFile is the state a preheat process rewrites.
	preheatStateFile = "state.json"

	// preheatPollInterval is how often the unit of a running preheat is
	// checked.
	preheatPollInterval = time.Second

	// preheatRetention keeps a finished preheat long enough for its state to
	// be read.
	preheatRetention = 24 * time.Hour
)

// PreheatState is the state of a preheat.
type PreheatState string

const (
	// PreheatStatePending is a preheat waiting for a slot.
	PreheatStatePending PreheatState = "pending"

	// PreheatStateRunning is a preheat downloading the blobs of the image.
	PreheatStateRunning PreheatState = "running"

	// PreheatStateSucceeded is a preheat that downloaded every blob of the
	// image.
	PreheatStateSucceeded PreheatState = "succeeded"

	// PreheatStateFailed is a preheat that stopped at the first blob that
	// failed.
	PreheatStateFailed PreheatState = "failed"
)

// PreheatCredential is the registry credential of one preheat: a username
// and a password, or a bearer token.
type PreheatCredential struct {
	// Username is the username of the registry.
	Username string

	// Password is the password of the registry.
	Password string

	// BearerToken is the token sent to the registry as is.
	BearerToken string
}

// renderOptions returns the credential as the options of a nydus config.
func (c *PreheatCredential) renderOptions() *renderOptions {
	if c.BearerToken != "" {
		return &renderOptions{registryToken: c.BearerToken}
	}

	return &renderOptions{auth: base64.StdEncoding.EncodeToString([]byte(c.Username + ":" + c.Password))}
}

// PreheatBlob is a blob of the image of a preheat.
type PreheatBlob struct {
	// Digest is the digest of the blob, as the registry names it.
	Digest string `json:"digest"`

	// ContentLength is the uncompressed size of the blob in bytes.
	ContentLength uint64 `json:"content_length"`

	// FinishedContentLength is the uncompressed size of the downloaded part
	// of the blob in bytes.
	FinishedContentLength uint64 `json:"finished_content_length"`

	// IsFinished reports whether the blob is downloaded completely.
	IsFinished bool `json:"is_finished"`
}

// Preheat is the preheat of an image: one process that downloads every blob
// the image references into the cache.
type Preheat struct {
	// State is the state of the preheat.
	State PreheatState

	// Blobs are the blobs of the image, in the order of the state file.
	Blobs []PreheatBlob

	// Description is the reason of a failure. It never holds the credential.
	Description string

	// CreatedAt is when the preheat was queued.
	CreatedAt time.Time

	// UpdatedAt is when the preheat last changed.
	UpdatedAt time.Time
}

// preheatRecord is what the snapshotter keeps of a preheat in its directory.
type preheatRecord struct {
	// Image is the image reference, which tells whoever reads the file on
	// the node what the directory of a chain ID preheats.
	Image string `json:"image"`

	// CreatedAt is when the preheat was queued.
	CreatedAt time.Time `json:"created_at"`
}

// preheatProgress is the state file a preheat process rewrites while it runs
// and once before it exits, refer to the Preheat section of docs/nydus.md.
type preheatProgress struct {
	// State is running, succeeded or failed.
	State PreheatState `json:"state"`

	// Blobs are the blobs of the image: the priority blobs, then the rest.
	Blobs []PreheatBlob `json:"blobs"`

	// Description is the reason of a failure.
	Description string `json:"description"`

	// UpdatedAt is when the file was written.
	UpdatedAt time.Time `json:"updated_at"`
}

// finished reports whether the process wrote its result.
func (p *preheatProgress) finished() bool {
	return p.State == PreheatStateSucceeded || p.State == PreheatStateFailed
}

// expired reports whether the result is older than preheatRetention.
func (p *preheatProgress) expired() bool {
	return p.finished() && time.Since(p.UpdatedAt) > preheatRetention
}

// preheatJob is a pending or running preheat.
type preheatJob struct {
	// id identifies the image.
	id daemonID

	// image is the image to preheat; nil for a preheat whose unit outlived a
	// restart of the snapshotter.
	image *Image

	// credential is what the blobs are read with, dropped once the config is
	// rendered.
	credential *PreheatCredential

	// running reports whether the unit was started.
	running atomic.Bool
}

// preheatQueue holds the pending and running preheats.
type preheatQueue struct {
	// locker serializes queuing a preheat of an image with expiring the
	// previous one.
	locker kmutex.KeyedLocker

	// slots bounds the preheats running at once. Waiters are served in order.
	slots *semaphore.Weighted

	// queued hands a new preheat to Run, which owns its goroutine.
	queued chan *preheatJob

	// recovered holds the preheats whose units outlived a restart of the
	// snapshotter, until Run watches them.
	recovered []*preheatJob

	// pollInterval is how often the unit of a running preheat is checked.
	pollInterval time.Duration

	// mu guards jobs.
	mu sync.Mutex

	// jobs holds them by image.
	jobs map[daemonID]*preheatJob
}

// newPreheatQueue returns an empty queue running maxConcurrent preheats at
// once.
func newPreheatQueue(maxConcurrent int) *preheatQueue {
	return &preheatQueue{
		locker:       kmutex.New(),
		slots:        semaphore.NewWeighted(int64(maxConcurrent)),
		queued:       make(chan *preheatJob),
		pollInterval: preheatPollInterval,
		jobs:         map[daemonID]*preheatJob{},
	}
}

// add stores a new job of the image and returns it.
func (q *preheatQueue) add(id daemonID, image *Image, credential *PreheatCredential) *preheatJob {
	job := &preheatJob{id: id, image: image, credential: credential}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.jobs[id] = job

	return job
}

// load returns the job of an image, nil when it has none.
func (q *preheatQueue) load(id daemonID) *preheatJob {
	q.mu.Lock()
	defer q.mu.Unlock()

	return q.jobs[id]
}

// remove forgets a job.
func (q *preheatQueue) remove(job *preheatJob) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.jobs[job.id] == job {
		delete(q.jobs, job.id)
	}
}

// Preheat queues the preheat of the image, read with the credential. A
// pending or running preheat of the same image is left as it is and the
// credential is not used; a finished one is replaced.
//
//	Preheat ─▶ pending ─▶ running ─▶ succeeded or failed, kept 24h
//	             │ a slot    │ nydus-preheat-<id>.service exits
func (f *fileSystem) Preheat(ctx context.Context, image *Image, credential *PreheatCredential) error {
	id, err := daemonIDFromChainID(image.ChainID)
	if err != nil {
		return err
	}

	// Expired preheats go first: each is removed under its own lock, and
	// holding two locks at once could deadlock with another request.
	cfg := f.cfg.Load()
	f.expirePreheats(ctx, cfg)
	if err := f.preheats.locker.Lock(ctx, string(id)); err != nil {
		return fmt.Errorf("lock preheat %s: %w", id.PreheatUnit(), err)
	}
	defer f.preheats.locker.Unlock(string(id))

	if f.preheats.load(id) != nil {
		return nil
	}

	return f.queuePreheat(ctx, cfg, id, image, credential)
}

// StatPreheat returns the preheat of the image of a chain ID.
func (f *fileSystem) StatPreheat(chainID string) (*Preheat, error) {
	id, err := daemonIDFromChainID(chainID)
	if err != nil {
		return nil, err
	}

	return f.statPreheat(f.cfg.Load(), id)
}

// queuePreheat replaces what is left of a finished preheat of the image with
// a new record and hands a new job to Run.
func (f *fileSystem) queuePreheat(ctx context.Context, cfg *config.Config, id daemonID, image *Image, credential *PreheatCredential) error {
	ref, err := registry.ParseReference(image.Ref)
	if err != nil {
		return err
	}

	job := f.preheats.add(id, image, credential)
	dir := cfg.PreheatRuntimeDir(string(id))
	if err := f.recordPreheat(dir, &preheatRecord{Image: ref.Name, CreatedAt: time.Now()}); err != nil {
		f.preheats.remove(job)
		return err
	}

	select {
	case f.preheats.queued <- job:
		return nil
	case <-ctx.Done():
		f.preheats.remove(job)
		if err := os.RemoveAll(dir); err != nil {
			log.G(ctx).WithError(err).WithField("path", dir).Warn("remove the directory of a preheat that was not queued")
		}

		return ctx.Err()
	}
}

// recordPreheat empties the directory of a preheat and writes its record.
func (f *fileSystem) recordPreheat(dir string, record *preheatRecord) error {
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove %s: %w", dir, err)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	return f.writePreheatFile(filepath.Join(dir, preheatRecordFile), record)
}

// statPreheat returns the preheat of an image from its directory.
//
//	preheat.json    image, created_at             written by the snapshotter
//	state.json      progress, then the result     written by nydus preheat
//	job             pending or running            in memory
func (f *fileSystem) statPreheat(cfg *config.Config, id daemonID) (*Preheat, error) {
	dir := cfg.PreheatRuntimeDir(string(id))
	notFound := fmt.Errorf("preheat %s: %w", id.ChainID(), errdefs.ErrNotFound)
	var record preheatRecord
	if err := f.readPreheatFile(filepath.Join(dir, preheatRecordFile), &record); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, notFound
		}

		return nil, err
	}

	// A process that has not written yet has no progress to show.
	var progress preheatProgress
	if err := f.readPreheatFile(filepath.Join(dir, preheatStateFile), &progress); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	preheat := &Preheat{
		State:     PreheatStatePending,
		Blobs:     progress.Blobs,
		CreatedAt: record.CreatedAt,
		UpdatedAt: record.CreatedAt,
	}
	if !progress.UpdatedAt.IsZero() {
		preheat.UpdatedAt = progress.UpdatedAt
	}

	// A result shows once the job is gone: by then the process has exited,
	// its config is removed and the next preheat of the image starts anew.
	job := f.preheats.load(id)
	switch {
	case job != nil:
		if job.running.Load() {
			preheat.State = PreheatStateRunning
		}
	case !progress.finished() || progress.expired():
		// The preheat was pending when the snapshotter stopped, or has
		// expired.
		return nil, notFound
	default:
		preheat.State, preheat.Description = progress.State, progress.Description
	}

	return preheat, nil
}

// expirePreheats removes the directories of the preheats that finished
// longer than preheatRetention ago, each under its lock, so a preheat of the
// same image queued meanwhile keeps its new directory.
func (f *fileSystem) expirePreheats(ctx context.Context, cfg *config.Config) {
	entries, err := os.ReadDir(cfg.PreheatRuntimesDir())
	if err != nil {
		log.G(ctx).WithError(err).Warn("read preheat directories")
		return
	}

	for _, entry := range entries {
		id, ok := daemonIDFromHex(entry.Name())
		if !ok || f.preheats.locker.Lock(ctx, string(id)) != nil {
			continue
		}

		dir := cfg.PreheatRuntimeDir(string(id))
		var progress preheatProgress
		if err := f.readPreheatFile(filepath.Join(dir, preheatStateFile), &progress); err == nil && f.preheats.load(id) == nil && progress.expired() {
			if err := os.RemoveAll(dir); err != nil {
				log.G(ctx).WithError(err).WithField("path", dir).Warn("remove expired preheat")
			}
		}
		f.preheats.locker.Unlock(string(id))
	}
}

// recoverPreheats sorts out what a previous run of the snapshotter left in
// the preheat directories and returns the jobs of the units still running.
// It runs before the snapshotter serves, so no request sees half of it.
//
//	unit runs                      ─▶ job, watched until the unit exits
//	no unit, state.json finished   ─▶ kept until it expires
//	no unit, state.json running    ─▶ failed, the process left no result
//	no unit, no state.json         ─▶ removed, it was pending
func (f *fileSystem) recoverPreheats(ctx context.Context) []*preheatJob {
	cfg := f.cfg.Load()
	entries, err := os.ReadDir(cfg.PreheatRuntimesDir())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.G(ctx).WithError(err).Warn("read preheat directories")
	}

	if len(entries) == 0 {
		return nil
	}

	units, err := f.systemd.ListUnits(ctx, cfg.Cgroup.Slice, preheatUnitPattern)
	if err != nil {
		// Nothing is removed while the units are unknown.
		log.G(ctx).WithError(err).Warn("list preheat units, leaving the preheats of the previous run alone")
		return nil
	}

	var jobs []*preheatJob
	for _, entry := range entries {
		id, ok := daemonIDFromHex(entry.Name())
		if !ok {
			continue
		}

		if state, loaded := units[id.PreheatUnit()]; loaded && !state.Stopped() {
			job := f.preheats.add(id, nil, nil)
			job.running.Store(true)
			jobs = append(jobs, job)
			continue
		}

		dir := cfg.PreheatRuntimeDir(string(id))
		var progress preheatProgress
		if err := f.readPreheatFile(filepath.Join(dir, preheatStateFile), &progress); err != nil {
			if err := os.RemoveAll(dir); err != nil {
				log.G(ctx).WithError(err).WithField("path", dir).Warn("remove a preheat that never ran")
			}

			continue
		}

		// A result needs no more than its config removed, which the previous
		// run may not have lived to do.
		if progress.finished() {
			f.removePreheatConfig(ctx, dir)
			continue
		}

		f.finishPreheat(ctx, cfg, id, nil)
	}

	f.expirePreheats(ctx, cfg)

	return jobs
}

// runPreheats owns the goroutines of the preheats until ctx is done: the
// recovered ones, then every queued one. The units keep running when the
// snapshotter stops.
func (f *fileSystem) runPreheats(ctx context.Context) {
	var wg sync.WaitGroup
	defer wg.Wait()
	for _, job := range f.preheats.recovered {
		wg.Go(func() { f.runPreheat(ctx, job) })
	}

	for {
		select {
		case job := <-f.preheats.queued:
			wg.Go(func() { f.runPreheat(ctx, job) })
		case <-ctx.Done():
			return
		}
	}
}

// runPreheat takes a preheat from pending to its result: it waits for a
// slot, starts the unit and waits for it to exit. A preheat still running
// when the snapshotter stops keeps running; the next run recovers it.
func (f *fileSystem) runPreheat(ctx context.Context, job *preheatJob) {
	defer f.preheats.remove(job)
	if err := f.preheats.slots.Acquire(ctx, 1); err != nil {
		return
	}
	defer f.preheats.slots.Release(1)

	cfg := f.cfg.Load()
	unit := job.id.PreheatUnit()
	if job.image != nil {
		if err := f.startPreheat(ctx, cfg, job); err != nil {
			if ctx.Err() == nil {
				f.finishPreheat(ctx, cfg, job.id, err)
			}

			return
		}
	}

	metrics.RunningPreheats.Inc()
	defer metrics.RunningPreheats.Dec()
	log.G(ctx).WithField("unit", unit).Info("preheat is running")

	// The poll fails only once the snapshotter stops. A failed check counts
	// as still running: the manager reconnects to systemd.
	if err := wait.PollUntilContextCancel(ctx, f.preheats.pollInterval, false, func(ctx context.Context) (bool, error) {
		state, err := f.systemd.ActiveState(ctx, unit)
		return err == nil && state.Stopped(), nil
	}); err != nil {
		return
	}

	f.finishPreheat(ctx, cfg, job.id, nil)
}

// startPreheat seeds the cache, renders the config with the credential and
// starts the unit of the preheat.
func (f *fileSystem) startPreheat(ctx context.Context, cfg *config.Config, job *preheatJob) error {
	ref, err := registry.ParseReference(job.image.Ref)
	if err != nil {
		return err
	}

	layer := NewBootstrapLayer(job.image.BootstrapDir)
	bootstrap, err := layer.bootstrap()
	if err != nil {
		return err
	}

	blobs, err := layer.Blobs()
	if err != nil {
		return err
	}

	if err := layer.seedCache(cfg.CacheDir(), blobs); err != nil {
		return err
	}

	endpoint, err := f.hosts.Resolve(ref.Host)
	if err != nil {
		return err
	}

	// The credential lives in the rendered config from here on.
	opts := job.credential.renderOptions()
	opts.prefetchScope = cfg.Nydusd.Config.Prefetch.Scope
	job.credential = nil
	dir := cfg.PreheatRuntimeDir(string(job.id))
	if err := f.writeConfig(cfg, ref, endpoint, dir, filepath.Join(dir, preheatConfigFile), opts); err != nil {
		return err
	}

	unit, err := f.preheatUnit(cfg, job.id, ref, bootstrap)
	if err != nil {
		return err
	}

	// The unit is Type=exec: its start job ends once the binary runs. One
	// that already runs is the preheat of a previous run of the snapshotter
	// that was not recovered when it started, and is watched as it is.
	if err := f.systemd.StartTransientUnit(ctx, unit); err != nil && !errdefs.IsAlreadyExists(err) {
		return fmt.Errorf("%w, see journalctl -u %s and %s", err, unit.Name, cfg.PreheatLogDir())
	}
	job.running.Store(true)

	return nil
}

// preheatUnit returns the transient unit running a preheat. It runs in the
// daemons' slice with the limits of one daemon. The console log is off, as a
// daemon's: it duplicates the --log-dir files.
func (f *fileSystem) preheatUnit(cfg *config.Config, id daemonID, ref *registry.Reference, bootstrap string) (*systemd.Unit, error) {
	binary, err := filepath.EvalSymlinks(cfg.Nydusd.Binary)
	if err != nil {
		return nil, fmt.Errorf("resolve nydus binary: %w", err)
	}

	dir := cfg.PreheatRuntimeDir(string(id))
	return &systemd.Unit{
		Name:        id.PreheatUnit(),
		Description: "nydus preheat of " + ref.Name,
		Slice:       cfg.Cgroup.Slice,
		ExecStart: []string{
			binary, "preheat",
			"--bootstrap", bootstrap,
			"--config", filepath.Join(dir, preheatConfigFile),
			"--state-file", filepath.Join(dir, preheatStateFile),
			"--log-dir", cfg.PreheatLogDir(),
			"--log-level", cfg.Nydusd.LogLevel,
			"--log-max-files", strconv.Itoa(cfg.Nydusd.LogMaxFiles),
		},
		Environment:      []string{"NYDUS_PREHEAT_CONSOLE=false"},
		TimeoutStop:      time.Duration(cfg.Nydusd.MountTimeout),
		LimitNOFILE:      limitNOFILE,
		SyslogIdentifier: "nydus-preheat",
		LogExtraFields:   []string{"NYDUS_CHAIN_ID=" + id.ChainID()},
		Resources:        f.daemonResources(cfg),
	}, nil
}

// finishPreheat closes a preheat whose process is gone: it removes the
// config and records a failure when the process left no result.
func (f *fileSystem) finishPreheat(ctx context.Context, cfg *config.Config, id daemonID, startErr error) {
	logger := log.G(ctx).WithField("unit", id.PreheatUnit())
	dir := cfg.PreheatRuntimeDir(string(id))
	f.removePreheatConfig(ctx, dir)
	path := filepath.Join(dir, preheatStateFile)
	var progress preheatProgress
	if err := f.readPreheatFile(path, &progress); err != nil && !errors.Is(err, os.ErrNotExist) {
		logger.WithError(err).Warn("read the state of a finished preheat")
	}

	if !progress.finished() {
		progress.State, progress.UpdatedAt = PreheatStateFailed, time.Now()
		progress.Description = fmt.Sprintf("preheat process exited without a result, see journalctl -u %s and %s", id.PreheatUnit(), cfg.PreheatLogDir())
		if startErr != nil {
			progress.Description = "start preheat: " + startErr.Error()
		}

		if err := f.writePreheatFile(path, &progress); err != nil {
			logger.WithError(err).Error("record the failure of a preheat")
		}
	}

	if progress.State == PreheatStateSucceeded {
		metrics.PreheatsTotal.WithLabelValues(metrics.ResultSuccess).Inc()
		logger.Info("preheat succeeded")
		return
	}

	metrics.PreheatsTotal.WithLabelValues(metrics.ResultFailure).Inc()
	logger.WithField("description", progress.Description).Warn("preheat failed")
}

// removePreheatConfig removes the rendered config of a preheat, which holds
// its credential.
func (f *fileSystem) removePreheatConfig(ctx context.Context, dir string) {
	path := filepath.Join(dir, preheatConfigFile)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.G(ctx).WithError(err).WithField("path", path).Error("remove the config of a finished preheat, which holds its credential")
	}
}

// readPreheatFile decodes a JSON file of a preheat's directory.
func (f *fileSystem) readPreheatFile(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}

	return nil
}

// writePreheatFile writes a JSON file of a preheat's directory, replacing
// it atomically.
func (f *fileSystem) writePreheatFile(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}

	return continuity.AtomicWriteFile(path, data, 0o600)
}
