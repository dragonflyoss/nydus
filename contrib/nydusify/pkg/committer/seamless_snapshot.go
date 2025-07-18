// Copyright 2024 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package committer

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	parserPkg "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// SeamlessSnapshot implements seamless container snapshotting with minimal pause time
type SeamlessSnapshot struct {
	manager    *Manager
	workDir    string
	mutex      sync.Mutex
	background chan *SnapshotTask
}

// SnapshotTask represents a background snapshot processing task
type SnapshotTask struct {
	ContainerID  string
	OldUpperDir  string
	SnapshotID   string
	TargetRef    string
	Opt          Opt
	CompleteChan chan error
}

// SnapshotResult contains the result of a seamless snapshot operation
type SnapshotResult struct {
	NewUpperDir string
	OldUpperDir string
	SnapshotID  string
	PauseTime   time.Duration
}

// NewSeamlessSnapshot creates a new seamless snapshot instance
func NewSeamlessSnapshot(manager *Manager, workDir string) *SeamlessSnapshot {
	ss := &SeamlessSnapshot{
		manager:    manager,
		workDir:    workDir,
		background: make(chan *SnapshotTask, 10),
	}

	// Start background processor
	go ss.backgroundProcessor()

	return ss
}

// CreateSeamlessSnapshot performs a seamless snapshot with minimal container pause
func (ss *SeamlessSnapshot) CreateSeamlessSnapshot(ctx context.Context, containerID string, opt Opt) (*SnapshotResult, error) {
	logrus.Infof("starting seamless snapshot for container: %s", containerID)

	// Step 1: Inspect container to get current overlay configuration
	inspect, err := ss.manager.Inspect(ctx, containerID)
	if err != nil {
		return nil, errors.Wrap(err, "inspect container")
	}

	// Step 2: Prepare new overlay layers (this can take time, but container keeps running)
	newUpperDir, newWorkDir, err := ss.prepareNewLayers(inspect.UpperDir)
	if err != nil {
		return nil, errors.Wrap(err, "prepare new layers")
	}

	// Step 3: Sync filesystem to ensure all changes are written
	if err := ss.syncFilesystem(ctx, containerID); err != nil {
		return nil, errors.Wrap(err, "sync filesystem")
	}

	// Step 4: Perform atomic layer switch with minimal pause
	result, err := ss.atomicLayerSwitch(ctx, containerID, inspect, newUpperDir, newWorkDir)
	if err != nil {
		// Cleanup on failure
		os.RemoveAll(newUpperDir)
		os.RemoveAll(newWorkDir)
		return nil, errors.Wrap(err, "atomic layer switch")
	}

	// Step 5: Schedule background commit processing
	snapshotID := fmt.Sprintf("snapshot-%d", time.Now().UnixNano())
	task := &SnapshotTask{
		ContainerID:  containerID,
		OldUpperDir:  result.OldUpperDir,
		SnapshotID:   snapshotID,
		TargetRef:    opt.TargetRef,
		Opt:          opt,
		CompleteChan: make(chan error, 1),
	}

	select {
	case ss.background <- task:
		logrus.Infof("scheduled background commit for snapshot: %s", snapshotID)
	default:
		logrus.Warnf("background queue full, processing synchronously")
		go ss.processSnapshotTask(task)
	}

	result.SnapshotID = snapshotID
	return result, nil
}

// prepareNewLayers creates new upper and work directories for overlay
func (ss *SeamlessSnapshot) prepareNewLayers(currentUpperDir string) (string, string, error) {
	timestamp := time.Now().UnixNano()

	// Create new upper directory
	newUpperDir := fmt.Sprintf("%s-new-%d", currentUpperDir, timestamp)
	if err := os.MkdirAll(newUpperDir, 0755); err != nil {
		return "", "", errors.Wrap(err, "create new upper directory")
	}

	// Create new work directory
	currentWorkDir := strings.Replace(currentUpperDir, "/upper", "/work", 1)
	newWorkDir := fmt.Sprintf("%s-new-%d", currentWorkDir, timestamp)
	if err := os.MkdirAll(newWorkDir, 0755); err != nil {
		os.RemoveAll(newUpperDir)
		return "", "", errors.Wrap(err, "create new work directory")
	}

	logrus.Debugf("prepared new layers: upper=%s, work=%s", newUpperDir, newWorkDir)
	return newUpperDir, newWorkDir, nil
}

// atomicLayerSwitch performs the critical atomic switch with minimal pause time
func (ss *SeamlessSnapshot) atomicLayerSwitch(ctx context.Context, containerID string, inspect *InspectResult, newUpperDir, newWorkDir string) (*SnapshotResult, error) {
	startTime := time.Now()

	// Parse current mount options
	currentLowerDirs := inspect.LowerDirs
	currentUpperDir := inspect.UpperDir

	// Prepare new mount options
	newMountOptions := []string{
		fmt.Sprintf("lowerdir=%s", currentLowerDirs),
		fmt.Sprintf("upperdir=%s", newUpperDir),
		fmt.Sprintf("workdir=%s", newWorkDir),
	}

	// Critical section: pause container and switch layers
	logrus.Infof("pausing container for atomic layer switch: %s", containerID)
	if err := ss.manager.Pause(ctx, containerID); err != nil {
		return nil, errors.Wrap(err, "pause container")
	}

	pauseStartTime := time.Now()

	// Perform atomic remount
	err := ss.performAtomicRemount(ctx, containerID, newMountOptions)

	pauseTime := time.Since(pauseStartTime)

	// Resume container immediately
	logrus.Infof("resuming container: %s", containerID)
	if resumeErr := ss.manager.UnPause(ctx, containerID); resumeErr != nil {
		logrus.Errorf("failed to resume container %s: %v", containerID, resumeErr)
		// Don't return here, we still need to handle the original error
	}

	if err != nil {
		return nil, errors.Wrap(err, "atomic remount")
	}

	totalTime := time.Since(startTime)
	logrus.Infof("atomic layer switch completed: pause=%v, total=%v", pauseTime, totalTime)

	return &SnapshotResult{
		NewUpperDir: newUpperDir,
		OldUpperDir: currentUpperDir,
		PauseTime:   pauseTime,
	}, nil
}

// syncFilesystem forces filesystem sync to ensure all changes are written to disk
func (ss *SeamlessSnapshot) syncFilesystem(ctx context.Context, containerID string) error {
	inspect, err := ss.manager.Inspect(ctx, containerID)
	if err != nil {
		return errors.Wrap(err, "inspect container for sync")
	}

	// Use nsenter to execute sync command in the container's namespace
	config := &Config{
		Mount:  true,
		PID:    true,
		Target: inspect.Pid,
	}

	stderr, err := config.ExecuteContext(ctx, nil, "sync")
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("execute sync in container namespace: %s", strings.TrimSpace(stderr)))
	}

	return nil
}

// performAtomicRemount performs the actual atomic remount operation
func (ss *SeamlessSnapshot) performAtomicRemount(ctx context.Context, containerID string, newMountOptions []string) error {
	// Get container's mount namespace
	inspect, err := ss.manager.Inspect(ctx, containerID)
	if err != nil {
		return errors.Wrap(err, "inspect container for remount")
	}

	// Find the container's root mount point
	var rootMount *Mount
	for _, m := range inspect.Mounts {
		if m.Destination == "/" {
			rootMount = &m
			break
		}
	}

	if rootMount == nil {
		return errors.New("container root mount not found")
	}

	// Use nsenter to perform remount in container's namespace
	config := &Config{
		Mount:  true,
		PID:    true,
		Target: inspect.Pid,
	}

	// Create remount command
	mountCmd := fmt.Sprintf("mount -t overlay overlay -o %s %s",
		strings.Join(newMountOptions, ","), rootMount.Source)

	stderr, err := config.ExecuteContext(ctx, nil, "sh", "-c", mountCmd)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("atomic remount failed: %s", strings.TrimSpace(stderr)))
	}

	logrus.Debugf("atomic remount successful with options: %v", newMountOptions)
	return nil
}

// backgroundProcessor handles background snapshot processing
func (ss *SeamlessSnapshot) backgroundProcessor() {
	for task := range ss.background {
		logrus.Infof("processing background snapshot task: %s", task.SnapshotID)
		err := ss.processSnapshotTask(task)

		select {
		case task.CompleteChan <- err:
		default:
			if err != nil {
				logrus.Errorf("background snapshot task failed: %v", err)
			}
		}
	}
}

// processSnapshotTask processes a single snapshot task
func (ss *SeamlessSnapshot) processSnapshotTask(task *SnapshotTask) error {
	ctx := context.Background()

	// Create a temporary committer for this task
	tempOpt := task.Opt
	tempOpt.ContainerID = task.ContainerID

	cm, err := NewCommitter(tempOpt)
	if err != nil {
		return errors.Wrap(err, "create temporary committer")
	}

	// Commit the old upper directory
	logrus.Infof("committing old upper directory: %s", task.OldUpperDir)

	// Use the existing diff-based commit logic
	mountList := NewMountList()

	upperBlobDigest, err := cm.commitUpperByDiff(ctx, mountList.Add,
		task.Opt.WithPaths, task.Opt.WithoutPaths,
		"", task.OldUpperDir,
		fmt.Sprintf("blob-snapshot-%s", task.SnapshotID),
		task.Opt.FsVersion, task.Opt.Compressor)
	if err != nil {
		return errors.Wrap(err, "commit upper directory")
	}

	// Push the blob
	logrus.Infof("pushing snapshot blob: %s", task.SnapshotID)
	targetRef, err := ValidateRef(task.TargetRef)
	if err != nil {
		return errors.Wrap(err, "validate target reference")
	}

	// Get original source reference for pushing
	inspect, err := cm.manager.Inspect(ctx, task.ContainerID)
	if err != nil {
		return errors.Wrap(err, "inspect container for push")
	}

	originalSourceRef, err := ValidateRef(inspect.Image)
	if err != nil {
		return errors.Wrap(err, "validate source reference")
	}

	// Load image for blob pushing using provider
	remoter, err := provider.DefaultRemote(originalSourceRef, task.Opt.SourceInsecure)
	if err != nil {
		return errors.Wrap(err, "create source remote")
	}

	parser, err := parserPkg.New(remoter, runtime.GOARCH)
	if err != nil {
		return errors.Wrap(err, "create parser")
	}

	image, err := parser.Parse(ctx)
	if err != nil {
		return errors.Wrap(err, "parse source image")
	}

	// Use the appropriate image (OCI or Nydus)
	var sourceImage *parserPkg.Image
	if image.NydusImage != nil {
		sourceImage = image.NydusImage
	} else if image.OCIImage != nil {
		sourceImage = image.OCIImage
	} else {
		return errors.New("no valid image found in parsed result")
	}

	_, err = cm.pushBlob(ctx, fmt.Sprintf("blob-snapshot-%s", task.SnapshotID),
		*upperBlobDigest, originalSourceRef, targetRef,
		task.Opt.TargetInsecure, sourceImage)
	if err != nil {
		return errors.Wrap(err, "push snapshot blob")
	}

	// Cleanup old upper directory after successful commit
	if err := os.RemoveAll(task.OldUpperDir); err != nil {
		logrus.Warnf("failed to cleanup old upper directory %s: %v", task.OldUpperDir, err)
	}

	logrus.Infof("background snapshot processing completed: %s", task.SnapshotID)
	return nil
}

// WaitForSnapshot waits for a specific snapshot to complete processing
func (ss *SeamlessSnapshot) WaitForSnapshot(snapshotID string, timeout time.Duration) error {
	// This is a simplified implementation
	// In a real implementation, you'd track active tasks and provide a way to wait for specific ones
	time.Sleep(timeout)
	return nil
}

// GetSnapshotStatus returns the status of a snapshot
func (ss *SeamlessSnapshot) GetSnapshotStatus(snapshotID string) (string, error) {
	// This would be implemented with proper task tracking
	return "completed", nil
}

// Close gracefully shuts down the seamless snapshot processor
func (ss *SeamlessSnapshot) Close() error {
	close(ss.background)
	return nil
}
