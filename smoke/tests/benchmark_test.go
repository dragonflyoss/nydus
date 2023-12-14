// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/dragonflyoss/image-service/smoke/tests/tool"
	"github.com/dragonflyoss/image-service/smoke/tests/tool/test"
	"github.com/google/uuid"
)

// Environment Requirement: Containerd, nerdctl >= 0.22, nydus-snapshotter, nydusd, nydus-image and nydusify.
// Prepare: setup nydus for containerd, reference: https://github.com/dragonflyoss/nydus/blob/master/docs/containerd-env-setup.md.
// TestBenchmark will dump json file(benchmark.json) which includes container e2e time, image size, read-amount and read-cout.
//	Example:
//	{
//		e2e_time: 2747131
//		image_size: 2107412
//		read_amount: 121345
//		read_count: 121
//	}

type BenchmarkTestSuite struct {
	t                 *testing.T
	testImage         string
	testContainerName string
	snapshotter       string
	metric            tool.ContainerMetrics
}

func (b *BenchmarkTestSuite) TestBenchmark(t *testing.T) {
	ctx := tool.DefaultContext(b.t)
	b.snapshotter = os.Getenv("SNAPSHOTTER")
	if b.snapshotter == "" {
		b.snapshotter = "nydus"
	}

	// choose test mode
	mode := os.Getenv("BENCHMARK_MODE")
	if mode == "" {
		mode = "fs-version-6"
	}
	switch mode {
	case "oci":
	case "fs-version-5":
		ctx.Build.FSVersion = "5"
	case "fs-version-6":
		ctx.Build.FSVersion = "6"
	case "zran":
		ctx.Build.OCIRef = true
	default:
		b.t.Fatalf("Benchmark don't support %s mode", mode)
	}

	// prepare benchmark image
	image := os.Getenv("BENCHMARK_TEST_IMAGE")
	if image == "" {
		image = "wordpress:6.1.1"
	} else {
		if !tool.SupportContainerImage(tool.ImageRepo(b.t, image)) {
			b.t.Fatalf("Benchmark don't support image " + image)
		}
	}
	targetImageSize, conversionElapsed := b.prepareImage(b.t, ctx, image)

	// run contaienr
	b.testContainerName = uuid.NewString()
	containerMetic := tool.RunContainer(b.t, b.testImage, b.snapshotter, b.testContainerName)
	b.metric = tool.ContainerMetrics{
		E2ETime:           containerMetic.E2ETime,
		ConversionElapsed: time.Duration(conversionElapsed),
		ReadCount:         containerMetic.ReadCount,
		ReadAmountTotal:   containerMetic.ReadAmountTotal,
		ImageSize:         targetImageSize,
	}

	// save metirc
	b.dumpMetric()
	t.Logf(fmt.Sprintf("Metric: E2ETime %d ConversionElapsed %s ReadCount %d ReadAmount %d ImageSize %d", b.metric.E2ETime, b.metric.ConversionElapsed, b.metric.ReadCount, b.metric.ReadAmountTotal, b.metric.ImageSize))
}

func (b *BenchmarkTestSuite) prepareImage(t *testing.T, ctx *tool.Context, image string) (int64, int64) {
	if b.testImage != "" {
		return 0, 0
	}

	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)
	source := tool.PrepareImage(t, image)

	// Prepare options
	target := fmt.Sprintf("%s-nydus-%s", source, uuid.NewString())
	fsVersion := fmt.Sprintf("--fs-version %s", ctx.Build.FSVersion)
	logLevel := "--log-level warn"
	if ctx.Binary.NydusifyOnlySupportV5 {
		fsVersion = ""
		logLevel = ""
	}
	enableOCIRef := ""
	if ctx.Build.OCIRef {
		enableOCIRef = "--oci-ref"
	}

	convertMetricFile := fmt.Sprintf("./%s.json", uuid.NewString())
	// Convert image
	convertCmd := fmt.Sprintf("%s %s convert --source %s --target %s --nydus-image %s --work-dir %s %s %s --output-json %s",
		ctx.Binary.Nydusify, logLevel, source, target, ctx.Binary.Builder, ctx.Env.WorkDir, fsVersion, enableOCIRef, convertMetricFile)
	tool.RunWithoutOutput(t, convertCmd)
	defer os.Remove(convertMetricFile)

	metricData, err := os.ReadFile(convertMetricFile)
	if err != nil {
		t.Fatalf("can't read convert metric file")
		return 0, 0
	}
	var convertMetirc map[string]int64
	err = json.Unmarshal(metricData, &convertMetirc)
	if err != nil {
		t.Fatalf("can't parsing convert metric file")
		return 0, 0
	}
	if b.snapshotter == "nydus" {
		b.testImage = target
		return convertMetirc["TargetImageSize"], convertMetirc["ConversionElapsed"]
	}
	b.testImage = source
	return convertMetirc["SourceImageSize"], 0
}

func (b *BenchmarkTestSuite) dumpMetric() {
	metricFileName := os.Getenv("BENCHMARK_METRIC_FILE")
	if metricFileName == "" {
		metricFileName = "benchmark.json"
	}
	file, err := os.Create(metricFileName)
	if err != nil {
		b.t.Fatalf("create benchmark metric file")
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(b.metric); err != nil {
		b.t.Fatalf("write benchmark metric file")
	}
}

func TestBenchmark(t *testing.T) {
	if os.Getenv("BENCHMARK_TEST") == "" {
		t.Skip("skipping benchmark test")
	}
	test.Run(t, &BenchmarkTestSuite{t: t})
}
