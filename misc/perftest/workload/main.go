// workload runs a cold-cache parallel-read benchmark over a mounted Nydus
// filesystem and writes a JSON summary describing throughput and latency.
//
// It is the data-plane half of the nydus perftest image; the orchestrator
// (entrypoint.sh) is responsible for mounting nydusd before invoking this
// program. We deliberately use stdlib only so the binary can be built
// statically with `CGO_ENABLED=0 go build`.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type latencyStats struct {
	Mean float64 `json:"mean"`
	P50  float64 `json:"p50"`
	P90  float64 `json:"p90"`
	P95  float64 `json:"p95"`
	P99  float64 `json:"p99"`
}

type summary struct {
	FilesSeen      int          `json:"files_seen"`
	FilesRead      int          `json:"files_read"`
	FilesSkipped   int          `json:"files_skipped"`
	FilesErrored   int          `json:"files_errored"`
	BytesRead      int64        `json:"bytes_read"`
	WallClockSec   float64      `json:"wall_clock_sec"`
	ThroughputMBps float64      `json:"throughput_mbps"`
	Parallelism    int          `json:"parallelism"`
	ChunkSize      int          `json:"chunk_size"`
	LatencyMs      latencyStats `json:"latency_ms"`
	ErrorSamples   []string     `json:"error_samples"`
}

func main() {
	root := flag.String("root", "", "directory to walk and read")
	parallelism := flag.Int("parallelism", 16, "concurrent file readers")
	chunkSize := flag.Int("chunk-size", 1<<20, "bytes per read() call")
	maxFiles := flag.Int("max-files", 0, "cap files read; 0 = no cap")
	output := flag.String("output", "", "summary JSON output path")
	flag.Parse()
	if *root == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "usage: workload --root DIR --output PATH [--parallelism N] [--chunk-size N] [--max-files N]")
		os.Exit(2)
	}
	if *parallelism < 1 {
		*parallelism = 1
	}

	files, skipped, err := collectFiles(*root, *maxFiles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[workload] walk error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[workload] %d files to read (%d non-regular skipped)\n", len(files), skipped)

	var (
		bytesRead    int64
		errored      int64
		latencies    = make([]float64, 0, len(files))
		latMu        sync.Mutex
		errSamples   []string
		errSamplesMu sync.Mutex
		work         = make(chan string, len(files))
		wg           sync.WaitGroup
	)
	for _, p := range files {
		work <- p
	}
	close(work)

	tStart := time.Now()
	for w := 0; w < *parallelism; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localBuf := make([]byte, *chunkSize)
			for path := range work {
				n, lat, rerr := readOne(path, localBuf)
				if rerr != nil {
					atomic.AddInt64(&errored, 1)
					errSamplesMu.Lock()
					if len(errSamples) < 10 {
						errSamples = append(errSamples, fmt.Sprintf("%s: %v", path, rerr))
					}
					errSamplesMu.Unlock()
					continue
				}
				atomic.AddInt64(&bytesRead, n)
				latMu.Lock()
				latencies = append(latencies, lat.Seconds())
				latMu.Unlock()
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(tStart).Seconds()

	s := summary{
		FilesSeen:    len(files) + skipped,
		FilesRead:    len(files) - int(errored),
		FilesSkipped: skipped,
		FilesErrored: int(errored),
		BytesRead:    bytesRead,
		WallClockSec: round(elapsed, 6),
		Parallelism:  *parallelism,
		ChunkSize:    *chunkSize,
		ErrorSamples: errSamples,
	}
	if elapsed > 0 {
		s.ThroughputMBps = round(float64(bytesRead)/1_000_000.0/elapsed, 3)
	}
	s.LatencyMs = computeLatency(latencies)

	out, err := os.Create(*output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[workload] cannot write %s: %v\n", *output, err)
		os.Exit(1)
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&s); err != nil {
		fmt.Fprintf(os.Stderr, "[workload] encode error: %v\n", err)
		os.Exit(1)
	}
	out.Close()

	fmt.Fprintf(os.Stderr,
		"[workload] done: %d files, %d bytes, %.2f MB/s, p95=%.2fms\n",
		s.FilesRead, s.BytesRead, s.ThroughputMBps, s.LatencyMs.P95)

	if errored > 0 && s.FilesRead == 0 {
		os.Exit(1)
	}
}

func collectFiles(root string, maxFiles int) ([]string, int, error) {
	var files []string
	skipped := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			skipped++
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			skipped++
			return nil
		}
		files = append(files, path)
		if maxFiles > 0 && len(files) >= maxFiles {
			return filepath.SkipAll
		}
		return nil
	})
	return files, skipped, err
}

func readOne(path string, buf []byte) (int64, time.Duration, error) {
	t0 := time.Now()
	f, err := os.Open(path)
	if err != nil {
		return 0, time.Since(t0), err
	}
	defer f.Close()
	var total int64
	for {
		n, rerr := f.Read(buf)
		total += int64(n)
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return total, time.Since(t0), rerr
		}
	}
	return total, time.Since(t0), nil
}

func computeLatency(secs []float64) latencyStats {
	if len(secs) == 0 {
		return latencyStats{}
	}
	sorted := make([]float64, len(secs))
	copy(sorted, secs)
	sort.Float64s(sorted)
	var sum float64
	for _, v := range secs {
		sum += v
	}
	pick := func(p float64) float64 {
		idx := int(p * float64(len(sorted)-1))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sorted) {
			idx = len(sorted) - 1
		}
		return sorted[idx] * 1000.0
	}
	return latencyStats{
		Mean: round(sum/float64(len(secs))*1000.0, 3),
		P50:  round(pick(0.50), 3),
		P90:  round(pick(0.90), 3),
		P95:  round(pick(0.95), 3),
		P99:  round(pick(0.99), 3),
	}
}

func round(v float64, places int) float64 {
	scale := 1.0
	for i := 0; i < places; i++ {
		scale *= 10
	}
	if v >= 0 {
		return float64(int64(v*scale+0.5)) / scale
	}
	return float64(int64(v*scale-0.5)) / scale
}
