//go:build manual

package bench

var warmMetrics = []struct {
	key, unit string
	get       func(r *fioResult) float64
}{
	{"seq_read_128k", "MiB/s", bandwidth},
	{"rand_read_128k", "MiB/s", bandwidth},
	{"seq_read_4k", "MiB/s", bandwidth},
	{"rand_read_4k", "IOPS", iops},
	{"rand_read_4k", "us", latency},
	{"seq_read_4t_128k", "MiB/s", bandwidth},
	{"rand_read_4t_128k", "MiB/s", bandwidth},
	{"seq_read_4t_4k", "MiB/s", bandwidth},
	{"rand_read_4t_4k", "MiB/s", bandwidth},
	{"stat", "IOPS", iops},
	{"stat", "us", latency},
	{"readdir", "IOPS", iops},
	{"readdir", "us", latency},
	{"listxattr", "IOPS", iops},
	{"listxattr", "us", latency},
	{"getxattr", "IOPS", iops},
	{"getxattr", "us", latency},
	{"readdir_stat", "IOPS", iops},
	{"readdir_stat", "us", latency},
}

func bandwidth(r *fioResult) float64 { return r.readBW }

func iops(r *fioResult) float64 { return r.readIOPS }

func latency(r *fioResult) float64 { return r.readLat }

func (r *modeResult) metrics() map[string]float64 {
	m := map[string]float64{
		"mount-sec":           r.mountSec,
		"cold-walk-sec":       r.coldWalkSec,
		"cold-walk-entries/s": float64(r.coldWalkEntries) / r.coldWalkSec,
		"cold-xattr-walk-sec": r.coldXattrWalkSec,
		"negative-lookups/s":  r.negativeLookupOps,
		"big-dir-lookups/s":   r.bigDirLookupOps,
		"first-read-sec":      r.firstReadSec,
		"cold-seq-read-MiB/s": r.coldSeqMiBps,
		"cold-seq-cache-MiB":  r.coldSeqCachedMiB,
		"cold-rand-read-IOPS": r.coldRandIOPS,
		"cold-rand-read-us":   r.coldRandLatUs,
	}

	if r.fetchedMiB >= 0 {
		m["backend-read-MiB"] = r.fetchedMiB
	}

	if r.warm != nil {
		for _, w := range warmMetrics {
			if res := r.warm[w.key]; res != nil {
				m[w.key+"-"+w.unit] = w.get(res)
			}
		}
	}

	return m
}
