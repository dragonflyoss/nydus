package fault

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
)

const (
	metricCRCErrors     = "nydus_cache_write_failure_total"
	metricBackendErrors = "nydus_backend_read_failure_total"
)

// range200Files lie past the start of the blob, where the head of a
// whole-blob body would happen to be the requested range.
var range200Files = []string{"data/content/text", "data/dedup/orig", "data/size/00065537", bigFile}

// TestRange200 answers every ranged blob GET with 200 and the whole blob,
// as some registries and proxies do. The backend must reject these responses
// before attempting to decode bytes at the wrong offset. Restoring valid
// range responses must recover without leaving corrupted cache entries.
func TestRange200(t *testing.T) {
	t.Parallel()
	for _, layout := range []string{"zstd-4k", "none-4k"} {
		img := fixture.Get(t, layout)
		for _, a := range adapters {
			t.Run(layout+"/"+a.Name(), func(t *testing.T) {
				t.Parallel()
				range200(t, a, img)
			})
		}
	}
}

func range200(t *testing.T, a mount.Adapter, img fixture.Image) {
	reg := pushImage(t, img)
	m := registryMount(t, a, img, reg.URL, nil, false)
	prime(t, m)
	before := m.API.Metrics(t)

	reg.Faults.Set(registry.Fault{IgnoreRange: true})
	var results []result
	failed := 0
	for _, rel := range range200Files {
		r := readOnce(t, m.Root, lookup(t, img, rel))
		t.Logf("%s", r)
		results = append(results, r)
		if r.Err != nil {
			failed++
		}
	}
	after := m.API.Metrics(t)
	if reg.Faults.Hits() == 0 {
		t.Fatalf("no blob request met the fault: the reads never reached the registry")
	}
	if !after.Has("nydus_backend_read_total") {
		t.Fatal("the daemon no longer exposes backend read metrics")
	}
	crc := after.Sum(metricCRCErrors, `reason="checksum"`) - before.Sum(metricCRCErrors, `reason="checksum"`)
	backendErrs := after.Sum(metricBackendErrors) - before.Sum(metricBackendErrors)
	t.Logf("%d of %d reads failed; %v CRC errors, %v backend errors", failed, len(results), crc, backendErrs)
	if !m.Daemon.Alive() {
		t.Fatalf("the daemon died on whole-blob responses")
	}

	// Whatever the backend made of the 200s, it cached none of it.
	reg.Faults.Clear()
	for _, rel := range range200Files {
		expectCorrect(t, readOnce(t, m.Root, lookup(t, img, rel)))
	}

	for _, r := range results {
		expectNotWrong(t, r)
	}
	if crc > 0 {
		t.Errorf("%v chunk groups were decoded from bytes at the wrong offset (CRC32C mismatch)", crc)
	}
	if failed == 0 || backendErrs == 0 {
		t.Errorf("whole-blob responses must be rejected by the backend: %d failed reads, %v backend errors", failed, backendErrs)
	}
}
