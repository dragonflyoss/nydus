package fault

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
)

const (
	// forgedFile is 2MiB+1 random bytes, so any 64 of them are unique in
	// the blob.
	forgedFile = "data/size/02097153"
	// forgedOffset is where in forgedFile the forged corruption lands.
	forgedOffset = 1<<20 + 100
)

// TestBitflip corrupts blob data on its way to the reader.
//
// A flipped bit in a registry response is always caught: every fetched
// chunk group is checked against its CRC32C by default, so with either setting the read
// fails, and reads back right once the corruption stops.
func TestBitflip(t *testing.T) {
	t.Parallel()
	img := fixture.Get(t, "zstd-4k")
	for _, a := range adapters {
		for _, verify := range []bool{false, true} {
			name := a.Name() + "/default"
			if verify {
				name = a.Name() + "/verify"
			}
			t.Run("registry/"+name, func(t *testing.T) {
				t.Parallel()
				bitflipRegistry(t, a, img, verify)
			})
		}
	}
}

func bitflipRegistry(t *testing.T, a mount.Adapter, img fixture.Image, verify bool) {
	reg := pushImage(t, img)
	m := registryMount(t, a, img, reg.URL, nil, verify)
	prime(t, m)
	big := lookup(t, img, bigFile)

	// Every response from here on is corrupted, retries and refetches too.
	reg.Faults.Set(registry.Fault{FlipBit: mount.Ptr(int64(64))})
	r := readOnce(t, m.Root, big)
	expectFailed(t, r)
	expectNotWrong(t, r)
	if reg.Faults.Hits() == 0 {
		t.Fatalf("no blob request met the fault: the read never reached the registry")
	}

	reg.Faults.Clear()
	expectCorrect(t, readOnce(t, m.Root, big))
}
