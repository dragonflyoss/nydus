package corpus

import "github.com/dragonflyoss/nydus/tests/e2e/internal/env"

// HugeSeed seeds the Huge corpus.
const HugeSeed = 20261020

// MakeHuge stages the files past 4GiB on their own. Past u32::MAX an inode
// needs the extended form for its size and file offsets pass 32 bits. They
// are kept out of the other corpora because the FUSE reader reports no
// holes and tar carries none, so every pass over them through either moves
// gigabytes of zeros; here they are read only where a test means to.
func MakeHuge(t env.TB, dir string) {
	t.Helper()
	const g4 = int64(1) << 32
	const chunk = 2 << 20
	c := NewSeeded(t, dir, HugeSeed)
	// The largest size a compact inode holds, data at both ends.
	c.CreateSparseFile(t, "huge/4g_minus_1", g4-1, map[int64][]byte{
		0: c.Random(16), g4 - 17: c.Random(16),
	})
	// Exactly 4GiB, data straddling a chunk boundary and the 32-bit edge.
	c.CreateSparseFile(t, "huge/4g", g4, map[int64][]byte{
		chunk - 8: c.Random(16), g4 - 4096 - 8: c.Random(4096 + 8),
	})
	// Data straddling 4GiB, which is also every block, pcluster and chunk
	// boundary, and a tail in a partial last block.
	c.CreateSparseFile(t, "huge/4g_plus_4097", g4+4097, map[int64][]byte{
		0: c.Random(16), g4 - 8: c.Random(16), g4 + 4097 - 16: c.Random(16),
	})
	// A small file the read contract can hash and fault in, which the
	// unhashed huge files cannot serve.
	c.CreateFile(t, "small", c.Random(64<<10))
	c.Finish(t)
}
