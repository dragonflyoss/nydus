// Package contract is the filesystem contract every way of serving an image
// must honor: FUSE and fileio (GA) and the experimental transports. A case
// is written once against a mounted image and runs unchanged against each
// adapter; an adapter's test is a single call to Run.
//
// Cases are registered from one file each (cNN_name.go) and come in two
// scopes. Semantic cases check behavior, which does not depend on how the
// image is encoded: they run once per adapter against the semantic image.
// Data cases check what is read back, which does: they run against every
// image of fixture.Matrix in every mode the adapter supports. That is
// "semantics once, data across the matrix".
package contract

import (
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
)

// Scope selects the mounts a case runs against. Semantic and Data combine.
type Scope int

const (
	// Semantic cases run once per adapter, on the shared semantic mount.
	Semantic Scope = 1 << iota
	// Data cases run on a mount of every matrix image in every mode.
	Data
	// Own cases mount whatever they need themselves (lifecycle, failure
	// injection), once per adapter.
	Own
)

// SemanticLayout is the layout of the semantic image.
const SemanticLayout = "zstd-4k"

// Fixture is the mount a Semantic or Data case runs against.
type Fixture struct {
	*mount.Mounted
	Adapter mount.Adapter
}

// At joins rel onto the mount root.
func (f *Fixture) At(rel string) string { return f.Path(rel) }

// Src joins rel onto the source tree of the image; empty for merged images.
func (f *Fixture) Src(rel string) string {
	if f.Image.Source == "" {
		return ""
	}
	return f.Image.Source + "/" + rel
}

// Case is one contract case.
type Case struct {
	// ID is the stable case number, e.g. "C03".
	ID    string
	Name  string
	Scope Scope
	// Run checks a Semantic or Data fixture. Cases call t.Parallel in their
	// subtests as they see fit; the case itself already runs in parallel.
	Run func(t *testing.T, f *Fixture)
	// RunOwn checks an Own case against the adapter.
	RunOwn func(t *testing.T, a mount.Adapter)
	// Supports narrows the adapters, modes or layouts a case applies to;
	// nil means all. Own cases see the zero Layout. A case that does not
	// apply is not run at all, rather than skipped, so the adapter's coverage
	// is visible in its case list.
	Supports func(a mount.Adapter, m mount.Mode, l fixture.Layout) bool
}

var (
	registryMu sync.Mutex
	registry   []Case
)

// Register adds a case; each cNN_*.go file registers its case from init.
func Register(c Case) {
	registryMu.Lock()
	defer registryMu.Unlock()
	for _, other := range registry {
		if other.ID == c.ID {
			panic("contract: duplicate case " + c.ID)
		}
	}
	if c.Scope == 0 || (c.Scope&Own != 0 && c.Scope != Own) {
		panic("contract: case " + c.ID + " has an invalid scope")
	}
	if (c.Scope == Own) != (c.RunOwn != nil) || (c.Scope != Own) != (c.Run != nil) {
		panic("contract: case " + c.ID + " sets the wrong run function for its scope")
	}
	registry = append(registry, c)
}

// Cases returns the registered cases in ID order.
func Cases() []Case {
	registryMu.Lock()
	defer registryMu.Unlock()
	out := append([]Case(nil), registry...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// SemanticImage is the image Semantic and Own cases run against: the
// Stress corpus, a superset of the Standard tree whose paths the semantic
// cases address by name, built with SemanticLayout.
func SemanticImage(t *testing.T) fixture.Image {
	t.Helper()
	l, err := fixture.LayoutByName(SemanticLayout)
	if err != nil {
		t.Fatal(err)
	}
	return fixture.Build(t, fixture.Stress, l)
}

// Run runs every applicable case against a: the semantic cases on one
// shared mount, the own cases, and the data cases on one mount per matrix
// image and mode. Every level runs in parallel.
func Run(t *testing.T, a mount.Adapter) {
	t.Helper()
	a.Require(t)
	cases := Cases()

	t.Run("Semantic", func(t *testing.T) {
		t.Parallel()
		f := &Fixture{Mounted: mount.Mount(t, a, SemanticImage(t), mount.Options{Mode: mount.Cold}), Adapter: a}
		runCases(t, cases, Semantic, f)
	})

	for _, c := range cases {
		if c.Scope != Own || (c.Supports != nil && !c.Supports(a, mount.Cold, fixture.Layout{})) {
			continue
		}
		t.Run(c.ID+"_"+c.Name, func(t *testing.T) {
			t.Parallel()
			c.RunOwn(t, a)
		})
	}

	for _, name := range fixture.Matrix {
		for _, mode := range mount.Modes {
			if !a.Supports(mode) || (mode == mount.Blob && strings.HasPrefix(name, fixture.MergedPrefix)) {
				continue
			}
			t.Run("Data/"+name+"/"+string(mode), func(t *testing.T) {
				t.Parallel()
				f := &Fixture{Mounted: mount.Mount(t, a, fixture.Get(t, name), mount.Options{Mode: mode}), Adapter: a}
				runCases(t, cases, Data, f)
			})
		}
	}
}

func runCases(t *testing.T, cases []Case, scope Scope, f *Fixture) {
	t.Helper()
	for _, c := range cases {
		if c.Scope&scope == 0 || (c.Supports != nil && !c.Supports(f.Adapter, f.Mode, f.Image.Layout)) {
			continue
		}
		t.Run(c.ID+"_"+c.Name, func(t *testing.T) {
			t.Parallel()
			c.Run(t, f)
		})
	}
}
