package mount

import "github.com/dragonflyoss/nydus/tests/e2e/util/fixture"

// Traits describe how an adapter's daemon relates to what it serves, so
// conformance cases can hold each adapter to what it promises.
type Traits struct {
	// API reports whether the daemon serves --apiserver metrics.
	API bool
	// OwnsMount reports whether the daemon mounts the filesystem itself:
	// it unmounts on SIGTERM and exits once the mount is gone. A daemon
	// that only exports a device leaves mounting to its caller.
	OwnsMount bool
	// Daemonless reports that no nydus process serves the mount, so there
	// is nothing to signal, fail or query.
	Daemonless bool
}

// Traited is implemented by adapters whose traits differ from the default
// (FUSE and fileio: both traits set).
type Traited interface {
	Traits() Traits
}

// Selective is implemented by adapters that serve only some layouts.
type Selective interface {
	Serves(fixture.Layout) bool
}

// Serves reports whether a can serve images of layout.
func Serves(a Adapter, layout fixture.Layout) bool {
	if sa, ok := a.(Selective); ok {
		return sa.Serves(layout)
	}

	return true
}

// TraitsOf returns the traits of a.
func TraitsOf(a Adapter) Traits {
	if ta, ok := a.(Traited); ok {
		return ta.Traits()
	}

	return Traits{API: true, OwnsMount: true}
}
