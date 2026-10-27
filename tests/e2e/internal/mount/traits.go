package mount

// Traits describe how an adapter's daemon relates to what it serves, so
// contract cases can hold each adapter to what it promises.
type Traits struct {
	// API reports whether the daemon serves --apiserver metrics.
	API bool
	// OwnsMount reports whether the daemon mounts the filesystem itself:
	// it unmounts on SIGTERM and exits once the mount is gone. A daemon
	// that only exports a device leaves mounting to its caller.
	OwnsMount bool
}

// Traited is implemented by adapters whose traits differ from the default
// (FUSE and fileio: both traits set).
type Traited interface {
	Traits() Traits
}

// TraitsOf returns the traits of a.
func TraitsOf(a Adapter) Traits {
	if ta, ok := a.(Traited); ok {
		return ta.Traits()
	}
	return Traits{API: true, OwnsMount: true}
}
