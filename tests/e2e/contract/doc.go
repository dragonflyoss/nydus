// Package contract runs the filesystem contract (cases C01-C15 in
// internal/contract) against the two GA ways of serving an image: the nydus
// FUSE reader (TestFUSE) and fileio, a kernel EROFS mount of the exported
// image file (TestFileio).
//
// Run it as root, e.g. `make e2e PKG=./contract/...`; select one adapter,
// scope or case with -run, e.g. -run 'TestFUSE/Semantic/C08'.
package contract
