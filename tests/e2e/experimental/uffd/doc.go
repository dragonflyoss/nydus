// Package uffd tests `nydus uffd`, which serves the flattened image as guest
// memory: a client hands the daemon a userfaultfd over a Unix socket and the
// daemon resolves its page faults from the image, either by copying the data
// in (UFFDIO_COPY/ZEROPAGE) or by returning backing fds the client maps
// itself (zerocopy). Unlike the other transports it serves no filesystem, so
// it has no mount.Adapter and does not run the filesystem contract.
package uffd
