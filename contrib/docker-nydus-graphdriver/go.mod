module github.com/dragonflyoss/image-service/contrib/nydus_graphdriver

go 1.15

require (
	github.com/containerd/containerd v1.6.0-beta.4 // indirect
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf // indirect
	github.com/docker/docker v20.10.3-0.20211206061157-934f955e3d62+incompatible
	github.com/docker/go-plugins-helpers v0.0.0-20211224144127-6eecb7beb651
	github.com/moby/sys/mount v0.3.0 // indirect
	github.com/moby/sys/mountinfo v0.5.0
	github.com/opencontainers/selinux v1.8.2
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.8.1
	github.com/vbatts/tar-split v0.11.1 // indirect
	golang.org/x/sys v0.0.0-20211025201205-69cdffdb9359
)

replace (
	github.com/containerd/go-runc => github.com/containerd/go-runc v1.0.0
	github.com/opencontainers/image-spec => github.com/opencontainers/image-spec v1.0.2
	github.com/opencontainers/runc => github.com/opencontainers/runc v1.0.3
)
