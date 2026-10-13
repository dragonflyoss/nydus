module github.com/dragonflyoss/nydus/tests/e2e

go 1.25.5

require (
	github.com/containerd/containerd/v2 v2.0.2
	github.com/containerd/continuity v0.4.4
	github.com/jedib0t/go-pretty/v6 v6.7.10
	github.com/opencontainers/image-spec v1.1.0
	github.com/pkg/xattr v0.4.12
	github.com/stretchr/testify v1.11.1
	golang.org/x/sys v0.30.0
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/Microsoft/hcsshim v0.12.9 // indirect
	github.com/containerd/cgroups/v3 v3.0.3 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/typeurl/v2 v2.2.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/moby/sys/sequential v0.6.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/sync v0.11.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241021214115-324edc3d5d38 // indirect
	google.golang.org/grpc v1.67.1 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dragonflyoss/nydus/nydusify v0.0.0-00010101000000-000000000000
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	golang.org/x/text v0.22.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/dragonflyoss/nydus/nydusify => ../../nydusify
