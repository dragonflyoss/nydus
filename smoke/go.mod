module github.com/dragonflyoss/image-service/smoke

go 1.18

require (
	github.com/containerd/containerd v1.6.17
	github.com/containerd/nydus-snapshotter v0.0.0-00010101000000-000000000000
	github.com/opencontainers/go-digest v1.0.0
	github.com/pkg/errors v0.9.1
	github.com/pkg/xattr v0.4.9
	github.com/stretchr/testify v1.8.1
	golang.org/x/sys v0.4.0
)

require (
	github.com/Microsoft/go-winio v0.5.2 // indirect
	github.com/Microsoft/hcsshim v0.9.6 // indirect
	github.com/containerd/cgroups v1.0.4 // indirect
	github.com/containerd/continuity v0.3.0 // indirect
	github.com/containerd/fifo v1.0.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/klauspost/compress v1.15.12 // indirect
	github.com/opencontainers/image-spec v1.0.3-0.20211202183452-c5a74bcca799 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/sirupsen/logrus v1.9.0 // indirect
	go.opencensus.io v0.23.0 // indirect
	golang.org/x/mod v0.8.0 // indirect
	golang.org/x/sync v0.0.0-20220722155255-886fb9371eb4 // indirect
	google.golang.org/genproto v0.0.0-20220502173005-c8bf987b8c21 // indirect
	google.golang.org/grpc v1.50.1 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// It will be updated to official repo once nydus-snapshotter release.
replace github.com/containerd/nydus-snapshotter => github.com/imeoer/nydus-snapshotter v0.3.32
