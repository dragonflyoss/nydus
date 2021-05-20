module github.com/dragonflyoss/image-service/contrib/nydus-snapshotter

go 1.14

require (
	github.com/containerd/containerd v1.4.3
	github.com/containerd/continuity v0.0.0-20200928162600-f2cc35102c2a
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/dragonflyoss/image-service/contrib/nydusify v0.0.0-20210518022841-c17fb49cce7c
	github.com/godbus/dbus v0.0.0-20190422162347-ade71ed3457e // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e
	github.com/google/go-containerregistry v0.1.2
	github.com/google/uuid v1.2.0
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.0.0
	github.com/prometheus/client_model v0.0.0-20190812154241-14fe0d1b01d4
	github.com/prometheus/common v0.4.1
	github.com/sirupsen/logrus v1.7.0
	github.com/stretchr/testify v1.5.1
	github.com/urfave/cli/v2 v2.3.0
	go.etcd.io/bbolt v1.3.5
	golang.org/x/sync v0.0.0-20200625203802-6e8e738ad208
	google.golang.org/grpc v1.31.0
	gotest.tools/v3 v3.0.2 // indirect
)
