module github.com/dragonflyoss/image-service/contrib/nydusify

go 1.14

require (
	github.com/aliyun/aliyun-oss-go-sdk v2.1.5+incompatible
	github.com/baiyubin/aliyun-sts-go-sdk v0.0.0-20180326062324-cfa1a18b161f // indirect
	github.com/containerd/containerd v1.5.13
	github.com/docker/cli v20.10.0-beta1.0.20201029214301-1d20b15adc38+incompatible
	github.com/docker/distribution v2.8.1+incompatible
	github.com/docker/docker v20.10.0-beta1.0.20201110211921-af34b94a78a1+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.6.3 // indirect
	github.com/dustin/go-humanize v1.0.0
	github.com/google/uuid v1.2.0
	github.com/kr/text v0.2.0 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.2
	github.com/pkg/errors v0.9.1
	github.com/pkg/xattr v0.4.3
	github.com/prometheus/client_golang v1.11.0
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/tidwall/gjson v1.9.3
	github.com/urfave/cli/v2 v2.3.0
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20220412211240-33da011f77ad
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	lukechampine.com/blake3 v1.1.5
)

replace github.com/opencontainers/runc => github.com/opencontainers/runc v1.1.2
