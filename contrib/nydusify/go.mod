module github.com/dragonflyoss/image-service/contrib/nydusify

go 1.18

require (
	github.com/aliyun/aliyun-oss-go-sdk v2.1.5+incompatible
	github.com/aws/aws-sdk-go-v2 v1.17.2
	github.com/aws/aws-sdk-go-v2/config v1.18.4
	github.com/aws/aws-sdk-go-v2/credentials v1.13.4
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.11.43
	github.com/aws/aws-sdk-go-v2/service/s3 v1.29.5
	github.com/containerd/containerd v1.6.17
	github.com/docker/cli v20.10.23+incompatible
	github.com/docker/distribution v2.8.1+incompatible
	github.com/goharbor/acceleration-service v0.1.1
	github.com/google/uuid v1.3.0
	github.com/hashicorp/go-hclog v1.3.1
	github.com/hashicorp/go-plugin v1.4.5
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.3-0.20211202183452-c5a74bcca799
	github.com/pkg/errors v0.9.1
	github.com/pkg/xattr v0.4.3
	github.com/prometheus/client_golang v1.14.0
	github.com/sirupsen/logrus v1.9.0
	github.com/stretchr/testify v1.8.1
	github.com/urfave/cli/v2 v2.24.2
	golang.org/x/sync v0.0.0-20220722155255-886fb9371eb4
	golang.org/x/sys v0.4.0
	lukechampine.com/blake3 v1.1.5
)

require (
	github.com/Microsoft/go-winio v0.5.2 // indirect
	github.com/Microsoft/hcsshim v0.9.6 // indirect
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/astaxie/beego v1.12.1 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.4.10 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.12.20 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.26 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.20 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.27 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.0.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.9.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.1.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.20 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.13.20 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.11.26 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.13.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.17.6 // indirect
	github.com/aws/smithy-go v1.13.5 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.1.2 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/containerd/cgroups v1.0.4 // indirect
	github.com/containerd/continuity v0.3.0 // indirect
	github.com/containerd/fifo v1.0.0 // indirect
	github.com/containerd/nydus-snapshotter v0.3.1 // indirect
	github.com/containerd/stargz-snapshotter v0.13.0 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.14.1 // indirect
	github.com/containerd/ttrpc v1.1.0 // indirect
	github.com/containerd/typeurl v1.0.2 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/docker/docker v20.10.17+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.6.4 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/felixge/httpsnoop v1.0.2 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gocraft/work v0.5.1 // indirect
	github.com/gogo/googleapis v1.4.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/goharbor/harbor/src v0.0.0-20211021012518-bc6a7f65a6fa // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/gomodule/redigo v2.0.0+incompatible // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.16.0 // indirect
	github.com/hashicorp/yamux v0.1.1 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/klauspost/compress v1.15.15 // indirect
	github.com/klauspost/cpuid v1.3.1 // indirect
	github.com/lib/pq v1.10.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.16 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mitchellh/go-testing-interface v1.14.1 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/sys/mountinfo v0.6.2 // indirect
	github.com/moby/sys/signal v0.6.0 // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/opencontainers/runc v1.1.2 // indirect
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417 // indirect
	github.com/opencontainers/selinux v1.10.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/common v0.37.0 // indirect
	github.com/prometheus/procfs v0.8.0 // indirect
	github.com/robfig/cron v1.0.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/vbatts/tar-split v0.11.2 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	go.opencensus.io v0.23.0 // indirect
	go.opentelemetry.io/contrib v0.22.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.22.0 // indirect
	go.opentelemetry.io/otel v1.3.0 // indirect
	go.opentelemetry.io/otel/exporters/jaeger v1.0.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/internal/retry v1.3.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.3.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.3.0 // indirect
	go.opentelemetry.io/otel/internal/metric v0.22.0 // indirect
	go.opentelemetry.io/otel/metric v0.22.0 // indirect
	go.opentelemetry.io/otel/sdk v1.3.0 // indirect
	go.opentelemetry.io/otel/trace v1.3.0 // indirect
	go.opentelemetry.io/proto/otlp v0.11.0 // indirect
	golang.org/x/mod v0.8.0 // indirect
	golang.org/x/net v0.5.0 // indirect
	golang.org/x/text v0.6.0 // indirect
	golang.org/x/time v0.0.0-20220722155302-e5dcc9cfc0b9 // indirect
	google.golang.org/genproto v0.0.0-20220927151529-dcaddaf36704 // indirect
	google.golang.org/grpc v1.50.1 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/opencontainers/runc => github.com/opencontainers/runc v1.1.2

// It will be updated to official repo once acceleration-service release.
replace github.com/goharbor/acceleration-service => github.com/imeoer/acceleration-service v0.0.34

// It will be updated to official repo once nydus-snapshotter release.
replace github.com/containerd/nydus-snapshotter => github.com/imeoer/nydus-snapshotter v0.3.32
