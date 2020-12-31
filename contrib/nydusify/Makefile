build:
	@CGO_ENABLED=0 GO111MODULE=on GOOS=linux go build -gcflags=all="-N -l" -o ./cmd ./cmd/nydusify.go

static-release:
	@CGO_ENABLED=0 GOOS=linux go build -ldflags '-extldflags "-static"' -o ./cmd ./cmd/nydusify.go

test:
	@CGO_ENABLED=0 GOOS=linux go test ./tests
