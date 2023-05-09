GOARCH ?= $(shell go env GOARCH)
GOPROXY ?= https://goproxy.io

ifdef GOPROXY
PROXY := GOPROXY=${GOPROXY}
endif

build:
	@CGO_ENABLED=0 ${PROXY} GOOS=linux GOARCH=${GOARCH} go build  -o ./convert ./convert.go
