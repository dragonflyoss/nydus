#!/bin/bash

GOOS=$(go env GOOS)
if [ -z "$GOARCH" ]; then
    GOARCH=$(go env GOARCH)
    echo "GOARCH is not set, use GOARCH=$GOARCH"
fi

cat <<EOF > .goreleaser.yml
version: 2
release:
  draft: true
  replace_existing_draft: true

before:
  hooks:
    - go mod download

builds:
  - main: contrib/goreleaser/main.go
    id: nydusify
    binary: nydusify
    goos:
      - $GOOS
    goarch:
      - $GOARCH
    env:
      - CGO_ENABLED=0
    hooks:
      post:
        - cp nydus-static/{{ .Name }} dist/{{ .Name }}_{{ .Target }}/{{ .Name }}
  - main: contrib/goreleaser/main.go
    id: nydus-overlayfs
    binary: nydus-overlayfs
    goos:
      - $GOOS
    goarch:
      - $GOARCH
    env:
      - CGO_ENABLED=0
    hooks:
      post:
        - cp nydus-static/{{ .Name }} dist/{{ .Name }}_{{ .Target }}/{{ .Name }}
  - main: contrib/goreleaser/main.go
    id: nydus-image
    binary: nydus-image
    goos:
      - $GOOS
    goarch:
      - $GOARCH
    env:
      - CGO_ENABLED=0
    hooks:
      post:
        - cp nydus-static/{{ .Name }} dist/{{ .Name }}_{{ .Target }}/{{ .Name }}
  - main: contrib/goreleaser/main.go
    id: nydusctl
    binary: nydusctl
    goos:
      - $GOOS
    goarch:
      - $GOARCH
    env:
      - CGO_ENABLED=0
    hooks:
      post:
        - cp nydus-static/{{ .Name }} dist/{{ .Name }}_{{ .Target }}/{{ .Name }}
  - main: contrib/goreleaser/main.go
    id: nydusd
    binary: nydusd
    goos:
      - $GOOS
    goarch:
      - $GOARCH
    env:
      - CGO_ENABLED=0
    hooks:
      post:
        - cp nydus-static/{{ .Name }} dist/{{ .Name }}_{{ .Target }}/{{ .Name }}

archives:
  - name_template: "nydus-static-{{ .Version }}-{{ .Os }}-{{ .Arch }}"
    formats: ["zip"]

checksum:
  name_template: "checksums-{{ .Version }}-$GOOS-$GOARCH.txt"

snapshot:
  version_template: "{{ .Tag }}-next"

changelog:
  sort: asc
  filters:
    exclude:
      - "^docs:"
      - "^test:"

nfpms:
  - id: nydus-static
    maintainer: Nydus Maintainers  <dragonfly-maintainers@googlegroups.com>
    file_name_template: "nydus-static-{{ .Version }}-{{ .Os }}-{{ .Arch }}"
    package_name: nydus-static
    description: Static binaries of Nydus, designed for building and mounting Nydus images.
    license: "Apache 2.0"
    bindir: /usr/bin
    ids:
      - nydusify
      - nydus-overlayfs
      - nydus-image
      - nydusctl
      - nydusd

    formats:
      - rpm
      - deb
    contents:
      - src: nydus-static/configs
        dst: /etc/nydus/configs
EOF