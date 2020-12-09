#! /bin/sh

set -eu

if [ "$#" -eq 0 ]; then
        /opt/bin/containerd -c /opt/etc/containerd/config.toml -l debug &
	/opt/bin/containerd-nydus-grpc --nydusd-path /opt/bin/nydusd \
		--config-path /opt/etc/nydusd-config.json \
		--shared-daemon \
		--log-level debug \
		--root /var/lib/containerd-test/io.containerd.snapshotter.v1.nydus \
		--address /run/containerd-test/containerd-nydus-grpc.sock &
fi

# pass all to dockerd-entrypoint.sh
set -- dockerd-entrypoint.sh "$@"

exec "$@"
