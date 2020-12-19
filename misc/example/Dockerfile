FROM ubuntu:latest AS base
RUN apt update
RUN apt install -y wget
RUN wget https://github.com/containerd/containerd/releases/download/v1.4.3/cri-containerd-cni-1.4.3-linux-amd64.tar.gz
RUN mkdir -p /opt/containerd-cri && tar xzf cri-containerd-cni-1.4.3-linux-amd64.tar.gz -C /opt/containerd-cri
# upstream containerd is not statically linked. Let's use the dind one instead.
RUN rm -f /opt/containerd-cri/usr/local/bin/containerd

FROM golang:1.15.6 AS go
RUN go get github.com/containerd/containerd
RUN cd $GOPATH/src/github.com/containerd/containerd && git checkout v1.4.3
RUN cd $GOPATH/src/github.com/containerd/containerd && make EXTRA_FLAGS="-buildmode pie" EXTRA_LDFLAGS='-linkmode external -extldflags "-fno-PIC -static"' BUILDTAGS="no_btrfs netgo osusergo static_build"
RUN cd $GOPATH/src/github.com/containerd/containerd && mv bin /opt/

FROM docker:dind
COPY --from=base /opt/containerd-cri/etc/cni/net.d/* /etc/cni/net.d/
COPY --from=base /opt/containerd-cri/opt/cni/bin/* /opt/cni/bin/
COPY --from=base /opt/containerd-cri/usr/local/bin/* /usr/local/bin/
COPY --from=go /opt/bin/* /opt/bin/
COPY containerd-config.toml  /opt/etc/containerd/config.toml
COPY crictl.yaml /etc/
COPY nydusd-config.json crictl.yaml /opt/etc/
COPY nydusd nydusify containerd-nydus-grpc nydus-image /opt/bin/
COPY containerd-entrypoint.sh container-config.yaml pod-config.yaml run.sh /
ENTRYPOINT ["/containerd-entrypoint.sh"]
