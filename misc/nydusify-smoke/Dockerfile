FROM docker:dind

ENV NYDUS_IMAGE=/nydus-rs/target-fusedev/x86_64-unknown-linux-musl/release/nydus-image
ENV NYDUSD=/nydus-rs/target-fusedev/x86_64-unknown-linux-musl/release/nydusd
WORKDIR /nydus-rs/contrib/nydusify/tests

ADD ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]
