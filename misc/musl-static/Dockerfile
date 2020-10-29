FROM clux/muslrust:1.47.0

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /nydus-rs

CMD chmod 400 /root/.ssh/id_rsa && eval `ssh-agent` && ssh-add && make static-release
