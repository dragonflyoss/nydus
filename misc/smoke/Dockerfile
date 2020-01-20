FROM rust:1.43

RUN echo '[source.crates-io] \n\
registry = "https://github.com/rust-lang/crates.io-index" \n\
replace-with = "thu" \n\
[source.thu] \n\
registry = "https://mirrors.tuna.tsinghua.edu.cn/git/crates.io-index.git"'\
>> /usr/local/cargo/config

RUN rustup component add clippy
RUN rustup component add rustfmt
RUN rustup update

RUN sed -i "s@http://deb.debian.org@http://mirrors.aliyun.com@g" /etc/apt/sources.list
RUN cat /etc/apt/sources.list
RUN rm -Rf /var/lib/apt/lists/*
RUN apt update && apt install -y tree

WORKDIR /nydus-rs

CMD chmod 400 /root/.ssh/id_rsa && eval `ssh-agent` && ssh-add && make test
