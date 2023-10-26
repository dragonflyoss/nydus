FROM python:3-bullseye

ENV GOPROXY https://goproxy.io;

RUN echo "deb https://mirrors.163.com/debian/ bullseye main contrib non-free \n\
    deb https://mirrors.163.com/debian/ bullseye-updates main contrib non-free \n\
    deb https://mirrors.163.com/debian/ bullseye-backports main contrib non-free " > /etc/apt/sources.list

RUN apt update && apt install --no-install-recommends -y attr libattr1-dev fio pkg-config libssl-dev; rm -rf /var/lib/apt/*

RUN wget http://gosspublic.alicdn.com/ossutil/1.6.13/ossutil64 -O /usr/bin/ossutil64; chmod +x /usr/bin/ossutil64

RUN mkdir /nydus-test; mkdir /nydus-rs

RUN python3 -m pip install --upgrade pip
RUN pip3 install pytest xattr requests psutil requests_unixsocket libconf py-splice fallocate pytest-repeat PyYAML six docker toml

# Pack containerd runc and crictl
RUN wget https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.17.0/crictl-v1.17.0-linux-amd64.tar.gz -O /home/crictl-v1.17.0-linux-amd64.tar.gz
RUN tar zxvf /home/crictl-v1.17.0-linux-amd64.tar.gz -C /usr/local/bin && rm -f crictl-v1.17.0-linux-amd64.tar.gz
RUN wget https://github.com/containerd/containerd/releases/download/v1.4.3/containerd-1.4.3-linux-amd64.tar.gz -O /home/containerd-1.4.3-linux-amd64.tar.gz
RUN cd /home; tar -zxf containerd-1.4.3-linux-amd64.tar.gz && mkdir -p /usr/bin/containerd/ && mv ./bin/* /usr/bin/containerd/; cd /
ENV PATH $PATH:/usr/bin/containerd
RUN wget https://github.com/opencontainers/runc/releases/download/v1.1.2/runc.amd64 -O /usr/bin/runc
RUN chmod +x /usr/bin/*; chmod +x /usr/bin/runc

# Install golang
RUN wget https://go.dev/dl/go1.20.10.linux-amd64.tar.gz -O /home/go1.20.10.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf /home/go1.20.10.linux-amd64.tar.gz
ENV PATH $PATH:/usr/local/go/bin
RUN mkdir /root/go
RUN rm -rf /home/*

# Get Rust
ENV RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static
ENV RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN echo '[source.crates-io] \n\
    replace-with = "ustc" \n\
    [source.ustc] \n\
    registry = "https://mirrors.ustc.edu.cn/crates.io-index"'\
    >> /root/.cargo/config
RUN rustup component add clippy
RUN rustup component add rustfmt
RUN rustup install 1.52.1-x86_64-unknown-linux-gnu
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ENTRYPOINT python3 nydus_test_config.py --dist fs_structure.yaml && pytest -vs --durations=0 --pdb
ENTRYPOINT ["/entrypoint.sh"]

#    functional-test/test_nydus.py functional-test/test_layered_image.py \
#    functional-test/test_upgrade.py functional-test/test_api.py
