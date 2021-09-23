# 使用 docker nydus graph driver

Docker 支持自定义的 remote graph driver，通过 graph driver 插件提供个性化容器镜像的存储、管理和挂载功能。
nydus 已经构建好了 graph driver plugin，并且已经发布到 DockerHub。在安装 nydus graph driver 后，用户可以在 docker 环境下快速启动容器和拉取镜像。

## 架构

---

Nydus graph driver 做为一个 docker engine 的插件，是一个独立运行的进程，其内置 http server。响应 docker engine 的 HTTP API。
插件运行在一个沙箱环境，在沙箱内，插件启动了 nydusd 进程，进而挂载了 rafs 作为容器的只读镜像层。
Nydusd 需要访问镜像的数据部分，这部分内容可能存储在远端。因此，在启动插件前，我们需要通过配置文件配置 nydusd，包括远端存储的鉴权等信息。

![Docker Info](./images/docker_graphdriver_arch.png)

## 配置 nydusd/rafs

---

将 nydus/rafs 的配置文件`config.json`保存在本机目录`/var/lib/nydus`中。

## 安装 graph driver plugin

---

### 直接从 DockerHub 安装

nydus remote graph driver 已经发布到 DockerHub (gechangwei/docker-nydus-graphdriver:0.2.0)，可以直接从 DockerHub 安装。

```
$ docker plugin install gechangwei/docker-nydus-graphdriver:0.2.0
```

## 启动 graph driver

---

在使用 graph driver plugin 前，需要先启动它。

```
$ sudo docker plugin enable gechangwei/docker-nydus-graphdriver:0.2.0
```

## 替换为 nydus graph driver

---

修改 docker 配置文件`/etc/docker/daemon.conf`。替换 graph driver。

```
{
    "experimental": true,
    "storage-driver": "gechangwei/docker-nydus-graphdriver:0.2.0"
}
```

## 重启 docker

---

```
$ sudo systemctl restart docker
```

## 验证正确性

---

执行`docker info`。Storage Driver 应该显示为"gechangwei/docker-nydus-graphdriver:0.2.0"

![Docker Info](./images/docker_info_storage_driver.png)

## 启动容器

---

使用`docker run`启动容器

# 局限

1. docker 版本>=20.10.2
2. `nydusify`构建镜像的时候，需要指定 blob 后端为 OSS。因为 docker 会逐层下载所有镜像层，而 remote graph driver 不能影响下载过程。
3. nydus graph driver 不兼容 classic OCI 镜像。
