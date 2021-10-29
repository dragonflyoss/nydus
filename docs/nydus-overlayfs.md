# NydusOverlayfs

`nydus-overlayfs` is a FUSE(Filesystem in UserSpacE) mount helper command for containerd to use with Nydus. The document explains in a nutshell on how it works.

When the `--enable-nydus-overlayfs` option is specified, `nydus-snapshotter` `Mount()` method returns a mount slice like
```shell
[
    {
        Type: "fuse.nydus-overlayfs",
        Source: "overlay",
        Options: [lowerdir=lower_A:lower_B,upperdir=upper_A,workdir=work_A,extraoption=base64({source:xxx,config:xxx,snapshotdir:xxx})],
    }
]
```

Compared with a mount slice returned by the `overlayfs` snapshotter, there is an extra `extraoption` option encoded in base64 format. The `nydus-overlayfs` mount helper is used to help containerd to ignore the extra mount option.

There are three calling stacks when handling a `nydus-snapshotter` mount slice.
1. `containerd` -> `mount.fuse` -> `nydus-overlay`
2. `containerd` -> `containerd-shim-runc-v2` -> `mount.fuse` -> `nydus-overlay`
3. `containerd` -> `containerd-shim-kata-v2` -> `nydusd`

Per [containerd](https://github.com/containerd/containerd/blob/v1.5.7/mount/mount_linux.go#L384), `containerd` and `containerd-shim-runc-v2` call `mount.fuse` or `mount.fuse3` when `Type` has prefix `fuse` or `fuse3`, with a command format like
```shell
mount.fuse overlay ./foo/merged -o lowerdir=./foo/lower2:./foo/lower1,upperdir=./foo/upper,workdir=./foo/work,extraoption=base64({source:xxx,config:xxx,snapshotdir:xxx}) -t nydus-overlayfs
```

When `mount.fuse` starts, it calls the below command to do the real mount
```shell
nydus-overlayfs overlay ./foo/merged -o lowerdir=./foo/lower2:./foo/lower1,upperdir=./foo/upper,workdir=./foo/work,extraoption=base64({source:xxx,config:xxx,snapshotdir:xxx}),dev,suid
```

And `nydus-overlayfs` parses the mount options, filters out `extraoption`, and calls the `mount` syscall in a format equivalent to
```shell
mount -t overlay overlay ./foo/merged -o lowerdir=./foo/lower2:./foo/lower1,upperdir=./foo/upper,workdir=./foo/work,dev,suid
```

Meanwhile, when ncontainerd passes the `nydus-snapshotter` mount slice to `containerd-shim-kata-v2`, it can parse the mount slice and pass the `extraoption` to `nydusd`, to support nydus image format natively.

So in summary, `containerd` and `containerd-shim-runc-v2` rely on the `nydus-overlay` mount helper to handle the mount slice returned by `nydus-snapshotter`, while `containerd-shim-kata-v2` can parse and handle it on its own.
