# NydusOverlayfs

nydus-overlayfs is a mount helper command for containerd to use in Nydus env. As the mount slice which nydus-snapshotter returned can not be mounted by containerd, so here provide a mount helper to do the mount refer to [containerd](https://github.com/containerd/containerd/blob/v1.5.7/mount/mount_linux.go#L384)

In order to unify the usage of `runc` and `kata`, nydus-snapshotter `Mount()` will return mount slice as below

```shell
[
    {
        Type: "fuse.nydus-overlayfs",
        Source: "overlay",
        Options: [lowerdir=lower_A:lower_B,upperdir=upper_A,workdir=work_A,extraoption={source:xxx,config:xxx,snapshotdir:xxx}],
    }
]
```

Containerd will use `mount.fuse` or `mount.fuse3` when `Type` has prefix `fuse` or `fuse3`, and the `mount.fuse` command format is

```shell
sudo mount.fuse overlay ./foo/merged -o lowerdir=./foo/lower2:./foo/lower1,upperdir=./foo/upper,workdir=./foo/work -t nydus-overlayfs
```

when `mount.fuse` starts, it will run below command to do the real mount

```shell
nydus-overlayfs overlay ./foo/merged -o lowerdir=./foo/lower2:./foo/lower1,upperdir=./foo/upper,workdir=./foo/work,dev,suid
```

So in nydus env,

1. when `runc` + `nydus`, `nydus-overlayfs` will ignore `extraoption` and do the overlay mount in containerd and runc-shim;
2. when `kata` + `nydus`, `nydus-overlayfs` will ignore `extraoption` and do the overlay mount in containerd and parse the `extraoption` in kata-shim.
