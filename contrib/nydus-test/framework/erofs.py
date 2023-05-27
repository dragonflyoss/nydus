from utils import execute, logging_setup


class Erofs:
    def __init__(self) -> None:
        pass

    def mount(self, fsid, mountpoint):
        cmd = f"mount -t erofs -o fsid={fsid} none {mountpoint}"
        self.mountpoint = mountpoint
        r, _ = execute(cmd, shell=True)
        assert r

    def umount(self):
        cmd = f"umount {self.mountpoint}"
        r, _ = execute(cmd, shell=True)
        assert r
