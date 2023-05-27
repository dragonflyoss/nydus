from abc import ABCMeta, abstractmethod
from distributor import Distributor
from utils import Size, Unit, pushd
import xattr
import os
import utils
from workload_gen import WorkloadGen

"""
Scratch a target directory
Verify image according to per schema
"""


class Verifier:
    __metaclass__ = ABCMeta

    def __init__(self, target, dist: Distributor):
        self.target = target
        self.dist = dist

    @abstractmethod
    def scratch(self):
        pass

    @abstractmethod
    def verify(self):
        pass


class XattrVerifier(Verifier):
    def __init__(self, target, dist: Distributor):
        super().__init__(target, dist)

    def scratch(self, scratch_dir):
        """Put various kinds of xattr value into.
        1. Very long value
        2. a common short value
        3. Nothing resides in value field
        4. Single file, multiple pairs.
        5. /n
        6. whitespace
        7. 中文
        8. Binary
        9. Only key?
        """
        self.dist.put_symlinks(100)
        files_cnt = 20
        self.dist.put_multiple_files(files_cnt, Size(9, Unit.KB))
        self.scratch_dir = os.path.abspath(scratch_dir)
        self.source_files = {}
        self.source_xattrs = {}
        self.source_dirs = {}
        self.source_dirs_xattrs = {}
        self.encoding = "gb2312"

        self.xattr_pairs = 50 if utils.get_fs_type(os.getcwd()) == "xfs" else 20

        # TODO: Only key without values?
        with pushd(self.scratch_dir):
            for f in self.dist.files[-files_cnt:]:
                relative_path = os.path.relpath(f, start=self.scratch_dir)
                self.source_xattrs[relative_path] = {}
                for idx in range(0, self.xattr_pairs):
                    # TODO: Random this Key
                    k = f"trusted.nydus.{Distributor.generate_random_name(20, chinese=True)}"
                    v = f"_{Distributor.generate_random_length_name(20, chinese=True)}"
                    xattr.setxattr(f, k.encode(self.encoding), v.encode(self.encoding))
                    # Use relative or canonicalized names as key to locate
                    # path in source rootfs directory. So we verify if image is
                    # packed correctly.
                    self.source_files[relative_path] = os.path.abspath(f)
                    self.source_xattrs[relative_path][k] = v

        dir_cnt = 20
        self.dist.put_directories(dir_cnt)

        # Add xattr key-value paris to directories.
        with pushd(self.scratch_dir):
            for d in self.dist.dirs[-dir_cnt:]:
                relative_path = os.path.relpath(d, start=self.scratch_dir)
                self.source_dirs_xattrs[relative_path] = {}
                for idx in range(0, self.xattr_pairs):
                    # TODO: Random this Key
                    k = f"trusted.{Distributor.generate_random_name(20)}"
                    v = f"{Distributor.generate_random_length_name(50)}"
                    xattr.setxattr(d, k, v.encode())
                    # Use relative or canonicalized names as key to locate
                    # path in source rootfs directory. So we verify if image is
                    # packed correctly.
                    self.source_dirs[relative_path] = os.path.abspath(d)
                    self.source_dirs_xattrs[relative_path][k] = v

    def verify(self, target_dir):
        """"""
        with pushd(target_dir):
            for f in self.source_files.keys():
                fp = os.path.join(target_dir, f)
                attrs = os.listxattr(path=fp, follow_symlinks=False)
                assert len(attrs) == self.xattr_pairs

                for k in self.source_xattrs[f].keys():
                    v = os.getxattr(fp, k.encode(self.encoding)).decode(self.encoding)
                    assert v == self.source_xattrs[f][k]
                attrs = os.listxattr(fp, follow_symlinks=False)
                if self.encoding != "gb2312":
                    for attr in attrs:
                        v = xattr.getxattr(f, attr)
                        assert attr in self.source_xattrs[f].keys()
                        assert v.decode(self.encoding) == self.source_xattrs[f][attr]

        with pushd(target_dir):
            for d in self.source_dirs.keys():
                dp = os.path.join(target_dir, d)
                attrs = xattr.listxattr(dp)
                assert len(attrs) == self.xattr_pairs
                for attr in attrs:
                    v = xattr.getxattr(d, attr)
                    assert attr in self.source_dirs_xattrs[d].keys()
                    assert v.decode(self.encoding) == self.source_dirs_xattrs[d][attr]


class SymlinkVerifier(Verifier):
    def __init__(self, target, dist: Distributor):
        super().__init__(target, dist)

    def scratch(self):
        # TODO: directory symlinks?
        self.dist.put_symlinks(140)
        self.dist.put_symlinks(24, chinese=True)

    def verify(self, target_dir, source_dir):
        for sl in self.dist.symlinks:
            vt = os.path.join(target_dir, sl)
            st = os.path.join(source_dir, sl)
            assert os.readlink(st) == os.readlink(vt)


class HardlinkVerifier(Verifier):
    def __init_(self, target, dist):
        super().__init__(target, dist)

    def scratch(self):
        self.dist.put_hardlinks(30)

        self.outer_source_name = "outer_source"
        self.inner_hardlink_name = "inner_hardlink"

        with pushd(os.path.dirname(os.path.realpath(self.dist.top_dir))):
            fd = os.open(self.outer_source_name, os.O_CREAT | os.O_RDWR)
            os.close(fd)

            os.link(
                self.outer_source_name,
                os.path.join(self.target, self.inner_hardlink_name),
            )

        assert (
            os.stat(os.path.join(self.target, self.inner_hardlink_name)).st_nlink == 2
        )

    def verify(self, target_dir, source_dir):
        for links in self.dist.hardlinks.values():
            try:
                links_iter = iter(links)
                l = next(links_iter)
            except StopIteration:
                continue
            t_hl_path = os.path.join(target_dir, l)
            last_md5 = WorkloadGen.calc_file_md5(t_hl_path)
            last_stat = os.stat(t_hl_path)
            last_path = t_hl_path

            for l in links_iter:
                t_hl_path = os.path.join(target_dir, l)

                t_hl_md5 = WorkloadGen.calc_file_md5(t_hl_path)
                t_hl_stat = os.stat(t_hl_path)
                assert last_md5 == t_hl_md5
                assert (
                    last_stat == t_hl_stat
                ), f"last hardlink path {last_path}, cur hardlink path {t_hl_path}"

                last_md5 = t_hl_md5
                last_stat = t_hl_stat
                last_path = t_hl_path

        with pushd(target_dir):
            assert (
                os.stat(os.path.join(target_dir, self.inner_hardlink_name)).st_nlink
                == 1
            )


class DirectoryVerifier(Verifier):
    pass


class FileModeVerifier(Verifier):
    pass


class UGIDVerifier(Verifier):
    pass


class SparseVerifier(Verifier):
    pass
