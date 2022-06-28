from utils import pushd
import os
import shutil
import xattr
import stat
import enum


class WhiteoutSpec(enum.Enum):
    OCI = "oci"
    OVERLAY = "overlayfs"

    def get_value(self):
        return self.value

    def __str__(self) -> str:
        return self.get_value()


class Whiteout:
    opaque_dir_key = "trusted.overlay.opaque".encode()
    opaque_dir_value = "y".encode()

    def __init__(self, spec=WhiteoutSpec.OCI) -> None:
        super().__init__()
        self.spec = spec

    @staticmethod
    def mirror_fs_structure(top, path):
        """
        :top: Target dir into which to construct mirrored tree.
        "path: Should be a relative path like `a/b/c`
        So this function creates directories recursively until reaching to the last component.
        Moreover, call should be responsible for creating the target file or directory.
        """
        path = os.path.normpath(path)
        dir_path = ""
        with pushd(top):
            for d in path.split("/")[:-1]:
                try:
                    os.chdir(d)
                except FileNotFoundError:
                    if len(d) == 0:
                        continue
                    os.mkdir(d)
                    os.chdir(d)
                finally:
                    dir_path += d + "/"

        return dir_path, path.split("/")[-1]

    @staticmethod
    def mirror_files(files, original_rootfs, target_rootfs):
        """
        files paths relative to rootfs, e.g.
            foo/bar/f
        """
        for f in files:
            mirrored_path, name = Whiteout.mirror_fs_structure(target_rootfs, f)
            src_path = os.path.join(original_rootfs, f)
            dst_path = os.path.join(target_rootfs, mirrored_path, name)
            shutil.copyfile(src_path, dst_path, follow_symlinks=False)

    def whiteout_one_file(self, top, lower_relpath):
        """
        :top: The top root directory from which to mirror from lower relative path.
        :lower_relpath: Should look like `a/b/c` and this function puts `{top}/a/b/.wh.c` into upper layer
        """
        whiteout_file_parent, whiteout_file = Whiteout.mirror_fs_structure(
            top, lower_relpath
        )
        if self.spec == WhiteoutSpec.OCI:
            f = os.open(
                os.path.join(top, whiteout_file_parent, f".wh.{whiteout_file}"),
                os.O_CREAT,
            )
            os.close(f)
        elif self.spec == WhiteoutSpec.OVERLAY:
            d = os.path.join(top, whiteout_file_parent, whiteout_file)
            os.mknod(
                d,
                0o644 | stat.S_IFCHR,
                0,
            )
            # Whitout a regular does not need such xattr pair, but it's a naughty monkey
            xattr.setxattr(d, self.opaque_dir_key, self.opaque_dir_value)

    def whiteout_opaque_directory(self, top, lower_relpath):
        upper_opaque_dir = os.path.join(top, lower_relpath)
        if self.spec == WhiteoutSpec.OCI:
            os.makedirs(upper_opaque_dir, exist_ok=True)
            f = os.open(os.path.join(upper_opaque_dir, ".wh..wh..opq"), os.O_CREAT)
            os.close(f)
        elif self.spec == WhiteoutSpec.OVERLAY:
            os.makedirs(upper_opaque_dir, exist_ok=True)
            xattr.setxattr(upper_opaque_dir, self.opaque_dir_key, self.opaque_dir_value)

    def whiteout_one_dir(self, top, lower_relpath):
        whiteout_dir_parent, whiteout_dir = Whiteout.mirror_fs_structure(
            top, lower_relpath
        )
        if self.spec == WhiteoutSpec.OCI:
            os.makedirs(os.path.join(top, whiteout_dir_parent, f".wh.{whiteout_dir}"))
        elif self.spec == WhiteoutSpec.OVERLAY:
            d = os.path.join(top, whiteout_dir_parent, whiteout_dir)
            os.mknod(
                d,
                0o644 | stat.S_IFCHR,
                0,
            )
            # Whitout a direcotoy does not need such xattr pair, but it's a naughty monkey
            xattr.setxattr(d, self.opaque_dir_key, self.opaque_dir_value)
            xattr.setxattr(d, "trusted.nydus.opaque", "y".encode())
