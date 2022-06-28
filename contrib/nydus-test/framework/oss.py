import tempfile
from string import Template
import logging
import utils

OSS_CONFIG_TEMPLATE = """
[Credentials]
language=EN
endpoint=${endpoint}
accessKeyID=${ak}
accessKeySecret=${ak_secret}
"""


class OssHelper:
    def __init__(self, util, endpoint, bucket, ak_id, ak_secret, prefix=None):

        oss_conf = tempfile.NamedTemporaryFile(mode="w+", suffix="oss.conf")
        items = {
            "endpoint": endpoint,
            "ak": ak_id,
            "ak_secret": ak_secret,
        }
        template = Template(OSS_CONFIG_TEMPLATE)
        _s = template.substitute(**items)
        oss_conf.write(_s)
        oss_conf.flush()

        self.util = util
        self.bucket = bucket
        self.conf_wrapper = oss_conf
        self.conf_file = oss_conf.name
        self.prefix = prefix
        self.path = (
            f"oss://{self.bucket}/{self.prefix}"
            if self.prefix is not None
            else f"oss://{self.bucket}/"
        )

    def upload(self, src, dst, force=False):
        if not self.stat(dst) or force:
            cmd = [
                self.util,
                "--config-file",
                self.conf_file,
                "-f",
                "cp",
                src,
                f"{self.path}{dst}",
            ]
            ret, _ = utils.execute(cmd, print_output=True)
            assert ret
            if ret:
                logging.info("Object %s is uploaded", dst)

    def download(self, src, dst):
        cmd = [
            self.util,
            "--config-file",
            self.conf_file,
            "cp",
            "-f",
            f"{self.path}{src}",
            dst,
        ]
        ret, _ = utils.execute(cmd, print_cmd=True)
        if ret:
            logging.info("Download %s ", src)

    def rm(self, object):
        cmd = [
            self.util,
            "rm",
            "--config-file",
            self.conf_file,
            f"{self.path}{object}",
        ]
        ret, _ = utils.execute(cmd, print_cmd=True, print_output=False)
        assert ret
        if ret:
            logging.info("Object %s is removed from oss", object)

    def stat(self, object):
        cmd = [
            self.util,
            "--config-file",
            self.conf_file,
            "stat",
            f"{self.path}{object}",
        ]
        ret, _ = utils.execute(
            cmd, print_cmd=False, print_output=False, print_err=False
        )
        if ret:
            logging.info("Object %s already uploaded", object)
        else:
            logging.warning(
                "Object %s was not uploaded yet",
                object,
            )
        return ret

    def list(self):
        cmd = [self.util, "--config-file", self.conf_file, "ls", self.path]

        ret, out = utils.execute(cmd, print_cmd=True, print_output=True, print_err=True)
        print(out)
