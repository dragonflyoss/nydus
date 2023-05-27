from os import PathLike
import utils


class BackendProxy:
    def __init__(self, anchor, blobs_dir: PathLike, bin:PathLike):
        self.__blobs_dir = blobs_dir
        self.bin = bin
        self.anchor = anchor

    def start(self):
        _, self.p = utils.run(
            [self.bin, "-b", self.blobs_dir()],
            wait=False,
            stdout=self.anchor.logging_file,
            stderr=self.anchor.logging_file,
        )

    def stop(self):
        self.p.terminate()
        self.p.wait()

    def blobs_dir(self):
        return self.__blobs_dir
