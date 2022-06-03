import multiprocessing
import os
import random
import threading
from stat import *
from utils import logging_setup, Unit, Size, pushd, dump_process_mem_cpu_load
import logging
import datetime
import hashlib
import time
import io
import threading
import multiprocessing
from multiprocessing import Queue, current_process
import stat


def get_current_time():
    return datetime.datetime.now()


def rate_limit(interval_rate):
    last = datetime.datetime.now()

    def inner(func):
        def wrapped(*args):
            nonlocal last
            if (datetime.datetime.now() - last).seconds > interval_rate:
                func(*args)
                last = datetime.datetime.now()

        return wrapped

    return inner


@rate_limit(interval_rate=5)
def dump_status(name, cnt):
    logging.info("Process %d - %s verified %lu files", os.getpid(), name, cnt)


size_list = [
    1,
    8,
    13,
    16,
    19,
    32,
    64,
    101,
    100,
    102,
    100,
    256,
    Size(4, Unit.KB).B,
    Size(7, Unit.KB).B,
    Size(8, Unit.KB).B,
    Size(16, Unit.KB).B,
    Size(17, Unit.KB).B,
    Size(1, Unit.MB).B - 100,
    Size(1, Unit.MB).B,
    Size(3, Unit.MB).B - Size(2, Unit.KB).B,
    Size(3, Unit.MB).B,
    Size(4, Unit.MB).B,
]


class WorkloadGen:
    def __init__(self, target_dir, verify_dir):
        """
        :target_dir: Generate IO against which directory
        :verify_dir: Generally, it has to be the original rootfs of the test image
        """
        self.target_dir = target_dir
        self.verify_dir = verify_dir
        self.verify = True
        self.io_error = False
        self.verifier = {}  # For append write verification
        logging.info(
            "Target dir: %s, Verified dir: %s", self.target_dir, self.verify_dir
        )

    def collect_all_dirs(self):
        # In case this function is called more than once.
        if hasattr(self, "collected"):
            return
        self.collected = True
        self._collected_dirs = []
        self._collected_dirs.append(self.target_dir)
        with pushd(self.target_dir):
            self._collect_each_dir(self.target_dir, self.target_dir)

    def _collect_each_dir(self, root_dir, parent_dir):
        files = os.listdir(parent_dir)
        with pushd(parent_dir):
            for one in files:
                st = os.lstat(one)
                if S_ISDIR(st.st_mode) and len(os.listdir(one)) != 0:
                    realpath = os.path.realpath(one)
                    self._collected_dirs.append(realpath)
                    self._collect_each_dir(root_dir, one)
                else:
                    continue

    def iter_all_files(self, file_op, dir_op=None):
        for (cur_dir, subdirs, files) in os.walk(
            self.target_dir, topdown=True, followlinks=False
        ):
            with pushd(cur_dir):
                for f in files:
                    file_op(f)

                if dir_op is not None:
                    for d in subdirs:
                        dir_op(d)

    def verify_single_file(self, path_from_mp):
        target_md5 = WorkloadGen.calc_file_md5(path_from_mp)
        # Locate where the source file is, so to calculate its md5 which
        # will be verified later
        source_path = os.path.join(
            self.verify_dir, os.path.relpath(path_from_mp, start=self.target_dir)
        )
        source_md5 = WorkloadGen.calc_file_md5(source_path)
        assert (
            target_md5 == source_md5
        ), f"Verification error. Want {source_md5} but got {target_md5}"

    @staticmethod
    def count_files(top_dir):
        """
        Including hidden files and directories.
        Just count files within `top_dir` whether it's oci special file or not.
        """
        total = 0
        for (cur_dir, subdirs, files) in os.walk(
            top_dir, topdown=True, followlinks=False
        ):
            total += len(files)
            total += len(subdirs)

        logging.info("%d is counted!", total)
        return total

    @staticmethod
    def calc_file_md5(path):
        md5 = hashlib.md5()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(Size(128, Unit.KB).B), b""):
                md5.update(block)

        return md5.digest()

    def __verify_one_level(self, path_queue, conn):
        target_files = []
        cnt = 0
        err_cnt = 0
        name = current_process().name
        while True:
            # In higher version of python, multiprocess queue can be noticed when it is closed.
            # Then we don't have to wait for timeout
            try:
                (abs_dir, dirs, files) = path_queue.get(timeout=3)
            except Exception as exc:
                logging.info("Verify process %s finished.", name)
                conn.send((target_files, cnt, err_cnt))
                return

            dump_status(name, cnt)
            sub_dir_count = 0
            for f in files:
                # Per as to OCI image spec, whiteout special file should be present.
                # TODO: uncomment me!
                assert not f.startswith(".wh.")
                # don't try to validate symlink
                cur_path = os.path.join(abs_dir, f)
                relpath = os.path.relpath(cur_path, start=self.target_dir)
                target_files.append(relpath)
                source_path = os.path.join(self.verify_dir, relpath)

                if os.path.islink(cur_path):
                    if os.readlink(cur_path) != os.readlink(source_path):
                        err_cnt += 1
                        logging.error("Symlink mismatch, %s", cur_path)
                elif os.path.isfile(cur_path):
                    # TODO: How to verify special files?
                    cur_md5 = WorkloadGen.calc_file_md5(cur_path)
                    source_md5 = WorkloadGen.calc_file_md5(source_path)
                    if cur_md5 != source_md5:
                        err_cnt += 1
                        logging.error("Verification error. File %s", cur_path)
                        assert False
                elif stat.S_ISBLK(os.stat(cur_path).st_mode):
                    assert os.stat(cur_path).st_rdev == os.stat(source_path).st_rdev
                elif stat.S_ISCHR(os.stat(cur_path).st_mode):
                    assert os.stat(cur_path).st_rdev == os.stat(source_path).st_rdev
                elif stat.S_ISFIFO(os.stat(cur_path).st_mode):
                    pass
                elif stat.S_ISSOCK(os.stat(cur_path).st_mode):
                    pass

                cnt += 1

            for d in dirs:
                assert not d.startswith(".wh.")
                cur_path = os.path.join(abs_dir, d)
                relpath = os.path.relpath(cur_path, start=self.target_dir)
                target_files.append(relpath)

                # Directory nlink should equal to 2 + amount of child direcotory
                if not os.path.islink(cur_path):
                    sub_dir_count += 1

            assert sub_dir_count + 2 == os.stat(abs_dir).st_nlink

    def verify_entire_fs(self, filter_list: list = []) -> bool:
        cnt = 0
        err_cnt = 0
        target_files = set()

        processes = []
        # There is underlying threads transfering objects. Set its size smaller so
        # there will not be many error printed once the side of the queue is closed.
        path_queue = Queue(20)

        for i in range(8):
            (parent_conn, child_conn) = multiprocessing.Pipe(False)
            p = multiprocessing.Process(
                name=f"verifier_{i}",
                target=self.__verify_one_level,
                args=(path_queue, child_conn),
            )
            p.start()
            processes.append((p, parent_conn))

        for (abs_dir, dirs, files) in os.walk(self.target_dir, topdown=True):
            try:
                path_queue.put((abs_dir, dirs, files))
            except Exception:
                return False

        for (p, conn) in processes:
            try:
                (child_files, child_cnt, child_err_cnt) = conn.recv()
            except EOFError:
                logging.error("EOF")
                return False
            p.join()
            target_files.update(child_files)
            cnt += child_cnt
            err_cnt += child_err_cnt

        path_queue.close()
        path_queue.join_thread()
        del path_queue

        logging.info("Verified %u files in %s", cnt, self.target_dir)

        if err_cnt > 0:
            logging.error("Verify fails, %u errors", err_cnt)
            return False

        # Collect files belonging to the original rootfs  into `source_files`.
        # Criteria is that each file in `source_files` should appear in the rafs.
        source_files = set()
        opaque_dirs = []
        for (abs_dir, dirs, files) in os.walk(self.verify_dir):
            for f in files:
                cur_path = os.path.join(abs_dir, f)

                relpath = os.path.relpath(cur_path, start=self.verify_dir)
                source_files.add(relpath)
                if f == ".wh..wh..opq":
                    opaque_dirs.append(os.path.relpath(abs_dir, start=self.verify_dir))

            for d in dirs:
                cur_path = os.path.join(abs_dir, d)
                relpath = os.path.relpath(cur_path, start=self.verify_dir)
                source_files.add(relpath)

        diff_files = list()

        for el in source_files:
            if not el in target_files:
                diff_files.append(el)

        trimmed_diff_files = []
        whiteout_files = [
            (
                os.path.basename(f),
                os.path.join(
                    os.path.dirname(f), os.path.basename(f).replace(".wh.", "", 1)
                ),
            )
            for f in diff_files
            if os.path.basename(f).startswith(".wh.")
        ]

        # The only possible reason we have different files is due to whiteout
        for suspect in diff_files:
            for d in opaque_dirs:
                if suspect.startswith(d):
                    trimmed_diff_files.append(suspect)
                    continue

            # Seems overlay fs does not hide the opaque special file(char) if nothing to whiteout
            try:
                # Example: c????????? ? ? ? ?            ? foo
                with open(os.path.join(self.verify_dir, suspect), "rb") as f:
                    pass
            except OSError as e:
                if e.errno == 2:
                    trimmed_diff_files.append(suspect)
                else:
                    pass

            # For example:
            # ['DIR.0.0/pQGLzKTWSpaCatjcwAqiZAGOxbfexiOvVsXqFqUhldTxLsIpONVnavybHObiCZepXsLyoPwDAXOoDtJFdZVUlrisTDaenJhsJVXegHuTMzFFqhowZAfcgggxVfEvXDtAVakarhSkZhavBtuuTFPOqgyowbI.regular',
            # 'DIR.0.0/.wh.pQGLzKTWSpaCatjcwAqiZAGOxbfexiOvVsXqFqUhldTxLsIpONVnavybHObiCZepXsLyoPwDAXOoDtJFdZVUlrisTDaenJhsJVXegHuTMzFFqhowZAfcgggxVfEvXDtAVakarhSkZhavBtuuTFPOqgyowbI.regular',
            # 'DIR.0.0/DIR.1.1/DIR.2.0/zktaNKmXMVgITVbAUFHpNfvECfVIdO.dir', 'DIR.0.0/DIR.1.1/DIR.2.0/.wh.zktaNKmXMVgITVbAUFHpNfvECfVIdO.dir', 'i/am/troublemaker/.wh.foo']
            if len(whiteout_files):
                base = os.path.basename(suspect)
                if f".wh.{base}" in list(zip(*whiteout_files))[0]:
                    trimmed_diff_files.append(suspect)

                for (_, s) in whiteout_files:
                    if suspect.startswith(s):
                        trimmed_diff_files.append(suspect)

        diff_files = list(
            filter(
                lambda x: x not in trimmed_diff_files
                and x not in filter_list
                and not os.path.basename(x).startswith(".wh."),
                diff_files,
            )
        )

        assert len(diff_files) == 0, print(diff_files)
        return True

    def read_collected_files(self, duration):
        """
        Randomly select a file from a random direcotry which was collected
        when set up this workload generator. No dir recursive read happens.
        """
        dirs_cnt = len(self._collected_dirs)
        logging.info("Total %u directories will be have stress read", dirs_cnt)
        t_begin = get_current_time()
        t_delta = t_begin - t_begin

        op_cnt, total_size = 0, 0

        while t_delta.total_seconds() <= duration:
            target_dir = random.choice(self._collected_dirs)
            files = os.listdir(target_dir)
            target_file = random.choice(files)
            one_path = os.path.join(target_dir, target_file)

            if os.path.isdir(one_path):
                os.listdir(one_path)
                continue

            if os.path.islink(one_path):
                # Don't expect anything broken happen.
                os.readlink(one_path)
                # Symlink might be broken, then skip to read from it.
                if not os.path.exists(one_path):
                    continue

            if not os.path.isfile(one_path):
                continue

            with open(one_path, "rb") as f:
                st = os.stat(one_path)
                file_size = st.st_size

                do_read = True

                while do_read:
                    # Select a file position randomly
                    pos = random.randint(0, file_size)
                    try:
                        f.seek(pos)
                    except io.UnsupportedOperation as exc:
                        logging.exception(exc)
                        break
                    except Exception as exc:
                        raise type(exc)(
                            str(exc)
                            + f"Seek pos {pos}, file {one_path}, file size {file_size}"
                        )

                    io_size = WorkloadGen.pick_io_size()
                    logging.debug(
                        "File %s" % target_file, "Pos %u" % pos, "IO Size %u" % io_size
                    )
                    op_cnt += 1
                    total_size += io_size

                    try:
                        buf = f.read(io_size)
                        assert io_size == len(buf) or file_size - pos == len(buf)
                    except IOError as exc:
                        logging.error(
                            "file %s, offset %u, io size %u", one_path, pos, io_size
                        )
                        raise exc

                    if random.randint(0, 13) % 4 == 0:
                        do_read = False

                    if self.verify:
                        self.verify_file_range(one_path, pos, io_size, buf)

            t_delta = get_current_time() - t_begin

        return op_cnt, total_size, t_delta.total_seconds()

    def verify_file_range(self, file_path, offset, length, buf):
        relpath = os.path.relpath(file_path, start=self.target_dir)
        file_path = os.path.join(self.verify_dir, relpath)
        with open(file_path, "rb") as f:
            f.seek(offset)
            out = f.read(length)

            orig_md5 = hashlib.md5(out).digest()
            buf_md5 = hashlib.md5(buf).digest()

            if orig_md5 != buf_md5:
                logging.error(
                    "File Verification error. path: %s offset: %lu len: %u. want %s but got %s",
                    file_path,
                    offset,
                    length,
                    str(orig_md5),
                    str(buf_md5),
                )
                raise Exception(
                    f"Verification error {file_path} {offset} {length} failed."
                )

    def io_read(self, io_duration, conn=None):
        try:
            cnt, size, duration = self.read_collected_files(io_duration)
            WorkloadGen.print_summary(cnt, size, duration)
        except Exception as exc:
            logging.exception("Stress read failure, %s", exc)
            self.io_error = True
        finally:
            if conn is not None:
                conn.send(self.io_error)
                conn.close()

    def setup_workload_generator(self):
        self.collect_all_dirs()

    def torture_read(self, threads_cnt: int, duration: int, verify=True):
        readers_list = []
        self.verify = verify
        for idx in range(0, threads_cnt):
            reader_name = "rafs_reader_%d" % idx
            (parent_conn, child_conn) = multiprocessing.Pipe(False)
            rafs_reader = multiprocessing.Process(
                name=reader_name,
                target=self.io_read,
                args=(duration, child_conn),
            )

            logging.info("Reader %s starts work" % reader_name)
            readers_list.append((rafs_reader, parent_conn))
            rafs_reader.start()

        self.readers = readers_list

    def finish_torture_read(self):
        for one in self.readers:
            self.io_error = one[1].recv() or self.io_error
            one[0].join()

        if self.verify:
            assert not self.io_error
        self.stop_load_monitor()

    @classmethod
    def print_summary(cls, cnt, size, duration):
        logging.info(
            "Issued reads: %(cnt)lu Total read size: %(size)lu bytes Time duration: %(duration)u"
            % {"cnt": cnt, "size": size, "duration": duration}
        )

    @staticmethod
    def pick_io_size():
        return random.choice(size_list)

    @staticmethod
    def issue_single_write(file_name, offset, bs: Size, size: Size):
        """
        :size: Amount of data to be written to
        :bs: Each write io block size
        :offset: From which offset of the file to star write
        """
        block = os.urandom(bs.B)
        left = size.B

        fd = os.open(file_name, os.O_RDWR)
        while left > 0:
            os.pwrite(fd, block, offset + size.B - left)
            left -= bs.B

        os.close(fd)

    @staticmethod
    def issue_single_read(dir, file_name, offset: Size, bs: Size):
        with pushd(dir):
            with open(file_name, "rb") as f:
                buf = os.pread(f.fileno(), bs.B, offset.B)
                return buf

    def start_load_monitor(self, pid):
        def _dump_mem_info(anchor, pid):
            while not self.monitor_stopped:
                dump_process_mem_cpu_load(pid)
                time.sleep(2)

        self.load_monitor = threading.Thread(
            name="load_monitor", target=_dump_mem_info, args=(self, pid)
        )
        self.monitor_stopped = False
        self.load_monitor.start()

    def stop_load_monitor(self):
        if "load_monitor" in self.__dict__:
            self.monitor_stopped = True
            self.load_monitor.join()


if __name__ == "__main__":
    print("This is workload generator")
    with open("append_test", "a") as f:
        wg = WorkloadGen(None, None)
        wg.do_append(f.fileno(), Size(1, Unit.KB), Size(16, Unit.KB))

    wg = WorkloadGen(".", None)

    wg.torture_append(2, Size(1, Unit.KB), Size(16, Unit.MB))
    wg.finish_torture_append()
