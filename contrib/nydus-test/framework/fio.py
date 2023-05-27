import datetime
import utils
import json
import os
from types import SimpleNamespace as Namespace
from linux_command import LinuxCommand


class FioParam(LinuxCommand):
    def __init__(self, fio, command_name):
        LinuxCommand.__init__(self, command_name)
        self.fio = fio
        self.command_name = command_name

    def block_size(self, size):
        return self.set_param("blocksize", size)

    def direct(self, value: bool = True):
        return self.set_param("direct", value)

    def size(self, size):
        return self.set_param("size", size)

    def io_mode(self, io_mode):
        return self.set_param("io_mode", io_mode)

    def ioengine(self, engine):
        return self.set_param("ioengine", engine)

    def filename(self, filename):
        return self.set_param("filename", filename)

    def read_write(self, readwrite):
        return self.set_param("readwrite", readwrite)

    def iodepth(self, iodepth):
        return self.set_param("iodepth", iodepth)

    def numjobs(self, jobs):
        self.set_flags("group_reporting")
        return self.set_param("numjobs", jobs)


class Fio:
    def __init__(self):
        self.jobs = []
        self.base_cmd_params = FioParam(self, "fio")
        self.global_cmd_params = FioParam(self, "fio")

    def create_command(self, *pattern):
        self.global_cmd_params.set_flags("group_reporting")
        p = "_".join(pattern)
        try:
            os.mkdir("benchmark_reports")
        except FileExistsError:
            pass

        self.fio_report_file = os.path.join(
            "benchmark_reports",
            f'fio_run_{p}_{datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%s")}',
        )

        self.base_cmd_params.set_param("output-format", "json").set_param(
            "output", self.fio_report_file
        )

        return self.global_cmd_params

    def expand_command(self):
        return self.global_cmd_params

    def __str__(self):
        fio_prams = FioParam(self, "fio")
        fio_prams.command_param_dict.update(self.base_cmd_params.command_param_dict)
        fio_prams.command_param_dict.update(self.global_cmd_params.command_param_dict)
        fio_prams.command_flags.extend(self.global_cmd_params.command_flags)
        fio_prams.set_param("name", "fio")
        command = str(fio_prams)
        return command

    def run(self):
        ret, _ = utils.run(
            str(self),
            wait=True,
            shell=True,
        )
        assert ret == 0

    def get_result(self, title_line, *keys):
        with open(self.fio_report_file) as f:
            data = json.load(f, object_hook=lambda d: Namespace(**d))

        if hasattr(data, "jobs"):
            jobs = data.jobs
            assert len(jobs) == 1
            job = jobs[0]
            print("")

            result = f"""
            {title_line}
            block size:         {getattr(data, 'global options').bs}
            direct:             {getattr(data, 'global options').direct}
            ioengine:           {getattr(data, 'global options').ioengine}
            runtime:            {job.read.runtime}
            iops:               {job.read.iops}
            bw(KB/S):           {job.read.bw}
            latency/ms:         min:{job.read.lat_ns.min/1e6}, max: {job.read.lat_ns.max/1e3}, mean: {job.read.lat_ns.mean/1e6}
            """
            print(result)

            return result
