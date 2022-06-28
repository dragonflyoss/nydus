from linux_command import LinuxCommand
import utils
import subprocess


class DdParam(LinuxCommand):
    def __init__(self, command_name):
        LinuxCommand.__init__(self, command_name)
        self.param_name_prefix = ""

    def bs(self, block_size):
        return self.set_param("bs", block_size)

    def input(self, input_file):
        return self.set_param("if", input_file)

    def output(self, output_file):
        return self.set_param("of", output_file)

    def count(self, count):
        return self.set_param("count", count)

    def iflag(self, iflag):
        return self.set_param("iflag", iflag)

    def skip(self, len):
        return self.set_param("skip", len)


class DD:
    """
    dd always tries to to copy the entire file.
    """

    def __init__(self):
        self.dd_params = DdParam("dd")

    def create_command(self):
        return self.dd_params

    def extend_command(self):
        return self.dd_params

    def __str__(self):
        return str(self.dd_params)

    def run(self):
        ret, _ = utils.run(
            str(self),
            verbose=False,
            wait=True,
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
        return ret
