import utils
import os
import sys
from argparse import ArgumentParser


def collect_coverage(source_dir, target_dir, report):
    """
    Example:
        ./target/debug/ -s . -t lcov --llvm --branch --ignore-not-existing -o ./target/debug/coverage/
    """

    cmd = f"framework/bin/grcov {target_dir} -s {source_dir} -t html --llvm --branch \
--ignore-not-existing -o {report}/coverage_report"

    utils.execute(cmd, shell=True)


if __name__ == "__main__":

    parser = ArgumentParser()
    parser.add_argument("--source", help="path to source code", type=str)
    parser.add_argument("--target", help="path to build target directory", type=str)

    args = parser.parse_args()
    source = args.source
    target = args.target
    report = "."

    os.environ["RUSTFLAGS"] = "-Zinstrument-coverage"

    collect_coverage(source, target, report)
