#!/usr/bin/env python3

import csv
import subprocess
from argparse import ArgumentParser

COMMANDS_BENCHMARK = [
    "sudo install -m 755 benchmark-oci/wordpress.csv oci.csv",
    "sudo install -m 755 benchmark-nydus-all-prefetch/wordpress.csv nydus-all-prefetch.csv",
    "sudo install -m 755 benchmark-nydus-no-prefetch/wordpress.csv nydus-no-prefetch.csv",
    "sudo install -m 755 benchmark-zran-all-prefetch/wordpress.csv zran-all-prefetch.csv",
    "sudo install -m 755 benchmark-zran-no-prefetch/wordpress.csv zran-no-prefetch.csv",
    "sudo install -m 755 benchmark-nydus-filelist-prefetch/wordpress.csv nydus-filelist-prefetch.csv"
]

COMMANDS_BENCHMARK_COMPARE = [
    "sudo install -m 755 benchmark-zran-all-prefetch-master/wordpress.csv zran-all-prefetch-master.csv",
    "sudo install -m 755 benchmark-zran-no-prefetch-master/wordpress.csv zran-no-prefetch-master.csv",
    "sudo install -m 755 benchmark-nydus-no-prefetch-master/wordpress.csv nydus-no-prefetch-master.csv",
    "sudo install -m 755 benchmark-nydus-all-prefetch-master/wordpress.csv nydus-all-prefetch-master.csv",
    "sudo install -m 755 benchmark-nydus-filelist-prefetch-master/wordpress.csv nydus-filelist-prefetch-master.csv"
]

FILE_LIST = [
    "oci.csv",
    "nydus-all-prefetch.csv",
    "zran-all-prefetch.csv",
    "nydus-no-prefetch.csv",
    "zran-no-prefetch.csv",
    "nydus-filelist-prefetch.csv"
]

FILE_LIST_COMPARE = [
    "oci.csv",
    "nydus-all-prefetch-master.csv",
    "nydus-all-prefetch.csv",
    "zran-all-prefetch-master.csv",
    "zran-all-prefetch.csv",
    "nydus-no-prefetch-master.csv",
    "nydus-no-prefetch.csv",
    "zran-no-prefetch-master.csv",
    "zran-no-prefetch.csv",
    "nydus-filelist-prefetch-master.csv",
    "nydus-filelist-prefetch.csv"
]


class BenchmarkSummary:
    def __init__(self, mode):
        self.mode = mode

    def summary(self):
        self.prepare_csv()
        print("| bench-result | pull-elapsed(s) | create-elapsed(s) | run-elapsed(s) | total-elapsed(s) | image-size(MB) | read-amount(MB) | read-count |")
        print("|:-------------|:---------------:|:-----------------:|:--------------:|:----------------:|:--------------:|:---------------:|:----------:|")
        if self.mode == "benchmark-result":
            self.print_csv_result()
        else:
            self.print_csv_compare()

    def print_csv_result(self):
        for file in FILE_LIST:
            print_csv(file)

    def print_csv_compare(self):
        for file in FILE_LIST_COMPARE:
            print_csv(file)

    def prepare_csv(self):
        """
            move the csv to current workdir
        """
        for cmd in COMMANDS_BENCHMARK:
            subprocess.run(cmd, shell=True)
        if self.mode == "benchmark-compare":
            for cmd in COMMANDS_BENCHMARK_COMPARE:
                subprocess.run(cmd, shell=True)


def print_csv(file: str):
    with open(file, 'r', newline='') as f:
        filename = file.rstrip(".csv")
        rows = csv.reader(f)
        for row in rows:
            pull_elapsed, create_elapsed, run_elapsed, total_elapsed, image_size, read_amount, read_count = row
            print(f"|{filename}|{pull_elapsed}|{create_elapsed}|{run_elapsed}|{total_elapsed}|{image_size}|{read_amount}|{read_count}|")


def main():
    parser = ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=["benchmark-result", "benchmark-compare"],
        dest="mode",
        type=str,
        required=True,
        help="The mode of benchmark summary"
    )
    args = parser.parse_args()
    mode = args.mode
    BenchmarkSummary(mode=mode).summary()


if __name__ == "__main__":
    main()
