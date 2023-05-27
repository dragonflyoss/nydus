#!/usr/bin/env python3

import csv
import os
import subprocess
from argparse import ArgumentParser

COMMANDS_BENCHMARK = [
    "sudo install -m 755 benchmark-oci/*.csv oci.csv",
    "sudo install -m 755 benchmark-nydus-all-prefetch/*.csv nydus-all-prefetch.csv",
    "sudo install -m 755 benchmark-nydus-no-prefetch/*.csv nydus-no-prefetch.csv",
    "sudo install -m 755 benchmark-zran-all-prefetch/*.csv zran-all-prefetch.csv",
    "sudo install -m 755 benchmark-zran-no-prefetch/*.csv zran-no-prefetch.csv",
    "sudo install -m 755 benchmark-nydus-filelist-prefetch/*.csv nydus-filelist-prefetch.csv"
]

COMMANDS_BENCHMARK_COMPARE = [
    "sudo install -m 755 benchmark-zran-all-prefetch-master/*.csv zran-all-prefetch-master.csv",
    "sudo install -m 755 benchmark-zran-no-prefetch-master/*.csv zran-no-prefetch-master.csv",
    "sudo install -m 755 benchmark-nydus-no-prefetch-master/*.csv nydus-no-prefetch-master.csv",
    "sudo install -m 755 benchmark-nydus-all-prefetch-master/*.csv nydus-all-prefetch-master.csv",
    "sudo install -m 755 benchmark-nydus-filelist-prefetch-master/*.csv nydus-filelist-prefetch-master.csv"
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
    ("nydus-all-prefetch-master.csv", "nydus-all-prefetch.csv"),
    ("zran-all-prefetch-master.csv", "zran-all-prefetch.csv"),
    ("nydus-no-prefetch-master.csv", "nydus-no-prefetch.csv"),
    ("zran-no-prefetch-master.csv", "zran-no-prefetch.csv"),
    ("nydus-filelist-prefetch-master.csv", "nydus-filelist-prefetch.csv")
]

BENCHMARK_CACHE = "benchmark-result/result.md"


class BenchmarkSummary:
    def __init__(self, mode):
        self.mode = mode

    def summary(self):
        self.prepare_csv()
        if self.mode == "benchmark-result":
            self.print_csv_result()
        elif self.mode == "benchmark-compare":
            self.print_csv_compare()
        else:
            self.print_csv_schedule()

    def print_csv_result(self):
        print("| bench-result | pull(s) | create(s) | run(s) | total(s) | size(MB) | read-amount(MB) | read-count |")
        print("|:-------------|:-------:|:---------:|:------:|:--------:|:--------:|:---------------:|:----------:|")
        for file in FILE_LIST:
            print_csv(file)

    def print_csv_compare(self):
        print("| bench-result(current vs master) | pull(s) | create(s) | run(s) | total(s) | size(MB) | read-amount(MB) | read-count |")
        print("|:--------------------------------|:-------:|:---------:|:------:|:--------:|:--------:|:---------------:|:----------:|")
        for item in FILE_LIST_COMPARE:
            if isinstance(item, str):
                print_csv(item)
            else:
                print_compare(item[0], item[1])

    def print_csv_schedule(self):
        data = []
        if os.path.exists(BENCHMARK_CACHE):
            print("| bench-result(current vs last) | pull(s) | create(s) | run(s) | total(s) | size(MB) | read-amount(MB) | read-count |")
            print("|:------------------------------|:-------:|:---------:|:------:|:--------:|:--------:|:---------------:|:----------:|")
            with open(BENCHMARK_CACHE, "r", newline='') as f:
                reader = csv.reader(f, delimiter='|')
                next(reader)  # head
                next(reader)  # line
                next(reader)  # oci
                for row in reader:
                    data.append(row[2:-1])
            for index, file in enumerate(FILE_LIST):
                if (file == "oci.csv"):
                    print_schedule(file)
                else:
                    print_schedule(file, data[index-1])
        else:
            self.print_csv_result()
        self.save_cache()

    def prepare_csv(self):
        """
            move the csv to current workdir
        """
        for cmd in COMMANDS_BENCHMARK:
            subprocess.run(cmd, shell=True)
        if self.mode == "benchmark-compare":
            for cmd in COMMANDS_BENCHMARK_COMPARE:
                subprocess.run(cmd, shell=True)

    def save_cache(self):
        with open(BENCHMARK_CACHE, 'w') as cache:
            print("| bench-result | pull(s) | create(s) | run(s) | total(s) | size(MB) | read-amount(MB) | read-count |", file=cache)
            print("|:-------------|:-------:|:---------:|:------:|:--------:|:--------:|:---------------:|:----------:|", file=cache)
            for file in FILE_LIST:
                with open(file, 'r') as f:
                    filename = file.rstrip(".csv")
                    rows = csv.reader(f)
                    for row in rows:
                        pull_elapsed, create_elapsed, run_elapsed, total_elapsed, image_size, read_amount, read_count = row
                        print(f"|{filename}|{pull_elapsed}|{create_elapsed}|{run_elapsed}|{total_elapsed}|{image_size}|{read_amount}|{read_count}|", file=cache)


def print_csv(file: str):
    with open(file, 'r', newline='') as f:
        filename = file.rstrip(".csv")
        rows = csv.reader(f)
        for row in rows:
            pull_elapsed, create_elapsed, run_elapsed, total_elapsed, image_size, read_amount, read_count = row
            print(f"|{filename}|{pull_elapsed}|{create_elapsed}|{run_elapsed}|{total_elapsed}|{image_size}|{read_amount}|{read_count}|")


def print_compare(file_master: str, file: str):
    with open(file, 'r', newline='') as f:
        filename = file.rstrip(".csv")
        rows = csv.reader(f)
        for row in rows:
            pull_elapsed, create_elapsed, run_elapsed, total_elapsed, image_size, read_amount, read_count = row
    with open(file_master, 'r', newline='') as f:
        rows = csv.reader(f)
        for row in rows:
            pull_elapsed_master, create_elapsed_master, run_elapsed_master, total_elapsed_master, image_size_master, read_amount_master, read_count_master = row
    pull_elapsed_compare = compare(pull_elapsed, pull_elapsed_master)
    create_elapsed_compare = compare(create_elapsed, create_elapsed_master)
    run_elapsed_compare = compare(run_elapsed, run_elapsed_master)
    total_elapsed_compare = compare(total_elapsed, total_elapsed_master, True)
    image_size_compare = compare(image_size, image_size_master, True)
    read_amount_compare = compare(read_amount, read_amount_master, True)
    read_count_compare = compare(read_count, read_count_master, True)

    print(f"|{filename}|{pull_elapsed_compare}|{create_elapsed_compare}|{run_elapsed_compare}|{total_elapsed_compare}|{image_size_compare}|{read_amount_compare}|{read_count_compare}|")


def print_schedule(file: str, data=[]):
    with open(file, 'r', newline='') as f:
        filename = file.rstrip(".csv")
        rows = csv.reader(f)
        for row in rows:
            pull_elapsed, create_elapsed, run_elapsed, total_elapsed, image_size, read_amount, read_count = row
            if filename != "oci":
                pull_elapsed = compare(pull_elapsed, data[0])
                create_elapsed = compare(create_elapsed, data[1])
                run_elapsed = compare(run_elapsed, data[2])
                total_elapsed = compare(total_elapsed, data[3], True)
                image_size = compare(image_size, data[4], True)
                read_amount = compare(read_amount, data[5], True)
                read_count = compare(read_count, data[6], True)

            print(f"|{filename}|{pull_elapsed}|{create_elapsed}|{run_elapsed}|{total_elapsed}|{image_size}|{read_amount}|{read_count}|")


def compare(data_current: str, data_master: str, compare: bool = False) -> str:
    data_current = float(data_current)
    data_master = float(data_master)
    if abs(data_current - data_master) > data_master * 0.05 and compare:
        if data_current > data_master:
            return f"{data_current}/{data_master}↑"
        else:
            return f"{data_current}/{data_master}↓"
    return f"{data_current}/{data_master}"


def main():
    parser = ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=["benchmark-result", "benchmark-compare", "benchmark-schedule"],
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
