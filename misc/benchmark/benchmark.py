#!/usr/bin/env python3
from argparse import ArgumentParser

import bench as bench
import convert as cvt
import metrics
import prefetch_list as alg
import util
import yaml

CONFIG = "config.yml"
PREFETCH_FILE_LIST = "out_list.txt"


def main():
    """
    1. read config file to knows the images:tag and registry and if we need convert to nydus image or not
    2. we have four modes for benchmark, the first is oci, the second is nydus without prefetch, the third is nydus with prefetch all, the latest is nydus with prefetch file list
    """
    parser = ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=["oci", "nydus-no-prefetch", "nydus-all-prefetch", "nydus-filelist-prefetch"],
        dest="mode",
        type=str,
        required=True,
        help="The mode of benchmark. Available modes are: oci, nydus-none_prefetch, nydus-all-prefetch, nydus-filelist-prefetch."
    )
    args = parser.parse_args()
    mode = args.mode

    # read config.yml
    cfg = {}
    with open(CONFIG, 'r', encoding='utf-8') as f:
        try:
            cfg = yaml.load(stream=f, Loader=yaml.FullLoader)
        except Exception as inst:
            print('error reading config file')
            print(inst)
            exit(-1)
    # bench
    start_bench(cfg, cfg["image"], mode)

def collect_metrics(cfg: dict, image: str) -> str:
    """
    collect container access metrics
    """
    return metrics.collect_access(cfg["local_registry"], cfg["insecure_local_registry"], util.image_nydus(image))


def start_bench(cfg: dict, image: str, mode: str):
    """
    bench oci, nydus without prefetch, nydus with all prefetch, nydus witch prefetch file list
    """
    f = open(util.image_repo(image) + ".csv", "w")
    csv_headers = "repo,pull_elapsed(s),create_elapsed(s),run_elapsed(s),total_elapsed(s),read_amount(MB),read_count"
    f.writelines(csv_headers + "\n")
    f.flush()
    if mode == "oci":
        util.enable_wondersphaper(cfg["bandwith"])
        bench.bench_image(cfg["local_registry"], cfg["insecure_local_registry"], image, f)
    elif mode == "nydus-no-prefetch":
        util.enable_wondersphaper(cfg["bandwith"])
        bench.bench_image(cfg["local_registry"], cfg["insecure_local_registry"], util.image_nydus(image), f, "nydus")
    elif mode == "nydus-all-prefetch":
        # open prefetch enable
        util.switch_config_prefetch_enable()
        util.reload_nydus()
        util.enable_wondersphaper(cfg["bandwith"])
        bench.bench_image(cfg["local_registry"], cfg["insecure_local_registry"], util.image_nydus(image), f, "nydus")
    else:
        # opne the metrics colletc api
        util.switch_config_access_pattern()
        util.reload_nydus()
        # collect metrics data
        file = collect_metrics(cfg, image)
        # generate prefetch list
        _ = alg.get_prefetch_list(file)
        # rebuild
        cvt.convert_nydus_prefetch(cfg["source_registry"], cfg["insecure_source_registry"], cfg["local_registry"], cfg["insecure_local_registry"], image, PREFETCH_FILE_LIST)
        # open prefetch enable
        util.switch_config_prefetch_enable()
        # close the metrics colletc api
        util.switch_config_access_pattern()
        util.reload_nydus()
        util.enable_wondersphaper(cfg["bandwith"])
        bench.bench_image(cfg["local_registry"], cfg["insecure_local_registry"], util.image_nydus_prefetch(image), f, "nydus")


if __name__ == "__main__":
    main()
