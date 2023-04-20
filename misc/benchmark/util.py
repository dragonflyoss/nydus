#!/usr/bin/env python3
import csv
import json
import os

NYDUSD_CONFIG = "/etc/nydus/config.json"


def get_nydusd_config() -> dict:
    config = []
    with open(NYDUSD_CONFIG, 'r', encoding='utf-8') as f:
        config = json.load(f)
    return config


def switch_config_prefetch_enable():
    """
    switch the fs_prefetch.enable status
    """
    config = get_nydusd_config()
    config["fs_prefetch"]["enable"] = not config["fs_prefetch"]["enable"]
    with open(NYDUSD_CONFIG, 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=4)


def switch_config_access_pattern():
    """
    switch the status of access pattern used by metrics.py
    """
    config = get_nydusd_config()
    config["iostats_files"] = not config["iostats_files"]
    config["access_pattern"] = not config["access_pattern"]
    config["latest_read_files"] = not config["latest_read_files"]
    with open(NYDUSD_CONFIG, 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=4)


def reload_nydus():
    rc = os.system("systemctl restart nydus-snapshotter.service")
    assert rc == 0


def image_repo(ref: str):
    return ref.split(":")[0]


def image_tag(ref: str) -> str:
    try:
        return ref.split(":")[1]
    except IndexError:
        return None


def image_nydus(ref: str):
    return image_repo(ref) + ":" + image_tag(ref) + "_nydus"


def image_nydus_prefetch(ref: str) -> str:
    return image_repo(ref) + ":" + image_tag(ref) + "_nydus_prefetch"


def show_csv(file_path: str):
    with open(file_path, mode='r') as f:
        reader = csv.reader(f)
        for row in reader:
            formatted_row = [f'{cell}' for cell in row]
            print(','.join(formatted_row))


def enable_wondersphaper(bandwith: int):
    os.system("sudo wondershaper -a docker0 -u " + str(bandwith) + " -d" + str(bandwith))
