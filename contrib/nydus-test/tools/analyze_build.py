import os
import re
import json


def find_all_outputs_sorted():
    outputs = [o for o in os.listdir() if re.match(r".*json$", o) is not None]
    outputs.sort(key=lambda x: int(x.split("-")[0]), reverse=True)

    info_list = []
    for o in outputs:
        with open(o, "r") as f:
            info_list.append(json.load(f))

    return info_list


if __name__ == "__main__":
    blobs_output = find_all_outputs_sorted()
    total_compressed_size = 0
    total_decompressed_size = 0
    dedup_decompressed_total_size = 0
    dedup_chunks_count = 0
    total_layers = 0
    layers_never_dumped = 0
    for bi in blobs_output:
        bo = bi["trace"]["registered_events"]
        total_layers += 1
        try:
            total_compressed_size += bo["blob_compressed_size"]
            total_decompressed_size += bo["blob_decompressed_size"]
        except KeyError:
            layers_never_dumped += 1
            continue

        try:
            dedup_decompressed_total_size += bo["dedup_decompressed_size"]
            dedup_chunks_count += bo["dedup_chunks"]
        except KeyError:
            continue

    print(f"total layers: {total_layers}")
    print(f"layers never dumped: {layers_never_dumped}")
    print(f"total compressed size: {total_compressed_size}")
    print(f"total decompressed size: {total_decompressed_size}")
    print(
        f"dedup total decompressed size: {dedup_decompressed_total_size}, dedup chunks count: {dedup_chunks_count}"
    )
