#!/usr/bin/env python3
import csv
from functools import cmp_to_key
from typing import Tuple


def read_csv(csv_path: str) -> dict:
    """
    convert csv to dictionary
    """
    file_dict = {}
    with open(csv_path, 'r') as fp:
        reader = csv.DictReader(fp)
        for x in reader:
            temp = {}
            temp['file_size'] = str(x['file_size'])
            temp['first_access_time'] = str(x['first_access_time'])
            file_dict[x['file_path']] = temp
    return file_dict


def sort_list(csv_path: str) -> Tuple[dict, list]:
    """
    sort access_files
    """
    file_dict = read_csv(csv_path)
    file_list = list(file_dict.keys())

    def comp(a, b):
        at = file_dict[a]['first_access_time']
        bt = file_dict[b]['first_access_time']
        if len(at) > len(bt):
            return 1
        elif len(at) < len(bt):
            return -1
        else:
            for i in range(len(at)):
                if i == len(at)-1:
                    return -1
                if int(at[i]) > int(bt[i]):
                    return 1
                elif int(at[i]) < int(bt[i]):
                    return -1
                else:
                    continue

    file_list.sort(key=cmp_to_key(comp))

    return file_dict, file_list


def optimize_list(csv_path: str) -> list:
    """
    optimize sorted list - only sort
    """
    _, file_list = sort_list(csv_path)

    return file_list


def to_txt(file_list: list, outpath: str):
    """
    prefetch_list to txt
    """
    with open(outpath, 'w')as f:
        for k in file_list:
            f.write(k + '\n')


def get_prefetch_list(csv_path: str) -> list:
    """
    get prefetch_list
    """
    optimized_list = optimize_list(csv_path)
    to_txt(optimized_list, 'out_list.txt')
    return optimized_list
