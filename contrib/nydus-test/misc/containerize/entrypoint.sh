#!/bin/bash

python3 nydus_test_config.py --dist fs_structure.yaml
pytest -vs --durations=0 --pdb $@