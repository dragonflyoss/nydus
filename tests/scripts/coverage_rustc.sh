#!/bin/sh
# Instrument workspace code, not dependency hot loops such as crc32c.
exec "$@" -C instrument-coverage
