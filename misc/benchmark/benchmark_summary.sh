#!/bin/bash

sudo install -m 755 benchmark-oci/wordpress.csv oci.csv
sudo install -m 755 benchmark-zran-all-prefetch/wordpress.csv zran-all-prefetch.csv
sudo install -m 755 benchmark-zran-no-prefetch/wordpress.csv zran-no-prefetch.csv
sudo install -m 755 benchmark-nydus-no-prefetch/wordpress.csv nydus-no-prefetch.csv
sudo install -m 755 benchmark-nydus-all-prefetch/wordpress.csv nydus-all-prefetch.csv
sudo install -m 755 benchmark-nydus-filelist-prefetch/wordpress.csv nydus-filelist-prefetch.csv

echo "| benchmark-result | pull-elapsed(s) | create-elapsed(s) | run-elapsed(s) | total-elapsed(s) |"
echo "|:-------|:-----------------:|:-------------------:|:----------------:|:------------------:|"

files=(oci.csv nydus-all-prefetch.csv zran-all-prefetch.csv nydus-no-prefetch.csv zran-no-prefetch.csv nydus-filelist-prefetch.csv)

for file in "${files[@]}"; do
if ! [ -f "$file" ]; then
    continue
fi
filename=$(basename "$file" .csv)
tail -n +2 "$file" | while read line; do
    pull=$(echo "$line" | cut -d ',' -f 2)
    create=$(echo "$line" | cut -d ',' -f 3)
    run=$(echo "$line" | cut -d ',' -f 4)
    total=$(echo "$line" | cut -d ',' -f 5)
    printf "| %s | %s | %s | %s | %s |\n" "$filename" "$pull" "$create" "$run" "$total"
done
done
