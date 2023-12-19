#!/bin/bash

# Path to the file containing URLs
file_path="/Users/timkh/webassembl/outguard/instrumentation/uniq_wasm_domains"

alive_file="alive_urls.txt"

alive_count=0
dead_count=0

check_url() {
  if curl --output /dev/null --silent --head --fail --max-time 20 "$1"; then
    echo "URL is alive: $1"
    echo "$1" >> "$alive_file"
    ((alive_count++))
  else
    echo "URL is broken: $1"
    ((dead_count++))
  fi
}

> "$alive_file"

while IFS= read -r url; do
  check_url "$url";
done < "$file_path"

echo "Total alive URLs: $alive_count"
echo "Total dead URLs: $dead_count"
