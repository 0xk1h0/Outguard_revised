#!/bin/bash

# cat tranco_100k_domain_dec11 | while read line
cat uniq_wasm_domains | while read line
do
    timeout 60s node resource_collection.js https://$line;
done