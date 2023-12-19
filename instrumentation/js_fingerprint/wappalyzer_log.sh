#!/bin/bash

# cat tranco_100k_domain_dec11 | while read line
cat /Users/timkh/webassembl/outguard/instrumentation/alive_urls.txt | while read line
do
    timeout 60s node driver_engine_2.js http://$line;
done