#!/bin/bash
CSV="static_data.csv"
BIN="../bin/"
declare -a array=("haproxy" "lighttpd" "memcached" "nginx" "redis-server" "sqlite3" "weborf")

echo "app,#syscalls(static)" > $CSV
for k in "${array[@]}"
do
    python3 static_analyser.py --app "${BIN}${k}" --csv True --display False --verbose False > "${k}_${CSV}"
done