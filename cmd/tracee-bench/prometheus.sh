#!/bin/bash

CURRENT=$(pwd)
ORIGIN=$(dirname ${0})
PROM_FILE=$CURRENT/$ORIGIN/prometheus.yml

if [[ ! -f $PROM_FILE ]]; then
    echo "ERROR: could not find prometheus yml file $PROM_FILE"
    exit 1
fi

docker run -d --rm \
    -p 9090:9090 \
    --net=host \
    --mount type=bind,source=$PROM_FILE,target=/etc/prometheus/prometheus.yml \
    prom/prometheus
