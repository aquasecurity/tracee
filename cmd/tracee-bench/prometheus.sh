#!/bin/bash

docker run -d --rm \
    -p 9090:9090 \
    --net=host \
    --mount type=bind,source="$(pwd)"/prometheus.yml,target=/etc/prometheus/prometheus.yml \
    prom/prometheus
