#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

docker image pull ubuntu:jammy-20240627.1 > /dev/null
docker container run --rm ubuntu:jammy-20240627.1 /usr/bin/ls > /dev/null
