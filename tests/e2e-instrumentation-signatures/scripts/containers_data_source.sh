#!/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

docker pull ubuntu > /dev/null
docker run --rm ubuntu /usr/bin/ls > /dev/null
