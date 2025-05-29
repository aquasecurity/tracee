#!/bin/sh

#
# Entrypoint for the official tracee container images
#

# variables

TRACEE_TMP="/tmp/tracee"
TRACEE_OUT="${TRACEE_TMP}/out"
TRACEE_EXE=${TRACEE_EXE:="/tracee/tracee"}

LIBBPFGO_OSRELEASE_FILE=${LIBBPFGO_OSRELEASE_FILE:="/etc/os-release-host"}

CAPABILITIES_BYPASS=${CAPABILITIES_BYPASS:="0"}
CAPABILITIES_ADD=${CAPABILITIES_ADD:=""}
CAPABILITIES_DROP=${CAPABILITIES_DROP:=""}

# functions

run_tracee() {
    mkdir -p $TRACEE_OUT

    if [ $# -ne 0 ]; then
        # no default arguments, just given ones
        $TRACEE_EXE "$@"
    else
        # default arguments
        $TRACEE_EXE \
        --server http.metrics \
        --cache cache-type=mem \
        --cache mem-cache-size=512 \
        --capabilities bypass=$CAPABILITIES_BYPASS \
        --capabilities add=$CAPABILITIES_ADD \
        --capabilities drop=$CAPABILITIES_DROP \
        --output=json \
        --output=option:parse-arguments \
        --events signatures,container_create,container_remove
    fi

    tracee_ret=$?
}

# startup

if [ ! -x $TRACEE_EXE ]; then
    echo "ERROR: cannot execute $TRACEE_EXE"
    exit 1
fi

if [ "$LIBBPFGO_OSRELEASE_FILE" == "" ]; then
    echo "ERROR:"
    echo "ERROR: You have to set LIBBPFGO_OSRELEASE_FILE env variable."
    echo "ERROR: It allows tracee to detect host environment features."
    echo "ERROR: "
    echo "ERROR: Run docker with :"
    echo "ERROR:     -v /etc/os-release:/etc/os-release-host:ro"
    echo "ERROR: "
    echo "ERROR: Then you may set LIBBPFGO_OSRELEASE_FILE:"
    echo "ERROR:     -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host"
    echo "ERROR:"

    exit 1
fi

if [ ! -f "$LIBBPFGO_OSRELEASE_FILE" ]; then
    echo "ERROR:"
    echo "ERROR: You provided a LIBBPFGO_OSRELEASE_FILE variable but"
    echo "ERROR: missed providing the bind mount for it."
    echo "ERROR:"
    echo "ERROR: Try docker with: -v /etc/os-release:/etc/os-release-host:ro"
    echo "ERROR:"

    exit 1
fi

#
# main
#

run_tracee $@

if [ $tracee_ret -eq 2 ]; then
    echo "INFO:"
    echo "INFO: It seems that your environment isn't supported by Tracee."
    echo "INFO: If you think this is an error, please open an issue at:"
    echo "INFO:"
    echo "INFO: https://github.com/aquasecurity/tracee/"
    echo "INFO:"
fi

exit $tracee_ret
