#!/bin/sh

#
# Entrypoint for the official tracee container images
#

# variables

TRACEE_TMP="/tmp/tracee"
TRACEE_OUT="${TRACEE_TMP}/out"
TRACEE_SRC=${TRACEE_SRC:="/tracee/src"}
TRACEE_EXE=${TRACEE_EXE:="/tracee/tracee"}

LIBBPFGO_OSRELEASE_FILE=${LIBBPFGO_OSRELEASE_FILE:=""}

EBPF_PROBE_TIMEOUT=${EBPF_PROBE_TIMEOUT:=3} # 3 seconds for ebpf co-re probe

# functions

run_tracee() {
    probe_tracee_ebpf
    if [ "${TRACEE_RET}" -eq 2 ]; then
        return
    fi

    mkdir -p ${TRACEE_OUT}

    # start tracee

    echo "INFO: starting tracee..."
    ${TRACEE_EXE} \
        --metrics \
        --output=option:parse-arguments \
        --cache cache-type=mem \
        --cache mem-cache-size=512 \
        --containers=${CONTAINERS_ENRICHMENT:="0"}\
        --capabilities bypass=${CAPABILITIES_BYPASS:="0"}\
        --capabilities add=${CAPABILITIES_ADD:=""}\
        --capabilities drop=${CAPABILITIES_DROP:=""}\
        $@
    #tracee_pid=$!

    TRACEE_RET=$?
}

probe_tracee_ebpf() {
    # check if non CO-RE obj is needed (tracee-ebpf ret code is 2)

    TRACEE_RET=0
    if [ "${probed_cap}" -ne 1 ]; then
        probed_cap=1

        echo "INFO: probing tracee-ebpf capabilities..."
        timeout --preserve-status "${EBPF_PROBE_TIMEOUT}" \
            "${TRACEE_EBPF_EXE}" --metrics --output=none \
            --filter comm="nothing" 2>&1 > /dev/null 2>&1
        TRACEE_RET=$?
    fi
}

# startup

probed_cap=0

if [ ! -x "${TRACEE_EXE}" ]; then
    echo "ERROR: cannot execute ${TRACEE_EXE}"
    exit 1
fi

if [ "${LIBBPFGO_OSRELEASE_FILE}" == "" ]; then
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

    exit 1;
fi

if [ ! -f "${LIBBPFGO_OSRELEASE_FILE}" ]; then
    echo "ERROR:"
    echo "ERROR: You provided a LIBBPFGO_OSRELEASE_FILE variable but"
    echo "ERROR: missed providing the bind mount for it."
    echo "ERROR:"
    echo "ERROR: Try docker with: -v /etc/os-release:/etc/os-release-host:ro"
    echo "ERROR:"

    exit 1;
fi

# main

if [ -d "${TRACEE_SRC}" ]; then
    # full container image

    # run first, may find cached eBPF non CO-RE obj in /tmp/tracee
    run_tracee $@

    if [ "${TRACEE_RET}" -eq 2 ]; then
        # if ret code is 2, compile non CO-RE obj, run again

        if [ ! -d "/lib/modules/$(uname -r)" ]; then
            echo "ERROR:"
            echo "ERROR: Tracee needs to build its non-CORE eBPF object!"
            echo "ERROR: You need to bind mount /usr/src and /lib/modules."
            echo "ERROR:"
            echo "ERROR: Run docker with:"
            echo "ERROR:     -v /usr/src:/usr/src:ro"
            echo "ERROR:     -v /lib/modules:/lib/modules:ro"
            echo "ERROR:"

            exit 1
        fi

        cd "${TRACEE_SRC}"
        make clean
        make install-bpf-nocore
        # force nocore ebpf object

        # make sure the just generated eBPF non CO-RE obj is used
        export TRACEE_BPF_FILE=$(ls -tr1 /tmp/tracee/tracee.bpf.*.o | head -1)
        if [ ! -f "${TRACEE_BPF_FILE}" ]; then
            echo "ERROR: could not find TRACEE_BPF_FILE"
            exit 1
        fi
    fi
fi

run_tracee $@

if [ "${TRACEE_RET}" -eq 2 ] && [ ! -d "${TRACEE_SRC}" ]; then
    echo "INFO:"
    echo "INFO: You should try the FULL tracee container image, it supports"
    echo "INFO: building, based on your host environment, needed eBPF objects"
    echo "INFO: so tracee may work."
    echo "INFO:"
fi

exit ${TRACEE_RET}

# vi:syntax=sh:expandtab:tabstop=4:shiftwidth=4:softtabstop=4
