#!/bin/sh -e

#
# Entrypoint for the official tracee container images
#

run_tracee() {
    if [ ${TRACEE_EBPF_ONLY} -eq 1 ]; then
        run_tracee_ebpf $@
    else
        run_tracee_rules $@
    fi
}

run_tracee_ebpf() {
    ${TRACEE_EBPF_EXE} $@
    return $?
}

run_tracee_rules() {
    # named pipe for tracee-ebpf <=> tracee-rules communication

    tracee_pipe=/tmp/tracee/pipe
    mkdir -p /tmp/tracee/out
    rm -f ${tracee_pipe}
    mkfifo ${tracee_pipe}

    # start tracee-ebpf in the background

    EVENTS=$($TRACEE_RULES_EXE --list-events)
    echo "starting tracee-ebpf..."
    ${TRACEE_EBPF_EXE} --output=format:gob --output=option:parse-arguments --trace event=$EVENTS --output=out-file:$tracee_pipe &
    tracee_ebpf_pid=$!

    # wait for tracee-ebpf to: load / exit / timeout

    tracee_ebpf_readiness=/tmp/tracee/out/tracee.pid
    rm -f ${tracee_ebpf_readiness}
    timeout=15
    i=0
    while [ ! -f ${tracee_ebpf_readiness} ] && \
        $(ls /proc/${tracee_ebpf_pid} >/dev/null 2>&1) && \
        [ ${i} -le ${timeout} ]
    do
    	i=$(( i + 1 ))
    	sleep 1
    done

    if [ ! -f ${tracee_ebpf_readiness} ]; then
        echo "could not start tracee-ebpf"
        exit 1
    fi

    # start tracee-rules

    echo "starting tracee-rules..."
    $TRACEE_RULES_EXE --input-tracee=file:$tracee_pipe --input-tracee=format:gob $@
    return $?
}

# variables

TRACEE_EBPF_SRC=${TRACEE_EBPF_SRC:="/tracee/src"}
TRACEE_EBPF_EXE=${TRACEE_EBPF_EXE:="/tracee/tracee-ebpf"}
TRACEE_RULES_EXE=${TRACEE_RULES_EXE:="/tracee/tracee-rules"}
FORCE_CORE=${FORCE_CORE:=0}
LIBBPFGO_OSRELEASE_FILE=${LIBBPFGO_OSRELEASE_FILE:=""}
TRACEE_EBPF_ONLY=${TRACEE_EBPF_ONLY:=0}

# startup checks

if [ ! -x ${TRACEE_EBPF_EXE} ]; then
    echo "Cannot execute ${TRACEE_EBPF_EXE}"
    exit 1
fi

if [ ! -x ${TRACEE_RULES_EXE} ]; then
    echo "Cannot execute ${TRACEE_EBPF_EXE}"
    exit 1
fi

for arg in ${@}; do
    case ${arg} in
    "--help")
        if [ ${TRACEE_EBPF_ONLY} -eq 1 ]; then
            ${TRACEE_EBPF_EXE} --help
        else
            ${TRACEE_RULES_EXE} --help
        fi

        exit $?
        ;;
    esac
done

if [ "${LIBBPFGO_OSRELEASE_FILE}" == "" ]; then
    echo ""
    echo "You have to set LIBBPFGO_OSRELEASE_FILE env variable."
    echo "It allows tracee to detect host environment features."
    echo ""
    echo "Run docker with :"
    echo "    -v /etc/os-release:/etc/os-release-host:ro"
    echo ""
    echo "Then you may set LIBBPFGO_OSRELEASE_FILE:"
    echo "    -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host"
    echo ""

    exit 1;
fi

if [ ! -f "${LIBBPFGO_OSRELEASE_FILE}" ]; then
    echo ""
    echo "You provided a LIBBPFGO_OSRELEASE_FILE variable but missed"
    echo " providing the bind mount for it."
    echo ""
    echo "Run docker with:"
    echo "    -v /etc/os-release:/etc/os-release-host:ro"
    echo ""

    exit 1;
fi

# main

if [ -d "${TRACEE_EBPF_SRC}" ]; then
    # container contains tracee source code

    if [ ${FORCE_CORE} -eq 1 ]; then
            run_tracee $@
    fi

    if [ ! -d "/lib/modules/$(uname -r)" ]; then
        echo ""
        echo "Tracee needs to build its non-CORE eBPF object!"
        echo "You need to bind mount /usr/src and /lib/modules."
        echo ""
        echo "Run docker with:"
        echo "    -v /usr/src:/usr/src:ro"
        echo "    -v /lib/modules:/lib/modules:ro"
        echo ""

        exit 1
    fi

    cd ${TRACEE_EBPF_SRC}
    make -f Makefile.one clean
    make -f Makefile.one install-bpf-nocore

    # force nocore ebpf object

    export TRACEE_BPF_FILE=$(ls -tr1 /tmp/tracee/tracee.bpf.*.o | head -1)
    if [ ! -f "${TRACEE_BPF_FILE}" ]; then
        echo "Error, could not find TRACEE_BPF_FILE"

        exit 1
    fi
fi

run_tracee $@

# vi:syntax=sh:expandtab:tabstop=4:shiftwidth=4:softtabstop=4
