#!/bin/bash

#
# TODO: This must be updated to be orchestrated by run.sh
#

#
# This test is executed by github workflows inside the action runners
#

TRACEE_STARTUP_TIMEOUT=60
TRACEE_SHUTDOWN_TIMEOUT=60
TRACEE_RUN_TIMEOUT=60
SCRIPT_TMP_DIR=/tmp
TRACEE_TMP_DIR=/tmp/tracee

info_exit() {
    echo -n "INFO: "
    echo $@
    exit 0
}

info() {
    echo -n "INFO: "
    echo $@
}

error_exit() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

if [[ $UID -ne 0 ]]; then
    error_exit "need root privileges"
fi

if [[ ! -d ./signatures ]]; then
    error_exit "need to be in tracee root directory"
fi

KERNEL=$(uname -r)
KERNEL_MAJ=$(echo $KERNEL | cut -d'.' -f1)

if [[ $KERNEL_MAJ -lt 5 && "$KERNEL" != *"el8"* ]]; then
    info_exit "skip test in kernels < 5.0 (and not RHEL)"
fi

# run CO-RE IPv4 test only by default
TESTS=${NETTESTS:=DNS HTTP IPv4 IPv6 ICMP ICMPv6 TCP UDP}

# startup needs
rm -rf $TRACEE_TMP_DIR/* || error_exit "could not delete $TRACEE_TMP_DIR"
git config --global --add safe.directory "*"

info
info "= ENVIRONMENT ================================================="
info
info "KERNEL: $(uname -r)"
info "CLANG: $(clang --version)"
info "GO: $(go version)"
info
info "= SETUP NETWORK TESTING ENV  =================================="
info
timeout --preserve-status 20 ./tests/e2e/net/scripts/setup.sh
ret=$?
if [[ $ret -ne 0 ]]; then
    error_exit "could not setup network namespaces: error $ret"
fi
info
info "= COMPILING TRACEE-E2E-NET ====================================="
info
# make clean # if you want to be extra cautious
set -e
make -j$(nproc) tracee-e2e-net
set +e
if [[ ! -x ./dist/tracee-e2e-net ]]; then
    error_exit "could not find tracee-e2e-net executable"
fi

# if any test has failed
anyerror=""

rm -f $SCRIPT_TMP_DIR/build-$$

logfile="${SCRIPT_TMP_DIR}/tracee-log-$$"
outputfile="${SCRIPT_TMP_DIR}/tracee-output-$$"

tracee_command="./dist/tracee-e2e-net \
    --output json:$outputfile \
    --logging file=$logfile \
    --server healthz \
    --policy ./tests/policies/e2e-net/"

eval "$tracee_command &"

# wait tracee to be started (30 sec most)
times=0
timedout=0
while true; do
    times=$(($times + 1))
    sleep 1
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:3366/healthz 2>/dev/null | grep -q "200"; then
        info
        info "UP AND RUNNING"
        info
        break
    fi

    if [[ $times -gt $TRACEE_STARTUP_TIMEOUT ]]; then
        timedout=1
        break
    fi
done

# tracee could not start for some reason, check stderr
if [[ $timedout -eq 1 ]]; then
    info
    info "TIMEDOUT"
    info
    cat $logfile

    exit 1
fi

# give some time for tracee to settle
sleep 3

# run tests
info "= RUNNING TESTS ================================================"
info
for TEST in $TESTS; do

    info
    info "= $TEST TEST RUNNING =========================================="
    info

    info "running test $TEST"
    # run test scripts
    timeout --preserve-status $TRACEE_RUN_TIMEOUT \
        ./tests/e2e/net/scripts/${TEST,,}.sh

done

# so events can be processed and detected
sleep 5

mapfile -t tracee_pids < <(pgrep -f tracee-e2e-net)
if [[ ${#tracee_pids[@]} -gt 0 ]]; then
    kill -SIGINT "${tracee_pids[@]}"
    sleep ${TRACEE_SHUTDOWN_TIMEOUT}
    # make sure tracee is exited with SIGKILL
    kill -SIGKILL "${tracee_pids[@]}" >/dev/null 2>&1
fi

info "= CHECKING TESTS RESULTS ======================================"
info
for TEST in $TESTS; do
    found=0
    cat ${outputfile} | grep "\"name\":\"$TEST\"" -B2 && found=1
    info
    if [[ $found -eq 1 ]]; then
        info "$TEST: SUCCESS"
    else
        anyerror="${anyerror}$TEST,"
        info "$TEST: FAILED, stderr from tracee:"
        cat $logfile
        info "$TEST: FAILED, stdout from tracee:"
        cat $outputfile
        
        info "Tracee command:"
        echo "$tracee_command" | tr -s ' '

        info "Tracee process is running?"
        mapfile -t tracee_pids < <(pgrep -f tracee-e2e-net)
        if [[ ${#tracee_pids[@]} -gt 0 ]]; then
            info "YES, Tracee is still running (should not be, fix me!), pids: ${tracee_pids[*]}"
            info "Aborting tests"
            break
        else
            info "NO, Tracee is not running, as expected"
        fi
        info

        info
    fi
    info
done

# Cleanup leftovers
rm -f $outputfile
rm -f $logfile
rm -rf $TRACEE_TMP_DIR

info
if [[ $anyerror != "" ]]; then
    info "ALL TESTS: FAILED: ${anyerror::-1}"
    exit 1
fi

info "ALL TESTS: SUCCESS"

exit 0
