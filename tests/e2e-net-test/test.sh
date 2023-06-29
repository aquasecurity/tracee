#!/bin/bash

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
TESTS=${NETTESTS:=IPv4}

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
timeout --preserve-status 20 ./tests/e2e-net-test/scripts/setup.sh
ret=$?
if [[ $ret -ne 0 ]]; then
    error_exit "could not setup network namespaces: error $ret"
fi
info
info "= COMPILING TRACEE ============================================"
info
# make clean # if you want to be extra cautious
set -e
make -j$(nproc) all
make e2e-net-signatures
set +e
if [[ ! -x ./dist/tracee ]]; then
    error_exit "could not find tracee executable"
fi

# setup script variables
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SIG_DIR=$(realpath $SCRIPT_DIR/../../dist/e2e-net-signatures)
POLICY_DIR=$(realpath $SCRIPT_DIR/policies)

# if any test has failed
anyerror=""

rm -f $SCRIPT_TMP_DIR/build-$$
rm -f $SCRIPT_TMP_DIR/tracee-log-$$

./dist/tracee \
    --install-path $TRACEE_TMP_DIR \
    --cache cache-type=mem \
    --cache mem-cache-size=512 \
    --output json:$SCRIPT_TMP_DIR/build-$$ \
    --output option:parse-arguments \
    --log file:$SCRIPT_TMP_DIR/tracee-log-$$ \
    --signatures-dir $SIG_DIR \
    --policy $POLICY_DIR &

# wait tracee-ebpf to be started (30 sec most)
times=0
timedout=0
while true; do
    times=$(($times + 1))
    sleep 1
    info "TESTING IF TRACEE IS UP"
    if [[ -f $TRACEE_TMP_DIR/out/tracee.pid ]]; then
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
    info "TIMEOUT STARTING TRACEE. ERRORS:"
    info
    cat $SCRIPT_TMP_DIR/tracee-log-$$

    error_exit "CLOSING TEST"
fi

# give some time for tracee to settle
sleep 3

# run tests
for TEST in $TESTS; do
    # run test scripts
    timeout --preserve-status $TRACEE_RUN_TIMEOUT \
        ./tests/e2e-net-test/scripts/${TEST,,}.sh &
    info "RUNNING TEST $TEST"
done

# so event can be processed and detected
sleep 5

# check test results
for TEST in $TESTS; do
    found=0
    cat $SCRIPT_TMP_DIR/build-$$ | jq .eventName | grep -q $TEST && found=1
    info
    info "= TEST: $TEST =============================================="
    info
    if [[ $found -eq 1 ]]; then
        info "$TEST: SUCCESS"
    else
        anyerror="${anyerror}$TEST,"
        info "$TEST: FAILED, stderr from tracee:"
        cat $SCRIPT_TMP_DIR/tracee-log-$$
        info
    fi
    info
done


## cleanup at EXIT

rm -f $SCRIPT_TMP_DIR/build-$$
rm -f $SCRIPT_TMP_DIR/tracee-log-$$

# make sure we exit to start it again

pid_tracee=$(pidof tracee)

kill -2 $pid_tracee

sleep $TRACEE_SHUTDOWN_TIMEOUT

# make sure tracee is exited with SIGKILL
kill -9 $pid_tracee >/dev/null 2>&1

# give a little break for OS noise to reduce
sleep 3

# cleanup leftovers
rm -rf $TRACEE_TMP_DIR

info
if [[ $anyerror != "" ]]; then
    info "ALL TESTS: FAILED: ${anyerror::-1}"
    exit 1
fi

info "ALL TESTS: SUCCESS"

exit 0
