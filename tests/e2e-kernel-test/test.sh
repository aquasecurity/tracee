#!/bin/bash

#
# This test is executed by github workflows inside the action runners
#

TRACEE_STARTUP_TIMEOUT=60
TRACEE_SHUTDOWN_TIMEOUT=60
#TRACEE_RUN_TIMEOUT=60
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
    error_exit "need root privileges for docker caps config"
fi

if [[ ! -d ./signatures ]]; then
    error_exit "need to be in tracee root directory"
fi

TESTER_IMAGE=ghcr.io/aquasecurity/tracee-tester:latest

# run CO-RE TRC-102 test only by default
TESTS=${TESTS:=TRC-102}

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
info "= PULLING CONTAINER IMAGE ====================================="
info
docker image pull $TESTER_IMAGE
info
info "= COMPILING TRACEE ============================================"
info
# make clean # if you want to be extra cautious
set -e
make -j$(nproc) all
set +e
if [[ ! -x ./dist/tracee-ebpf || ! -x ./dist/tracee-rules ]]; then
    error_exit "could not find tracee executables"
fi

# setup script variables
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SIG_DIR=$(realpath $SCRIPT_DIR/../../dist/signatures)
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
    case $TEST in
    TRC-2 | TRC-102 | TRC-3 | TRC-103)
        docker_extra_arg="--cap-add=SYS_PTRACE"
        ;;
    TRC-11 | TRC-1014)
        docker_extra_arg="--cap-add=SYS_ADMIN"
        ;;
    *) ;;
    esac
    info "RUNNING TEST $TEST"
    docker run $docker_extra_arg --rm $TESTER_IMAGE $TEST >/dev/null 2>&1
    sleep 1
done

# so event can be processed and detected
sleep 5

# check test results
for TEST in $TESTS; do
    found=0
    cat $SCRIPT_TMP_DIR/build-$$ | jq .metadata.Properties.signatureID | grep -q $TEST && found=1
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
