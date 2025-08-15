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

DOCKER_IMAGE=ghcr.io/aquasecurity/tracee-tester:latest

# run CO-RE ARM compatible tests only by default (x86_64 has more but this is for manual user runs)
TESTS=${TESTS:=TRC-102 TRC-103 TRC-104 TRC-105 TRC-107 TRC-1010 TRC-1014 TRC-1016 TRC-1018}

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
docker image pull $DOCKER_IMAGE
info
info "= COMPILING TRACEE ============================================"
info
# make clean # if you want to be extra cautious
set -e
make -j$(nproc) all
set +e
if [[ ! -x ./dist/tracee ]]; then
    error_exit "could not find tracee executable"
fi

# if any test has failed
anyerror=""

rm -f $SCRIPT_TMP_DIR/build-$$

outputfile=$SCRIPT_TMP_DIR/output-$$
logfile=$SCRIPT_TMP_DIR/tracee-log-$$

tracee_command="./dist/tracee \
    --install-path $TRACEE_TMP_DIR \
    --output json:$outputfile \
    --log file:$logfile \
    --policy ./tests/policies/kernel/kernel.yaml 2>&1 \
    | tee $SCRIPT_TMP_DIR/build-$$"

eval "$tracee_command &"

# give some time for tracee to settle
sleep 5

# wait tracee to be started (30 sec most)
times=0
timedout=0
while true; do
    times=$(($times + 1))
    sleep 1
    if [[ -f $TRACEE_TMP_DIR/tracee.pid ]]; then
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

# run tests
info "= RUNNING TESTS ================================================"
info
for TEST in $TESTS; do
    info
    info "= $TEST TEST RUNNING =========================================="
    info

    # special capabilities needed for some tests
    case $TEST in
    TRC-2 | TRC-102 | TRC-3 | TRC-103)
        docker_extra_arg="--cap-add=SYS_PTRACE"
        ;;
    TRC-11 | TRC-1014)
        docker_extra_arg="--cap-add=SYS_ADMIN"
        ;;
    *) ;;
    esac

    # run tracee-tester (triggering the signature)
    docker run $docker_extra_arg --rm $DOCKER_IMAGE $TEST >/dev/null 2>&1

    # so event can be processed and detected
    sleep 5
done

sleep 5
mapfile -t tracee_pids < <(pgrep -x tracee)
# cleanup tracee with SIGINT
kill -SIGINT "${tracee_pids[@]}"
sleep $TRACEE_SHUTDOWN_TIMEOUT
# make sure tracee is exited with SIGKILL
kill -SIGKILL "${tracee_pids[@]}" >/dev/null 2>&1
# give a little break for OS noise to reduce

info "= CHECKING TESTS RESULTS ======================================"
info
for TEST in $TESTS; do
found=0
    cat $outputfile | grep "\"signatureID\":\"$TEST\"" -B2 && found=1
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
        mapfile -t tracee_pids < <(pgrep -x tracee)
        if [[ -n "${tracee_pids[*]}" ]]; then
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
