#!/bin/bash

#
# This test is executed by github workflows inside the action runners
#

TRACEE_STARTUP_TIMEOUT=30
SCRIPT_TMP_DIR=/tmp
TRACEE_TMP_DIR=/tmp/tracee

info() {
    echo -n "INFO: "
    echo $@
}

error_exit() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

if [[ $UID -ne 0 ]]
then
    error_exit "need root privileges for docker caps config"
fi

if [[ ! -d ./signatures ]]
then
    error_exit "need to be in tracee root directory"
fi

# run CO-RE TRC-2 test only by default
TESTS=${TESTS:=TRC-2}
ISNONCORE=${ISNONCORE:=0}
DONTSLEEP=${DONTSLEEP:=1}

# randomize start point (for parallel runners)
if [[ $DONTSLEEP -ne 1 ]]
then
  rand=$(( $RANDOM % 10 ))
  info "sleeping for $rand seconds"
  sleep $rand
fi

# startup needs
rm -rf $TRACEE_TMP_DIR/* || error_exit "could not delete $TRACEE_TMP_DIR"
git config --global --add safe.directory "*"

info
info "= ENVIRONMENT ================================================="
info
info "KERNEL: $(uname -r)"
info "NON CO-RE: $ISNONCORE"
info "CLANG: $(clang --version)"
info "GO: $(go version)"
info
info "= PULLING CONTAINER IMAGE ====================================="
info
docker image pull aquasec/tracee-tester:latest
info
info "= COMPILING TRACEE ============================================"
info
# make clean # if you want to be extra cautious
set -e
make -j$(nproc) all
set +e
if [[ ! -x ./dist/tracee-ebpf || ! -x ./dist/tracee-rules ]]
then
    error_exit "could not find tracee executables"
fi
if [[ $ISNONCORE -eq 1 ]]
then
    info "STATE: Compiling non CO-RE eBPF object"
    make clean-bpf-nocore
    set -e
    make install-bpf-nocore
    set +e
    export TRACEE_BPF_FILE=$(ls -1tr $TRACEE_TMP_DIR/*tracee.bpf*.o | head -n1)
fi

# if any test has failed
anyerror=""

# run tests
for TEST in $TESTS; do

    info
    info "= TEST: $TEST ================================================="
    info

    rm -f $SCRIPT_TMP_DIR/build-$$
    rm -f $SCRIPT_TMP_DIR/ebpf-$$

    events=$(./dist/tracee-rules --rules $TEST --list-events)

    ./dist/tracee-ebpf \
        --install-path $TRACEE_TMP_DIR \
        --cache cache-type=mem \
        --cache mem-cache-size=512 \
        --output format:gob \
        --output option:parse-arguments \
        --output option:detect-syscall \
        --trace container=new \
        --trace event=$events \
        2>$SCRIPT_TMP_DIR/ebpf-$$ \
        | \
    ./dist/tracee-rules \
        --input-tracee=file:stdin \
        --input-tracee format:gob \
        --rules $TEST 2>&1 \
        | \
    tee $SCRIPT_TMP_DIR/build-$$ 2>&1 &

    # wait tracee-ebpf to be started (30 sec most)
    times=0
    timedout=0
    while true; do
        times=$(($times + 1))
        sleep 1
        if [[ -f $TRACEE_TMP_DIR/out/tracee.pid ]]
        then
            info
            info "UP AND RUNNING"
            info
            break
        fi

        if [[ $times -gt $TRACEE_STARTUP_TIMEOUT ]]
        then
            timedout=1
            break
        fi
    done

    # tracee-ebpf could not start for some reason, check stderr
    if [[ $timedout -eq 1 ]]
    then
        info
        info "$TEST: FAILED. ERRORS:"
        info
        cat $SCRIPT_TMP_DIR/ebpf-$$

        anyerror="${anyerror}$TEST,"
        continue
    fi

    # special capabilities needed for some tests
    case $TEST in
        TRC-2 | TRC-3)
            docker_extra_arg="--cap-add=SYS_PTRACE"
            ;;
        TRC-11)
            docker_extra_arg="--cap-add=SYS_ADMIN"
            ;;
        *)
            ;;
    esac

    # give some time for tracee to settle
    sleep 5

    # run tracee-tester (triggering the signature)
    docker run $docker_extra_arg --rm aquasec/tracee-tester $TEST > /dev/null 2>&1

    # so event can be processed and detected
    sleep 5

    ## cleanup at EXIT

    found=0
    cat $SCRIPT_TMP_DIR/build-$$ | grep "Signature ID: $TEST" -B2 | head -3 | grep -q "\*\*\* Detection" && found=1
    info
    if [[ $found -eq 1 ]]
    then
        info "$TEST: SUCCESS"
    else
        anyerror="${anyerror}$TEST,"
        info "$TEST: FAILED, stderr from tracee-ebpf:"
        cat $SCRIPT_TMP_DIR/ebpf-$$
        info
    fi
    info

    rm -f $SCRIPT_TMP_DIR/build-$$
    rm -f $SCRIPT_TMP_DIR/ebpf-$$

    # make sure we exit both to start them again

    kill -19 $(pidof tracee-rules)
    kill -19 $(pidof tracee-ebpf)

    kill -9 $(pidof tracee-rules)
    kill -9 $(pidof tracee-ebpf)

    # give a little break for OS noise to reduce
    sleep 5
done

info
if [[ $anyerror != "" ]]
then
    info "ALL TESTS: FAILED: ${anyerror::-1}"
    exit 1
fi

info "ALL TESTS: SUCCESS"

exit 0
