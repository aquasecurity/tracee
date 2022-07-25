#!/bin/bash

#
# This test is executed by github workflows inside the action runners
#

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

# run CO-RE TRC-2 test only by default
TESTS=${TESTS:=TRC-2}
ISNONCORE=${ISNONCORE:=0}
DONTSLEEP=${DONTSLEEP:=1}

# randomize start point (for parallel runners)
if [[ $DONTSLEEP -ne 1 ]]; then
  rand=$(( $RANDOM % 10 ))
  info "sleeping for $rand seconds"
  sleep $rand
fi

# startup needs
rm -rf /tmp/tracee/* || error_exit "could not delete /tmp/tracee"
git config --global --add safe.directory "*"

info "=== ENVIRONMENT ==="
info "KERNEL: $(uname -r)"
info "NON CO-RE: $ISNONCORE"
info "CLANG: $(clang --version)"
info "GO: $(go version)"
info "==================="
info "PULLING aquasec/tracee-tester:latest"
docker image pull aquasec/tracee-tester:latest
info "==================="
info "COMPILING TRACEE"
make clean
set -e
make -j$(nproc) all
set +e
if [[ ! -x ./dist/tracee-ebpf || ! -x ./dist/tracee-rules ]]; then
    error_exit "could not find tracee executables"
fi
if [[ $ISNONCORE -eq 1 ]]; then
    info "STATE: Compiling non CO-RE eBPF object"
    make clean-bpf-nocore
    set -e
    make install-bpf-nocore
    set +e
    export TRACEE_BPF_FILE=$(ls -1tr /tmp/tracee/*tracee.bpf*.o | head -n1)
fi
info "==================="

# if any test has failed
anyerror=""

# run tests
for TEST in $TESTS; do

    info ""
    info "=== TESTING: $TEST ==="
    info ""

    # file containing tracee-event output (to check for detection)
    rm -f /tmp/build-$$

    events=$(./dist/tracee-rules --rules $TEST --list-events)

    ./dist/tracee-ebpf \
      --cache cache-type=mem \
      --cache mem-cache-size=512 \
      -o format:gob \
      -o option:parse-arguments \
      -o option:detect-syscall \
      -trace container \
      -trace event=$events \
      | \
    ./dist/tracee-rules \
      --input-tracee=file:stdin \
      --input-tracee format:gob \
      --rules $TEST | tee /tmp/build-$$ &

    # wait tracee-ebpf to be started (30 sec most)
    times=0
    while true; do
        times=$(($times + 1))
        sleep 1
        if [[ -f /tmp/tracee/out/tracee.pid ]]; then
            info "tracee is up"
            break
        fi
        if [[ $times -gt 30 ]]; then
            error_exit "time out waiting for tracee initialization"
        fi
    done

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

    # run tracee-tester (triggering the signature) many times
    for i in 1 2 3; do
        docker run $docker_extra_arg --rm aquasec/tracee-tester $TEST > /dev/null 2>&1
    done

    # so event can be processed and detected
    sleep 5

    ## cleanup at EXIT

    success=1
    found=0
    cat /tmp/build-$$ | grep "Signature ID: $test_name" -B2 | head -3 | grep -q "\*\*\* Detection" && found=1
    echo ""
    if [[ $found -eq 1 ]]; then
        echo "TEST $TEST: SUCCESS"
    else
        echo "TEST $TEST: FAILED"
        anyerror="${anyerror}$TEST,"
    fi
    echo ""

    kill -19 $(pidof tracee-rules)
    kill -19 $(pidof tracee-ebpf)

    kill -9 $(pidof tracee-rules)
    kill -9 $(pidof tracee-ebpf)

    # give a little break
    sleep 5
done

info ""
if [[ $anyerror != "" ]]; then
    info "TESTS HAVE FAILED: ${anyerror::-1}"
    exit 1
fi

info "SUCCESS"

exit 0
