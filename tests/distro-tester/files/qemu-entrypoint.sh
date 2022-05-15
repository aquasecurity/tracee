#!/bin/bash -e

info() {
  echo -n "VM INFO: "
  echo $@
}

error_exit() {
  echo -n "VM ERROR: "
  echo $@
  exit 1
}

endhook() {
  umount -f /tracee > /dev/null 2>&1 || true
  shutdown -h now
}

cleanup() {
  endhook
}

beginhook() {
  mkdir -p /tracee
  dmesg --console-off
  trap cleanup EXIT
  mount -t virtiofs /tracee /tracee
}

## main

beginhook

# get testname
testname=$(cat /proc/cmdline | sed 's: :\n:g' | grep testname | cut -d'=' -f2)

if [[ $testname != TRC* ]]; then
  error_exit "could not get test from cmdline"
fi

# get if it should do NON CO-RE
isnoncore=0
isnoncore=$(cat /proc/cmdline | sed 's: :\n:g' | grep isnoncore | cut -d'=' -f2)

info "KERNEL: $(uname -r)"
info "SELECTED TEST: $testname"
info "NON CO-RE: $isnoncore"
info "CLANG: $(clang --version)"
info "GO: $(go version)"

info "pulling aquasec/tracee-tester:latest docker image"
docker image pull aquasec/tracee-tester:latest

git config --global --add safe.directory /tracee

rm -rf /tmp/tracee/*
cd /tracee

make -j$(nproc) bpf-core
make -j$(nproc) tracee-ebpf
make -j$(nproc) tracee-rules
make -j$(nproc) rules

if [[ ! -x ./dist/tracee-ebpf || ! -x ./dist/tracee-rules ]]; then
  error_exit "could not find tracee executables"
fi

if [[ "$isnoncore" == "1" ]]; then
  info "STATE: Compiling non CO-RE eBPF object"
  make clean-bpf-nocore
  make install-bpf-nocore
  export TRACEE_BPF_FILE=$(ls -1tr /tmp/tracee/*tracee.bpf*.o | head -n1)
fi

events=$(./dist/tracee-rules --rules $testname --list-events)

./dist/tracee-ebpf \
  -o format:gob \
  -o option:parse-arguments \
  -o option:detect-syscall \
  -trace event=$events \
  | \
./dist/tracee-rules \
  --input-tracee=file:stdin \
  --input-tracee format:gob \
  --rules $testname &

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

docker run --rm aquasec/tracee-tester $testname > /dev/null 2>&1

# so event can be processed

sleep 5

## cleanup at EXIT

exec 1>&-
exec 2>&-

kill -19 $(pidof tracee-rules) # stop them to avoid broken pipe errors
kill -19 $(pidof tracee-ebpf) # stop them to avoid broken pipe errors

kill -9 $(pidof tracee-rules)
kill -9 $(pidof tracee-ebpf)

# vi:syntax=sh:expandtab:smarttab:tabstop=2:shiftwidth=2:softtabstop=2
