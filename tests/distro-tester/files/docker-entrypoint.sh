#!/bin/bash -e

info() {
  echo -n "ENTRYPOINT: "
  echo "$@"
}

error_exit() {
  echo -n "ENTRYPOINT ERROR: "
  echo $@
  exit 1
}

image_name=$1

## main

cleanup() {
  cat /tmp/qemu.log | sed 's:::g'

  found=0
  cat /tmp/qemu.log | grep "Signature ID: $test_name" -B2 | head -3 | grep -q "\*\*\* Detection" && found=1
  if [[ $found -eq 1 ]]; then
    echo "TEST: SUCCESS"
    exit 0
  else
    echo "TEST: FAILED"
    exit 1
  fi
}

echo > /tmp/qemu.log
trap cleanup EXIT

if [[ ! -f /tracee/go.mod ]]; then
  error_exit "/tracee doesn't seem to be tracee source directory"
fi

cd /tester

./03-run-qemu.sh $image_name /tracee $test_name $kvm_accel $non_core $cpus $mem | tee /tmp/qemu.log

# vi:syntax=sh:expandtab:smarttab:tabstop=2:shiftwidth=2:softtabstop=2
