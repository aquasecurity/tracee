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

# create loop devices if running in LXD guest

for seq in $(echo {150..170}); do
  mknod -m 660 /dev/loop$seq b 7 $seq > /dev/null 2>&1 || true
done

# sleep for random time not to start all jobs at once

if [[ $skip_sleep -ne 1 ]]; then
  rand=$(( $RANDOM % 30 ))
  info "sleeping for $rand seconds"
  sleep $rand
fi

# run qemu

cd /tester

./03-run-qemu.sh $image_name /tracee $test_name $kvm_accel $non_core $cpus $mem | tee /tmp/qemu.log

# vi:syntax=sh:expandtab:smarttab:tabstop=2:shiftwidth=2:softtabstop=2
