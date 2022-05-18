#!/bin/bash -ex

# syntax: ./$0 [image] [tracee_dir] [TRC-X] [kvm|tcg] [0|1]

. ./00-config

command -v qemu-system-x86_64 || exit 1
command -v qemu-img || exit 1

image=$1
tracee=$2
testname=$3
kvmaccel=$4
isnoncore=$5

qemu-img info images/$image | grep -q raw && format="raw"
qemu-img info images/$image | grep -q qcow2 && format="qcow2"

error_syntax() {
  echo ""
  echo -n "ERROR: "
  echo $@
  echo ""
  echo "syntax: $0 [image] [tracee_dir] [TRC-X] [kvm|tcg]"
  echo ""
  exit 1
}

if [[ ! -f images/$image ]]; then
  error_syntax "image file $image does not exist"
fi

if [[ ! -d $tracee && ! -f $tracee/go.mod ]]; then
  error_syntax "invalid tracee dir: $tracee"
fi

if [[ ! $testname == TRC* ]]; then
  error_syntax "test should be named TRC-<something>"
fi

if [[ $kvmaccel != tcg && $kvmaccel != kvm ]]; then
  error_syntax "acceleration should be tcg or kvm"
fi

if [[ $isnoncore == "" || ( $isnoncore -ne 0 && $isnoncore -ne 1 ) ]]; then
  error_syntax "non core should be either 0 or 1"
fi

mount -t tmpfs -o rw,nosuid,nodev,inode64 tmpfs /dev/shm

rm -f "/tmp/vhostqemu-$image"

/usr/lib/qemu/virtiofsd \
  -o cache=always \
  -o no_flock \
  -o log_level=err \
  -o no_posix_lock \
  -o sandbox=chroot \
  -o no_writeback \
  -o no_xattr \
  -o no_allow_direct_io \
  -o source=$tracee \
  -o allow_root \
  --socket-path="/tmp/vhostqemu-$image" &

if [[ -f ./kernels/$image.vmlinuz ]]; then
  vmlinuz="./kernels/$image.vmlinuz"
  initrd="./kernels/$image.initrd"
else
  vmlinuz="./kernels-copy/$image.vmlinuz"
  initrd="./kernels-copy/$image.initrd"
fi

qemu-system-x86_64 \
  -name guest=$image \
  -machine accel=$kvmaccel \
  --cpu max --smp cpus=1 -m 2G \
  -object memory-backend-file,id=mem,size=2G,mem-path=/dev/shm,share=on \
  -numa node,nodeid=0,cpus=0,memdev=mem \
  -rtc base=utc,clock=vm,driftfix=none \
  -boot c \
  -display none \
  -serial stdio \
  -kernel $vmlinuz \
  -initrd $initrd \
  -append "root=/dev/vda console=ttyS0 testname=$testname isnoncore=$isnoncore selinux=0 apparmor=0 systemd.unified_cgroup_hierarchy=false net.ifnames=0" \
  -netdev user,id=mynet,net=192.168.76.0/24,dhcpstart=192.168.76.9 \
  -device virtio-net-pci,netdev=mynet \
  -drive file="./images/$image",if=virtio,format=$format \
  -chardev socket,id=char0,path="/tmp/vhostqemu-$image" \
  -device vhost-user-fs-pci,queue-size=1024,chardev=char0,tag=/tracee

# vi:syntax=sh:expandtab:smarttab:tabstop=2:shiftwidth=2:softtabstop=2
