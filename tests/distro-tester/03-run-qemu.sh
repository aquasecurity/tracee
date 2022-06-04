#!/bin/bash -ex

# syntax: ./$0 [image] [tracee_dir] [TRC-X] [kvm|tcg] [0|1] [cpus] [memory]

. ./00-config

command -v qemu-system-x86_64 || exit 1
command -v qemu-img || exit 1
command -v truncate || exit 1
command -v mount || exit 1
command -v rsync || exit 1
command -v stat || exit 1

image=$1
tracee=$2
testname=$3
kvmaccel=$4
isnoncore=$5
cpus=$6 # optional
mem=$7 # optional

error_syntax() {
  echo ""
  echo -n "ERROR: "
  echo $@
  echo ""
  echo "syntax: $0 [image] [tracee_dir] [TRC-X] [kvm|tcg] [0|1] [cpus] [memory]"
  echo ""
  exit 1
}

# check where the image is coming from (if inside container)

image_name=$image

if [[ -f ./kernels/$image.vmlinuz ]]; then
  vmlinuz=./kernels/$image.vmlinuz
  initrd=./kernels/$image.initrd
else
  vmlinuz=./kernels-copy/$image.vmlinuz
  initrd=./kernels-copy/$image.initrd
fi

if [[ -f ./images-copy/$image ]]; then
  image=./images-copy/$image
else
  image=./images/$image
fi

qemu-img info $image | grep -q raw && format="raw"
qemu-img info $image | grep -q qcow2 && format="qcow2"

# check if kernel needs initrd

cmd_initrd=""
[[ -f $initrd ]] && cmd_initrd="-initrd $initrd"

# regular checks

if [[ ! -f $image ]]; then
  error_syntax "image file $image does not exist"
fi

if [[ ! -f $vmlinuz ]]; then
  error_syntax "vmlinuz file $vmlinuz does not exist"
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

if [[ $isnoncore -ne 0 && $isnoncore -ne 1 ]]; then
  error_syntax "non core should be either 0 or 1"
fi

# amount of vpus
if [[ $cpus -ne 2 && $cpus -ne 4 && $cpus -ne 6 && $cpus -ne 8 ]]; then
  error_syntax "should provide amount of cpus"
fi

# amount of memory
if [[ $mem -ne 2 && $mem -ne 4 && $mem -ne 6 && $mem -ne 8 ]]; then
  error_syntax "should provide amount of mem"
fi

# create tracee source directory filesystem (as a 2nd disk)
# NOTE: idea here is to avoid using virtiofs and/or p9 filesystems

tempfile=$(mktemp)
tempdir=$(mktemp -d)
truncate -s 300M $tempfile
mkfs.ext4 -Ltracee $tempfile

mount $tempfile $tempdir
rm -rf $tempdir/load+found

rsync -avz \
  $tracee/ \
  --exclude=3rdparty/btfhub/* \
  --exclude=3rdparty/btfhub-archive/* \
  --exclude=tests/distro* \
  $tempdir/

ouid=$(stat -c %u $tracee/LICENSE)
ogid=$(stat -c %g $tracee/LICENSE)

umount $tempdir
rmdir $tempdir

# kernel cmdline
cmd_kernel=$cmd_kernel"root=LABEL=$image_name "
cmd_kernel=$cmd_kernel"console=ttyS0 "
cmd_kernel=$cmd_kernel"testname=$testname "
cmd_kernel=$cmd_kernel"isnoncore=$isnoncore "
cmd_kernel=$cmd_kernel"selinux=0 "
cmd_kernel=$cmd_kernel"apparmor=0 "
cmd_kernel=$cmd_kernel"systemd.unified_cgroup_hierarchy=false "
cmd_kernel=$cmd_kernel"net.ifnames=0"

# run qemu with 20 minutes timeout (needed because of kernel soft/hard lockups)

timeout --preserve-status --foreground --signal=9 20m \
qemu-system-x86_64 \
  -name guest=$image \
  -machine accel=$kvmaccel \
  --cpu max --smp $cpus -m ${mem}G \
  -rtc base=utc,clock=vm,driftfix=none \
  -boot c \
  -display none \
  -serial stdio \
  -kernel $vmlinuz \
  $cmd_initrd \
  -append "$cmd_kernel" \
  -netdev user,id=mynet,net=192.168.76.0/24,dhcpstart=192.168.76.9 \
  -device virtio-net-pci,netdev=mynet \
  -device virtio-scsi-pci,id=scsi \
  -device scsi-hd,drive=hd0 \
  -drive if=none,id=hd0,file=$image,format=$format,index=0 \
  -device scsi-hd,drive=hd1 \
  -drive if=none,id=hd1,file=$tempfile,format=raw,index=1

tempdir=$(mktemp -d)
mount $tempfile $tempdir
chown -R $ouid:$ogid $tempdir/

# clean up tracee source directory filesystem

rsync -avz --delete \
  $tempdir/ \
  --exclude=3rdparty/btfhub/* \
  --exclude=3rdparty/btfhub-archive/* \
  --exclude=tests/distro* \
  $tracee/

umount $tempdir
rmdir $tempdir
rm -rf $tempfile

# vi:syntax=sh:expandtab:smarttab:tabstop=2:shiftwidth=2:softtabstop=2
