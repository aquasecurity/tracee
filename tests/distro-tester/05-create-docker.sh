#!/bin/bash -ex

. ./00-config

for image in $IMAGES; do
  image_name=${image/vm-/}

  cp ./kernels/$image_name.vmlinuz ./kernels-copy/$image_name.vmlinuz
  cp ./kernels/$image_name.initrd ./kernels-copy/$image_name.initrd

  cp ./images/$image_name ./images-copy/$image_name

  docker build \
    --build-arg=IMAGE=$(basename $image_name) \
    -t rafaeldtinoco/tracee-distro-tester:$image_name \
    .

  rm ./kernels-copy/$image_name.vmlinuz
  rm ./kernels-copy/$image_name.initrd
  rm ./images-copy/$image_name
done

# vi:syntax=sh:expandtab:smarttab:tabstop=2:shiftwidth=2:softtabstop=2
