#!/bin/bash -ex

. ./00-config

command -v qemu-img || exit 1

for image in $IMAGES; do
  image_name=${image/vm-/}

  qemu-img convert -f raw ./images/$image_name -O qcow2 ./images/$image_name.qcow2

  mv ./images/$image_name images/$image_name.raw
  mv ./images/$image_name.qcow2 ./images/$image_name
done

# vi:syntax=sh:expandtab:smarttab:tabstop=2:shiftwidth=2:softtabstop=2
