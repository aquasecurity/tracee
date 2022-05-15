#!/bin/bash -ex

. ./00-config

command -v qemu-img || exit 1

find ./images | grep -q raw || exit 0

for image in $IMAGES; do
  image_name=${image/vm-/}

  mv ./images/$image_name.raw ./images/$image_name
done

# vi:syntax=sh:expandtab:smarttab:tabstop=2:shiftwidth=2:softtabstop=2
