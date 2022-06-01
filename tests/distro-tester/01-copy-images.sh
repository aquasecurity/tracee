#!/bin/bash -ex

. ./00-config

[[ ! -d ./images-full ]] && mkdir ./images-full

for image in $IMAGES; do
  if [[ -f ${LXD_STORAGE}/$image/root.img ]]; then
    cp ${LXD_STORAGE}/$image/root.img ./images-full/${image/vm-/}
  else
    echo "skipping non-existent $image..."
  fi
done

chown -R $(whoami): ./images*

# vi:syntax=sh:expandtab:smarttab:tabstop=2:shiftwidth=2:softtabstop=2
