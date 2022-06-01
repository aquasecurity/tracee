#!/bin/bash -ex

. ./00-config

command -v parted || exit 1
command -v losetup || exit 1
command -v mktemp || exit 1
command -v grep || exit 1
command -v truncate || exit 1
command -v mount || exit 1
command -v rsync || exit 1

cleanup() {
  echo waiting to cleanup; sleep 5
  [[ $destdir != "" ]] && umount $destdir || true
  [[ $tempdir != "" ]] && umount $tempdir/boot/efi || true
  [[ $tempdir != "" ]] && umount $tempdir || true
  [[ $un_fat != "" ]] && losetup -d $un_fat || true
  [[ $un_ext4 != "" ]] && losetup -d $un_ext4 || true
  [[ $tempdir != "" ]] && rmdir $tempdir || true
}
trap cleanup EXIT

[[ ! -d ./images ]] && mkdir ./images
[[ ! -d ./kernels ]] && mkdir ./kernels

for image in $IMAGES; do
  image_name=${image/vm-/}

  # destination ext4 loop file
  if [[ ! -f ./images/$image_name ]]; then
      truncate -s 5G ./images/$image_name
      mkfs.ext4 ./images/$image_name
  #else
      #rm -f ./images/$(basename $image)
  fi

  tempdir=$(mktemp -d)
  destdir=$(mktemp -d)

  # ext4 partition from image
  sec_ext4=$(parted ./images-full/$image_name UNIT b print 2>&1 | grep ext4 | awk '{print $2}' | sed 's:B$::g')
  un_ext4=$(losetup -f)
  losetup -f ./images-full/$image_name -o $sec_ext4

  # efi partition from image
  sec_fat=$(parted ./images-full/$image_name UNIT b print 2>&1 | grep fat32 | awk '{print $2}' | sed 's:B$::g')
  un_fat=$(losetup -f)
  losetup -f ./images-full/$image_name -o $sec_fat

  # mount them for the copy
  mount ./images/$image_name $destdir
  mount $un_ext4 $tempdir
  mount $un_fat $tempdir/boot/efi

  #rsync -av --delete $tempdir/ $destdir/
  #rsync -av $tempdir/ $destdir/

  # fstab fix
  echo "/dev/sda / ext4 errors=remount-ro 0 1" > $destdir/etc/fstab

  # qemu entrypoint execution at ttyS0
  mkdir -p $destdir/etc/systemd/system/serial-getty@ttyS0.service.d/
  echo """[Service]
User=root
Environment=HOME=/root
WorkingDirectory=/
ExecStart=
ExecStart=-/init
StandardInput=tty
StandardOutput=tty
Restart=always
[Install]
WantedBy=getty.target
""" \
| tee $destdir/etc/systemd/system/serial-getty@ttyS0.service.d/override.conf

  # take entrypoint inside
  cp ./files/qemu-entrypoint.sh $destdir/init
  chmod +x $destdir/init

  # bring kernel outside
  cp $tempdir/boot/*init* ./kernels/$image_name.initrd
  cp $tempdir/boot/*vmlinuz* ./kernels/$image_name.vmlinuz
  cp $tempdir/boot/*config* ./kernels/$image_name.config

  echo waiting to cleanup; sleep 5
  [[ $destdir != "" ]] && umount $destdir || true
  [[ $tempdir != "" ]] && umount $tempdir/boot/efi || true
  [[ $tempdir != "" ]] && umount $tempdir || true
  [[ $un_fat != "" ]] && losetup -d $un_fat || true
  [[ $un_ext4 != "" ]] && losetup -d $un_ext4 || true
  [[ $tempdir != "" ]] && rmdir $tempdir || true
done

chown -R $(whoami): ./images
chown -R $(whoami): ./kernels

# cleanup at EXIT

# vi:syntax=sh:expandtab:smarttab:tabstop=2:shiftwidth=2:softtabstop=2
