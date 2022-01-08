#!/bin/sh

cp /bin/ls /tmp/packed_ls
upx /tmp/packed_ls
/tmp/packed_ls