#!/bin/sh

case $@ in
  "TRC-2")
    ./trc2.sh
    ;;
  "TRC-3")
    ./trc3.sh
    ;;
  "TRC-4")
    ./trc4.sh
    ;;
  "TRC-9")
    ./trc9.sh
    ;;
  "TRC-10")
    ./trc10.sh
    ;;
  "TRC-11")
    ./trc11.sh
    ;;
  *)
    echo "invalid args specified:" "$@"
esac