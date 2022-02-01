#!/bin/sh

nc -l 4444 &
sleep 1
./injector load.so $(pidof nc)