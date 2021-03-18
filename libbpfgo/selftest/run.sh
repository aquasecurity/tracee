#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' 

for d in */
do
    echo -e "${GREEN}[*] RUNNING $d ${NC}"
    ( cd $d && bash "run.sh" )
done

