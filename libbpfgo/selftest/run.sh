#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' 

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

for d in ${DIR}/*/
do
    echo -e "${GREEN}[*] RUNNING $d ${NC}"
    ( cd $d && bash "run.sh" )
done

