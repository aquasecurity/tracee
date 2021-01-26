#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' 

VERSION_LIMIT=5.8
CURRENT_VERSION=$(uname -r | cut -d '.' -f1-2)

# Check major version
MAJOR_VERSION_LIMIT=$(echo $VERSION_LIMIT | cut -d '.' -f1)
MAJOR_CURRENT_VERSION=$(echo $CURRENT_VERSION | cut -d '.' -f1)
if (( $(echo "$MAJOR_CURRENT_VERSION < $MAJOR_VERSION_LIMIT") |bc -l)); then
    echo -e "${RED}[*] OUTDATED MAJOR KERNEL VERSION${NC}"
    exit 1
fi

# Check minor version
MINOR_VERSION_LIMIT=$(echo $VERSION_LIMIT | cut -d '.' -f2)
MINOR_CURRENT_VERSION=$(echo $CURRENT_VERSION | cut -d '.' -f2)
if (( $(echo "$MINOR_CURRENT_VERSION < $MINOR_VERSION_LIMIT") |bc -l)); then
    echo -e "${RED}[*] OUTDATED MINOR KERNEL VERSION${NC}"
    exit 1
else
    echo -e "${GREEN}[*] SUFFICIENT KERNEL VERSION${NC}"
fi

make -f $PWD/Makefile
if [ $? -ne 0 ]; then
    echo -e "${RED}[*] MAKE FAILED"
    exit 2
else
    echo -e "${GREEN}[*] MAKE RAN SUCCESFULLY${NC}"
fi

timeout 5 $PWD/self
RETURN_CODE=$?
if [ $RETURN_CODE -eq 124 ]; then
    echo -e "${RED}[*] SELFTEST TIMEDOUT${NC}"
    exit 3
fi

if [ $RETURN_CODE -ne 0 ]; then
    echo -e "${RED}[*] ERROR IN SELFTEST${NC}"
    exit 4
fi

echo -e "${GREEN}[*] SUCCESS${NC}"
exit 0
