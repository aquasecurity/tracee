#!/bin/bash

GREEN='    \033[0;32m'
RED='    \033[0;31m'
NC='\033[0m' 

VERSION_LIMIT=4.3
CURRENT_VERSION=$(uname -r | cut -d '.' -f1-2)

# Check that kernel version is big enough
if [ $(echo "$CURRENT_VERSION"$'\n'"$VERSION_LIMIT" | sort -V | head -n1) != "$VERSION_LIMIT" ]; then
    echo -e "${RED}[*] OUTDATED KERNEL VERSION${NC}"
    exit 1
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
