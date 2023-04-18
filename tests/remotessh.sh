#!/bin/bash

die() {
    echo ${@}
    exit 1
}

. /etc/os-release

CMDS="sshpass"

# variables

SSH_IP="${SSH_IP:=154.53.35.3}"
SSH_PORT="${SSH_PORT:=2222}"
SSH_USER="${SSH_USER:=github}"
SSH_PASS="${SSH_PASS:=changeme}"

HOST_IP="${HOST_IP:=0.0.0.0}"
HOST_PORT=$((8000 + ($RANDOM % 999))) # port to direct to given IP

LOCAL_IP=127.0.0.1 # ip to be external to the world
LOCAL_PORT=22      # port to be external to the world

# environment

GOPATH="${GOPATH:=/tmp/go}"
GOCACHE="${GOCACHE:=/tmp/go-cache}"
GOROOT="${GOROOT:=/usr/local/go}"

# sanity checks

ping -w3 -c1 $SSH_IP >/dev/null 2>&1 || die "can't access $SSH_IP"

# set user password

if [[ $ID == ubuntu ]]; then
    HOST_USER="ubuntu"
    HOST_SERVICE="ssh"
fi
if [[ $ID == almalinux ]]; then
    HOST_USER="ec2-user"
    HOST_SERVICE="sshd"
fi

printf "changeme\nchangeme\n" | passwd $HOST_USER 2>&1 > /dev/null 2>&1
sed -Ei 's:.*PasswordAuthentication.*:PasswordAuthentication yes:g' /etc/ssh/sshd_config
systemctl restart $HOST_SERVICE

# requirements

if [[ $UID -eq 0 ]]; then
    echo
    echo Updating Package List ...
    echo
    if [[ $ID == ubuntu ]]; then
        apt-get update -y 2>&1 >/dev/null
    fi
fi

for cmd in $CMDS; do
    if [[ $UID -eq 0 ]]; then
        if [[ $ID == ubuntu ]]; then
            dpkg -l | grep -q $cmd || apt-get install -y $cmd 2>&1 > /dev/null
        fi
        if [[ $ID == almalinux ]]; then
            rpm -aq | grep -q $cmd || yum install -y $cmd 2>&1 > /dev/null
        fi
    fi
    command -v $cmd >/dev/null || die "$cmd not found"
done

# execute debug shell

echo
echo "######                                #####                              "
echo "#     # ###### #####  #    #  ####   #     # #    # ###### #      #      "
echo "#     # #      #    # #    # #    #  #       #    # #      #      #      "
echo "#     # #####  #####  #    # #        #####  ###### #####  #      #      "
echo "#     # #      #    # #    # #  ###        # #    # #      #      #      "
echo "#     # #      #    # #    # #    #  #     # #    # #      #      #      "
echo "######  ###### #####   ####   ####    #####  #    # ###### ###### ###### "
echo
echo "You may now connect:"
echo
echo "ssh -p $HOST_PORT $HOST_USER@$SSH_IP (pw: changeme)"
echo
echo "To get access to the debug shell."
echo
echo "NOTE 1: You may also use VSCODE for remove development."
echo "NOTE 2: Please change your password as soon as you connect."
echo "NOTE 3: Shutdown the VM when you're done !!!"
echo

sshpass -p $SSH_PASS \
    ssh \
    -oStrictHostKeyChecking=no \
    -oUserKnownHostsFile=/dev/null \
    -p $SSH_PORT $SSH_USER@$SSH_IP -N \
    -R $HOST_IP:$HOST_PORT:$LOCAL_IP:$LOCAL_PORT &

# sleep forever (until VM shuts down)

while true; do
    sleep 30;
    echo "You can: ssh -p $HOST_PORT $HOST_USER@$SSH_IP (pw: changeme)."
done
