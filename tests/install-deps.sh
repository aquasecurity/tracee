#!/bin/sh

apt-get update

# TRC-2 Anti-debugging
apt-get install -y strace

# TRC-3 Code Injection
chmod +x ./injector
apt-get install -y ncat gcc

# TRC-4 Dynamic code loading
apt-get install -y upx

# k8s service account tokens
mkdir -p /var/run/secrets/kubernetes.io/serviceaccount
mkdir -p /etc/kubernetes/pki
echo "test" > /var/run/secrets/kubernetes.io/serviceaccount/token
echo "test" > /etc/kubernetes/pki/token
echo "test" > /authorized_keys

# TRC-14 CGroups Release Agent File Modification
chmod +x ./cdk_linux_amd64