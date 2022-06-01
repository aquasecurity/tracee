FROM ubuntu:jammy

ARG IMAGE

RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install -y --no-install-recommends coreutils findutils && \
    apt-get install -y --no-install-recommends bash vim curl rsync git && \
    apt-get install -y --no-install-recommends iproute2 openssh-client && \
    apt-get install -y --no-install-recommends ssl-cert ca-certificates && \
    apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils

COPY . /tester/

RUN mkdir -p /tracee && \
    mkdir -p /tester && \
    rm -f /root/.profile && \
    rm -f /root/.bashrc && \
    echo "export PS1=\"\u@\h \w $ \"" > /root/.bashrc && \
    echo "alias ls=\"ls --color\"" >> /root/.bashrc && \
    ln -s /root/.bashrc /root/.profile && \
    git config --global --add safe.directory /tracee

ENV IMAGE=$IMAGE

ENTRYPOINT /tester/files/docker-entrypoint.sh $IMAGE

USER root
ENV HOME /root
WORKDIR /tracee
