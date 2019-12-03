# must run privileged and with linux headers and debugfs mounted 
# docker run --name tracee --rm --privileged -v /lib/modules/:/lib/modules/ -v /usr/src:/usr/src -v /sys/kernel/debug:/sys/kernel/debug tracee:t2
FROM ubuntu:bionic

RUN echo "deb [trusted=yes] http://repo.iovisor.org/apt/bionic bionic main" > /etc/apt/sources.list.d/iovisor.list && \
    apt-get -y update && \
    apt-get -y install python bcc-tools

WORKDIR /tracee
COPY . /tracee
ENTRYPOINT ["python", "start.py"]