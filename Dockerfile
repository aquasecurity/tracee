# must run privileged and with linux headers 
# docker run --name tracee --rm --privileged -v /lib/modules/:/lib/modules/ -v /usr/src:/usr/src tracee
FROM ubuntu:bionic

RUN echo "deb [trusted=yes] http://repo.iovisor.org/apt/bionic bionic main" > /etc/apt/sources.list.d/iovisor.list && \
    apt-get -y update && \
    apt-get -y install python bcc-tools

WORKDIR /tracee
COPY . /tracee
ENTRYPOINT ["./entrypoint.sh", "python", "start.py"]