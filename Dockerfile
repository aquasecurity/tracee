FROM golang:1.13-buster as builder

RUN DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y --no-install-recommends libtinfo5

WORKDIR /bcc
# aquasec/bcc-builder is built from the upstream bcc dockerfile using:
# docker build --target=builder -t aquasec/bcc-builder:latest --file Dockerfile.ubuntu .
COPY --from=aquasec/bcc-builder:latest /root/bcc/libbcc_*.deb /bcc/
RUN DEBIAN_FRONTEND=noninteractive dpkg -i libbcc_*.deb && rm -rf /bcc

WORKDIR /tracee
COPY . /tracee
RUN make build


# must run privileged and with linux headers mounted
# docker run --name tracee --rm --privileged --pid=host -v /lib/modules/:/lib/modules/:ro -v /usr/src:/usr/src:ro aquasec/tracee
FROM ubuntu:eoan

RUN DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y --no-install-recommends libelf1 libtinfo5

WORKDIR /bcc
# aquasec/bcc-builder is built from the upstream bcc dockerfile using:
# docker build --target=builder -t aquasec/bcc-builder:latest --file Dockerfile.ubuntu .
COPY --from=aquasec/bcc-builder:latest /root/bcc/libbcc_*.deb /bcc/
RUN DEBIAN_FRONTEND=noninteractive dpkg -i libbcc_*.deb && rm -rf /bcc

WORKDIR /tracee
COPY --from=builder /tracee/dist/tracee /tracee/entrypoint.sh ./
ENTRYPOINT ["./entrypoint.sh", "./tracee"]
