FROM golang:1.13-buster as builder

RUN DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y --no-install-recommends libelf-dev llvm clang

WORKDIR /tracee

COPY . /tracee

RUN make build

# must run privileged and with linux headers mounted
# docker run --name tracee --rm --privileged --pid=host -v /lib/modules/:/lib/modules/:ro -v /usr/src:/usr/src:ro aquasec/tracee
FROM ubuntu:focal

RUN DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y --no-install-recommends libelf1 llvm clang

WORKDIR /tracee

COPY --from=builder /tracee/dist/tracee /tracee/entrypoint.sh ./

ENTRYPOINT ["./entrypoint.sh", "./tracee"]
