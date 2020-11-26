ARG BASE=fat

FROM golang:1.15-buster as builder
RUN echo "deb http://apt.llvm.org/buster/ llvm-toolchain-buster-9 main" >> /etc/apt/sources.list && apt-key adv --keyserver hkps://keyserver.ubuntu.com --recv-keys 15CF4D18AF4F7421 && \
    DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y --no-install-recommends libelf-dev llvm-9-dev clang-9 && \ 
    (for tool in "clang" "llc" "llvm-strip"; do path=$(which $tool-9) && ln -s $path ${path%-*}; done)
WORKDIR /tracee

ARG VERSION
FROM tracee-builder as build
ENV VERSION=$VERSION
COPY . /tracee
RUN make build

# base image for tracee which includes all tools to build the bpf object at runtime
FROM ubuntu:focal as fat
RUN DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y ca-certificates gnupg && \
    echo "deb http://apt.llvm.org/buster/ llvm-toolchain-buster-9 main" >> /etc/apt/sources.list && apt-key adv --keyserver hkps://keyserver.ubuntu.com --recv-keys 15CF4D18AF4F7421 && \
    DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y --no-install-recommends libelf-dev llvm-9-dev clang-9 && \ 
    (for tool in "clang" "llc" "llvm-strip"; do path=$(which $tool-9) && ln -s $path ${path%-*}; done)

# base image for tracee which includes minimal dependencies and expects the bpf object to be provided at runtime
FROM ubuntu:focal as slim
RUN DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y libelf1

# must run privileged and with linux headers mounted
# docker run --name tracee --rm --privileged --pid=host -v /lib/modules/:/lib/modules/:ro -v /usr/src:/usr/src:ro -v /tmp/tracee:/tmp/tracee aquasec/tracee
FROM $BASE
WORKDIR /tracee
COPY --from=build /tracee/dist/tracee /tracee/entrypoint.sh ./
ENTRYPOINT ["./entrypoint.sh", "./tracee"]
