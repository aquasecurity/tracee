ARG BASE=fat

FROM golang:1.17-buster as builder
RUN echo "deb http://apt.llvm.org/buster/ llvm-toolchain-buster-12 main" >> /etc/apt/sources.list && apt-key adv --keyserver hkps://keyserver.ubuntu.com --recv-keys 15CF4D18AF4F7421 && \
    DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y --no-install-recommends gawk libelf-dev llvm-12 clang-12 && \
    (for tool in "clang" "llc" "llvm-strip"; do path=$(which $tool-12) && ln -s $path ${path%-*}; done)
WORKDIR /tracee

FROM builder as build
ARG VERSION
COPY . /tracee
RUN make

# base image for tracee which includes all tools to build the bpf object at runtime
FROM golang:1.17-buster as fat
RUN echo "deb http://apt.llvm.org/buster/ llvm-toolchain-buster-12 main" >> /etc/apt/sources.list && apt-key adv --keyserver hkps://keyserver.ubuntu.com --recv-keys 15CF4D18AF4F7421 && \
    DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y --no-install-recommends gawk libelf-dev llvm-12 clang-12 tini && \
    (for tool in "clang" "llc" "llvm-strip"; do path=$(which $tool-12) && ln -s $path ${path%-*}; done)

# base image for tracee which includes minimal dependencies and expects the bpf object to be provided at runtime
FROM debian:buster-slim as slim
RUN apt-get update && apt-get install -y libelf-dev

# final image
FROM $BASE
ARG VERSION
ARG BUILD_DATE
ARG VCS_BRANCH
ARG VCS_REF
WORKDIR /tracee

COPY --from=build /tracee/dist/tracee-ebpf /tracee/dist/tracee-rules /tracee/entrypoint.sh ./
COPY --from=build /tracee/dist/rules ./rules
COPY --from=build /tracee/tracee-rules/templates /tracee/templates/

LABEL org.label-schema.build-date=$BUILD_DATE \
    org.label-schema.description="Linux Runtime Security and Forensics using eBPF" \
    org.label-schema.name="tracee" \
    org.label-schema.schema-version="1.0" \
    org.label-schema.vcs-branch=$VCS_BRANCH \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.vcs-url="https://github.com/aquasecurity/tracee" \
    org.label-schema.vendor="Aqua Security" \
    org.label-schema.version=$VERSION

ENV TINI_SUBREAPER=true

ENTRYPOINT ["/usr/bin/tini", "-g", "--", "./entrypoint.sh"]