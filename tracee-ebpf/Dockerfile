ARG BASE=fat

FROM golang:alpine as builder
RUN apk --no-cache update && apk --no-cache add git clang llvm make gcc libc6-compat coreutils linux-headers musl-dev elfutils-dev libelf-static zlib-static
WORKDIR /tracee

FROM builder as build
ARG VERSION
COPY . /tracee
RUN make build VERSION=$VERSION

# base image for tracee which includes all tools to build the bpf object at runtime
FROM alpine as fat
RUN apk --no-cache update && apk --no-cache add clang llvm make gcc libc6-compat coreutils linux-headers musl-dev elfutils-dev libelf-static zlib-static

# base image for tracee which includes minimal dependencies and expects the bpf object to be provided at runtime
FROM alpine as slim
RUN apk --no-cache update && apk --no-cache add libc6-compat elfutils-dev

# must run privileged and with linux headers mounted
# docker run --name tracee --rm --privileged --pid=host -v /lib/modules/:/lib/modules/:ro -v /usr/src:/usr/src:ro -v /tmp/tracee:/tmp/tracee aquasec/tracee
FROM $BASE
WORKDIR /tracee
COPY --from=build /tracee/dist/tracee /tracee/entrypoint.sh ./
ENTRYPOINT ["./entrypoint.sh", "./tracee"]
