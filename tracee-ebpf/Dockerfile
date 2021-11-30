ARG BASE=fat

FROM alpine:3.15 as builder
RUN apk --no-cache update && apk --no-cache add git go clang llvm make gcc libc6-compat coreutils linux-headers musl-dev elfutils-dev libelf-static zlib-static
WORKDIR /tracee

FROM builder as build
ARG VERSION
COPY . /tracee
RUN make build VERSION=$VERSION

# base image for tracee which includes all tools to build the bpf object at runtime
FROM alpine:3.15 as fat
RUN apk --no-cache update && apk --no-cache add clang llvm make gcc libc6-compat coreutils linux-headers musl-dev elfutils-dev libelf-static zlib-static

# base image for tracee which includes minimal dependencies and expects the bpf object to be provided at runtime
FROM alpine:3.15 as slim
RUN apk --no-cache update && apk --no-cache add libc6-compat elfutils-dev

# If running on a BTF enabled kernel:
# docker run --name tracee --pid=host --cgroupns=host --rm --privileged -it aquasec/tracee:latest
# If running on a BTF disabled kernel, you must mount linux headers:
# docker run --name tracee --pid=host --cgroupns=host --rm --privileged --pid=host -v /lib/modules/:/lib/modules/:ro -v /usr/src:/usr/src:ro -v /tmp/tracee:/tmp/tracee aquasec/tracee
FROM $BASE
WORKDIR /tracee
COPY --from=build /tracee/dist/tracee-ebpf ./
ENTRYPOINT ["./tracee-ebpf"]
