ARG BASE=fat

FROM golang:alpine as builder
RUN apk --no-cache update && apk --no-cache add git clang llvm make gcc libc6-compat coreutils linux-headers musl-dev elfutils-dev libelf-static zlib-static
WORKDIR /tracee

FROM builder as build
ARG VERSION
COPY . /tracee
RUN make

# base image for tracee which includes all tools to build the bpf object at runtime
FROM alpine as fat
RUN apk --no-cache update && apk --no-cache add clang llvm make gcc libc6-compat coreutils linux-headers musl-dev elfutils-dev libelf-static zlib-static

# base image for tracee which includes minimal dependencies and expects the bpf object to be provided at runtime
FROM alpine as slim
RUN apk --no-cache update && apk --no-cache add libc6-compat elfutils-dev

# final image
FROM $BASE
WORKDIR /tracee

COPY --from=falcosecurity/falcosidekick@sha256:a32d8850d51e9b096a09f4ae73ba6cde038c3fe1fd9c58baf76333dfda7e7bbd /app/falcosidekick ./
COPY --from=build /tracee/dist/tracee-ebpf /tracee/dist/tracee-rules /tracee/entrypoint.sh ./
COPY --from=build /tracee/dist/rules ./rules

ENTRYPOINT ["./entrypoint.sh"]
