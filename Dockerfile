ARG BASE=fat

FROM golang:1.16-alpine as builder
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
ARG VERSION
ARG BUILD_DATE
ARG VCS_BRANCH
ARG VCS_REF
WORKDIR /tracee

COPY --from=build /tracee/dist/tracee-ebpf /tracee/dist/tracee-rules /tracee/entrypoint.sh ./
COPY --from=build /tracee/dist/rules ./rules
COPY --from=build /tracee/tracee-rules/templates/falcosidekick.tmpl /tracee/tracee-rules/templates/rawjson.tmpl /tracee/templates/

LABEL org.label-schema.build-date=$BUILD_DATE \
    org.label-schema.description="Linux Runtime Security and Forensics using eBPF" \
    org.label-schema.name="tracee" \
    org.label-schema.schema-version="1.0" \
    org.label-schema.vcs-branch=$VCS_BRANCH \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.vcs-url="https://github.com/aquasecurity/tracee" \
    org.label-schema.vendor="Aqua Security" \
    org.label-schema.version=$VERSION

ENTRYPOINT ["./entrypoint.sh"]
