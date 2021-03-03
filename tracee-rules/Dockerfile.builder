FROM golang:1.16-buster as builder
RUN DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y --no-install-recommends curl && \
    curl -L -o /usr/bin/opa https://github.com/open-policy-agent/opa/releases/download/v0.26.0/opa_linux_amd64 && chmod 755 /usr/bin/opa
WORKDIR /tracee
