FROM golang:1.15-buster as builder
RUN echo "deb http://apt.llvm.org/buster/ llvm-toolchain-buster-9 main" >> /etc/apt/sources.list && apt-key adv --keyserver hkps://keyserver.ubuntu.com --recv-keys 15CF4D18AF4F7421 && \
    DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y --no-install-recommends libelf-dev llvm-9-dev clang-9 curl && \
    (for tool in "clang" "llc" "llvm-strip"; do path=$(which $tool-9) && ln -s $path ${path%-*}; done) && \
    curl -L -o /usr/bin/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64 && chmod 755 /usr/bin/opa
WORKDIR /tracee
