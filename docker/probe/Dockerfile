# Builds the spike probe and runs it against a live Analysis Services instance.
#
# Linux, because the NTLM path needs gss-ntlmssp: macOS has no NTLM GSS
# mechanism at all, and Apple's GSS.framework exports no gss_wrap_iov either
# (research D11). The container reaches OUT to the instance; nothing listens, so
# no port is published.
#
# Works with both `container build` (Apple) and `docker build`.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build pkg-config \
        libkrb5-dev gss-ntlmssp ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src/

# Only the probe and what it needs. The DuckDB submodule is not required and is
# not built here: this image exists to exercise the protocol against a real
# server, which is the milestone that precedes any DuckDB surface.
RUN cmake -S . -B build/probe -G Ninja -DCMAKE_BUILD_TYPE=Debug \
    && cmake --build build/probe --target xmla_probe

ENTRYPOINT ["/src/build/probe/xmla_probe"]
