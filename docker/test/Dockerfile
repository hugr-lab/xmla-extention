# The build and test environment: dependencies only, no source.
#
# Unlike docker/probe/Dockerfile this does NOT copy the repository in. The full
# DuckDB build takes tens of minutes and produces a build tree of about a
# gigabyte, so the repository and a build directory are bind-mounted instead and
# the tree survives between runs. A COPY here would rebuild DuckDB from scratch
# on every source edit, which makes the loop unusable.
#
# Works with both `container build` (Apple) and `docker build`.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# gss-ntlmssp is the reason this runs on Linux at all: macOS ships no NTLM GSS
# mechanism, and Apple's GSS.framework exports no gss_wrap_iov either
# (research D11). libkrb5-dev provides the GSSAPI the extension links.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build pkg-config git \
        libkrb5-dev gss-ntlmssp ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
