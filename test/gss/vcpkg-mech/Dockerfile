# Three arms of one experiment, differing ONLY in which krb5 provides the
# GSSAPI mechglue. Same probe, same gss-ntlmssp, same container.
#
#   A  system krb5              what local builds and this repo's CI link
#   B  vcpkg krb5, static       what the community-extensions registry would ship
#   C  vcpkg krb5 + sysconfdir  B with autoconf's sysconfdir pointed at /etc
#
# A is the control: if A does not register NTLM then the container is wrong and
# the comparison proves nothing, so run.sh reports INCONCLUSIVE rather than
# blaming B.
#
# NOTE this image is NOT the registry's build environment. It is ubuntu:24.04,
# chosen so the control arm has a system krb5 to compare against. The registry
# builds in quay.io/pypa/manylinux_2_28_{x86_64,aarch64} (AlmaLinux 8), which
# ships no system krb5 and -- see README.md -- no autoconf-archive either, so
# the port cannot even be built there. This probe measures what the artifact
# WOULD do, on the assumption that the build is somehow made to succeed.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

# autoconf-archive is REQUIRED, and not because krb5 needs its macros -- krb5
# vendors ax_pthread.m4 and ax_recursive_eval.m4 itself. vcpkg-make checks for
# it independently: vcpkg_make.cmake runs `aclocal --dry-run` over its own probe
# configure.ac and greps stderr for "autoconf-archive ... missing", then raises
# FATAL_ERROR listing the whole autotools set. So it gates every vcpkg autotools
# port on Linux whatever the port itself vendors. Verified by removing it from
# this list, which fails the krb5 install in about 20 seconds.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libkrb5-dev gss-ntlmssp ca-certificates \
        cmake git curl zip unzip tar pkg-config \
        autoconf autoconf-archive automake libtool bison python3 \
    && rm -rf /var/lib/apt/lists/*

# The premise: gss-ntlmssp dropped a mech.d entry naming the NTLM OID and the
# .so that implements it. Printed rather than asserted, because seeing the file
# is what makes the three arms legible.
RUN echo "=== the host's mechanism config ===" && cat /etc/gss/mech.d/*.conf

COPY mech_registration.c /
RUN gcc -O0 -g -Wall -o /mechs_system /mech_registration.c $(pkg-config --libs krb5-gssapi)

# Pinned to the vcpkg commit the registry selects for the lane that is not
# DUCKDB_LATEST_STABLE (community-extensions/.github/workflows/build.yml). The
# stable lane pins 84bab45, where ports/krb5 is 1.22.1 and declares host
# vcpkg-cmake unconditionally -- a different port revision this does not cover.
ARG VCPKG_COMMIT=cd61e1e26a038e82d6550a3ebbe0fbbfe7da78e3
RUN git clone -q https://github.com/microsoft/vcpkg /opt/vcpkg \
 && git -C /opt/vcpkg checkout -q ${VCPKG_COMMIT} \
 && /opt/vcpkg/bootstrap-vcpkg.sh -disableMetrics >/dev/null

# --- arm B: the port exactly as the registry would build it ----------------
RUN /opt/vcpkg/vcpkg install krb5 --triplet x64-linux-release \
        --x-install-root=/opt/vcpkg-stock > /tmp/stock.log 2>&1 \
    || { tail -30 /tmp/stock.log; exit 1; }

# --- arm C: the same port, sysconfdir/localstatedir pointed at the host ----
COPY sysconfdir_overlay.py /
RUN mkdir -p /overlay && cp -r /opt/vcpkg/ports/krb5 /overlay/krb5 \
 && python3 /sysconfdir_overlay.py /overlay/krb5 \
 && /opt/vcpkg/vcpkg install krb5 --triplet x64-linux-release \
        --overlay-ports=/overlay --x-install-root=/opt/vcpkg-fixed \
        > /tmp/fixed.log 2>&1 \
    || { tail -30 /tmp/fixed.log; exit 1; }

# What each build actually baked in. This is the mechanism behind the verdict,
# so it is shown at build time rather than inferred from the probe's result.
RUN echo "=== MECH_CONF as baked into each static libgssapi_krb5.a ===" \
 && for t in stock fixed; do \
      printf '  %-6s ' "$t"; \
      strings /opt/vcpkg-$t/x64-linux-release/lib/libgssapi_krb5.a \
        | grep -E '^/.*/gss/mech$' | sort -u | tr '\n' ' '; \
      echo; \
    done

# Both vcpkg arms must link krb5 statically, or they are not measuring what a
# registry artifact does and the whole comparison is void.
RUN for t in stock fixed; do \
      gcc -O0 -g -Wall -o /mechs_$t /mech_registration.c \
        -I/opt/vcpkg-$t/x64-linux-release/include \
        $(PKG_CONFIG_PATH=/opt/vcpkg-$t/x64-linux-release/lib/pkgconfig \
          pkg-config --static --libs krb5-gssapi) || exit 1; \
      if ldd /mechs_$t | grep -qEi 'krb5|gssapi'; then \
        echo "arm $t links krb5 dynamically; it is not what it claims to be"; \
        exit 1; \
      fi; \
    done \
 && echo "arms B and C link krb5 statically, as a registry artifact would"

COPY run.sh /
CMD ["/bin/bash", "/run.sh"]
