FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libkrb5-dev krb5-kdc krb5-admin-server krb5-user \
    && rm -rf /var/lib/apt/lists/*
COPY wrap_iov_layout.c /probe.c
RUN gcc -O0 -g -Wall -o /probe /probe.c -lgssapi_krb5 -lkrb5
COPY run.sh /run.sh
RUN chmod +x /run.sh
CMD ["/run.sh"]
