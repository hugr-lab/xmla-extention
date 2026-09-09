FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libkrb5-dev gss-ntlmssp ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY wrap_iov_availability.c wrap_split.c /
RUN gcc -O0 -g -Wall -o /wrap_iov_availability /wrap_iov_availability.c -lgssapi_krb5 \
 && gcc -O0 -g -Wall -o /wrap_split /wrap_split.c -lgssapi_krb5
ENV NTLM_USER_FILE=/creds
ENV NTLM_PRINCIPAL=TESTDOM\\probeuser
RUN printf 'TESTDOM:probeuser:probepass\n' > /creds && chmod 600 /creds
CMD ["/bin/sh", "-c", "/wrap_iov_availability; echo; /wrap_split"]
