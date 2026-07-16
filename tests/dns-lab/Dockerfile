FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends bind9 bind9-utils dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY named.conf /etc/bind/named.conf
COPY zones /etc/bind/zones
COPY start.sh /usr/local/bin/start-dns-lab
RUN chmod +x /usr/local/bin/start-dns-lab

EXPOSE 5353/udp 5353/tcp
ENTRYPOINT ["/usr/local/bin/start-dns-lab"]
