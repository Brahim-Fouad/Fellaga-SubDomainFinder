FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends bind9 bind9-utils dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY named.conf /etc/bind/named.conf
COPY zones /etc/bind/zones
COPY start.sh /usr/local/bin/start-dns-lab
RUN chmod +x /usr/local/bin/start-dns-lab

EXPOSE 5353/udp 5353/tcp
ENTRYPOINT ["/usr/local/bin/start-dns-lab"]
