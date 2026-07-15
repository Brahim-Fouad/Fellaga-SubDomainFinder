#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
image="fellaga-dns-lab:local"
container="fellaga-dns-lab-$RANDOM"
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT

docker build -q -t "$image" "$root" >/dev/null
docker run -d --name "$container" -p 127.0.0.1:53535:5353/udp -p 127.0.0.1:53535:5353/tcp "$image" >/dev/null
for _ in $(seq 1 30); do
  dig @127.0.0.1 -p 53535 lab.test SOA +short | grep -q . && break
  sleep 1
done

[[ "$(dig @127.0.0.1 -p 53535 random.lab.test A +short | wc -l)" -eq 2 ]]
dig @127.0.0.1 -p 53535 random.deep.lab.test A +short | grep -q '192.0.2.30'
dig @127.0.0.1 -p 53535 dangling.lab.test CNAME +short | grep -q 'absent.lab.test.'
dig @127.0.0.1 -p 53535 child.lab.test NS +short | grep -q 'ns.child.lab.test.'
[[ "$(dig @127.0.0.1 -p 53535 lab.test AXFR +short | grep -c 'SOA')" -ge 2 ]]
dig @127.0.0.1 -p 53535 refused.lab.test AXFR | grep -q 'Transfer failed'
dig @127.0.0.1 -p 53535 missing.nsec.lab.test A +dnssec | grep -q 'NSEC'
dig @127.0.0.1 -p 53535 missing.nsec3.lab.test A +dnssec | grep -q 'NSEC3'
dig @127.0.0.1 -p 53535 large.lab.test TXT +bufsize=512 | grep -q 'tc'
dig @127.0.0.1 -p 53535 large.lab.test TXT +tcp +short | grep -q '^"aaa'
dig @127.0.0.1 -p 53535 random.hijack.test A +short | grep -q '198.51.100.66'

echo "DNS lab: wildcard, multiniveau, hijack, CNAME pendant, délégation, NSEC, NSEC3, TCP et AXFR validés"
