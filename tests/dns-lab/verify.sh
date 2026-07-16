#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
image="fellaga-dns-lab:local"
container="fellaga-dns-lab-$RANDOM"
cleanup() {
  local status=$?
  trap - EXIT
  if (( status != 0 )); then
    docker logs "$container" >&2 || true
  fi
  docker rm -f "$container" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

require_fixed() {
  local description="$1" expected="$2"
  if ! grep -F "$expected" >/dev/null; then
    echo "DNS laboratory failure: $description (missing value: $expected)" >&2
    return 1
  fi
}

require_regex() {
  local description="$1" pattern="$2"
  if ! grep -E "$pattern" >/dev/null; then
    echo "DNS laboratory failure: $description (missing pattern: $pattern)" >&2
    return 1
  fi
}

docker build -q -t "$image" "$root" >/dev/null
docker run -d --name "$container" -p 127.0.0.1:53535:5353/udp -p 127.0.0.1:53535:5353/tcp "$image" >/dev/null
ready=0
for _ in $(seq 1 30); do
  if dig @127.0.0.1 -p 53535 lab.test SOA +short | grep -E '.' >/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
if (( ready != 1 )); then
  echo "The DNS laboratory server did not become ready" >&2
  exit 1
fi

random_count="$(dig @127.0.0.1 -p 53535 random.lab.test A +short | wc -l)"
if (( random_count != 2 )); then
  echo "DNS laboratory failure: the rotating wildcard returned $random_count value(s)" >&2
  exit 1
fi
dig @127.0.0.1 -p 53535 random.deep.lab.test A +short |
  require_fixed "multilevel wildcard" "192.0.2.30"
dig @127.0.0.1 -p 53535 dangling.lab.test CNAME +short |
  require_fixed "dangling CNAME" "absent.lab.test."
dig @127.0.0.1 -p 53535 child.lab.test NS +noall +authority |
  require_fixed "child delegation" "ns.child.lab.test."
soa_count="$(dig @127.0.0.1 -p 53535 lab.test AXFR +noall +answer |
  awk '$4 == "SOA" { count++ } END { print count + 0 }')"
if (( soa_count < 2 )); then
  echo "DNS laboratory failure: AXFR contains only $soa_count SOA record(s)" >&2
  exit 1
fi
refused_output="$(dig @127.0.0.1 -p 53535 refused.lab.test AXFR 2>&1 || true)"
printf '%s\n' "$refused_output" | require_fixed "refused AXFR" "Transfer failed"
dig @127.0.0.1 -p 53535 missing.nsec.lab.test A +dnssec |
  require_fixed "NSEC proof" "NSEC"
dig @127.0.0.1 -p 53535 missing.nsec3.lab.test A +dnssec |
  require_fixed "NSEC3 proof" "NSEC3"
dig @127.0.0.1 -p 53535 large.lab.test TXT +bufsize=512 +ignore |
  require_regex "UDP truncation" 'flags:.*\btc\b'
dig @127.0.0.1 -p 53535 large.lab.test TXT +tcp +short |
  require_regex "TCP fallback" '^"aaa'
dig @127.0.0.1 -p 53535 random.hijack.test A +short |
  require_fixed "NXDOMAIN rewriting" "198.51.100.66"

echo "DNS lab: wildcard, multilevel wildcard, hijack, dangling CNAME, delegation, NSEC, NSEC3, TCP, and AXFR validated"
