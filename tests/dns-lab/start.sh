#!/usr/bin/env bash
set -euo pipefail

cp /etc/bind/zones/nsec.lab.test.zone /var/cache/bind/nsec.lab.test.zone
cp /etc/bind/zones/nsec3.lab.test.zone /var/cache/bind/nsec3.lab.test.zone
cd /var/cache/bind
dnssec-keygen -q -a ECDSAP256SHA256 -n ZONE nsec.lab.test >/dev/null
dnssec-keygen -q -a ECDSAP256SHA256 -f KSK -n ZONE nsec.lab.test >/dev/null
dnssec-signzone -S -o nsec.lab.test -f nsec.lab.test.zone.signed nsec.lab.test.zone >/dev/null
dnssec-keygen -q -a ECDSAP256SHA256 -n ZONE nsec3.lab.test >/dev/null
dnssec-keygen -q -a ECDSAP256SHA256 -f KSK -n ZONE nsec3.lab.test >/dev/null
dnssec-signzone -S -3 A1B2C3 -o nsec3.lab.test -f nsec3.lab.test.zone.signed nsec3.lab.test.zone >/dev/null
exec named -g -c /etc/bind/named.conf
