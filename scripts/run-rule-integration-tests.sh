#!/usr/bin/env bash
# Runs :worker:ruleIntegrationTest inside a user+net+mount namespace.
#
# The fixture binds 80/443/21/23 and answers DNS as 1.1.1.1. Those need to be
# root inside the namespace (ip_unprivileged_port_start is 1024 on the host)
# and 1.1.1.1 must not be the real Cloudflare resolver. A plain `./gradlew test`
# does not run this source set. Outside the namespace the suite skips instead
# of failing.
#
# Usage: scripts/run-rule-integration-tests.sh [extra gradle args]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ -z "${BH_RULE_IT_NS:-}" ]]; then
  export BH_RULE_IT_NS=1
  exec unshare --user --map-root-user --net --mount "$0" "$@"
fi

ip link set lo up
ip addr replace 127.0.0.1/8 dev lo
ip addr replace 1.1.1.1/32 dev lo

ALLOWLIST="$ROOT/worker/src/ruleIntegrationTest/resources/ssrf-allowlist.txt"
NSDIR="$(mktemp -d)"

{
  echo "127.0.0.1 localhost"
  hosts="127.0.0.1"
  while IFS= read -r line || [[ -n "$line" ]]; do
    host="${line%%#*}"
    host="${host//[[:space:]]/}"
    [[ -z "$host" ]] && continue
    hosts="$hosts $host"
  done < "$ALLOWLIST"
  echo "$hosts"
} > "$NSDIR/hosts"

printf 'nameserver 1.1.1.1\noptions timeout:1 attempts:1\n' > "$NSDIR/resolv.conf"

# glibc on this host asks systemd-resolved before /etc/hosts. Resolved's socket
# is still visible in this mount namespace and would NXDOMAIN the fixture names.
# files-then-dns makes InetAddress and the system resolver both hit the fixture.
cat > "$NSDIR/nsswitch.conf" <<'EOF'
passwd: files
group: files
shadow: files
hosts: files dns
networks: files
protocols: files
services: files
ethers: files
rpc: files
EOF

mount --make-rprivate /
mount --bind "$NSDIR/hosts" /etc/hosts
mount --bind "$NSDIR/resolv.conf" /etc/resolv.conf
mount --bind "$NSDIR/nsswitch.conf" /etc/nsswitch.conf

export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
export PATH="$JAVA_HOME/bin:$PATH"
# unshare --map-root-user is uid 0, so Java's user.home is /root and the wrapper
# cannot create /root/.gradle. Keep the real user's Gradle home.
export HOME=/home/joe
export GRADLE_USER_HOME=/home/joe/.gradle
export GRADLE_OPTS="-Duser.home=/home/joe ${GRADLE_OPTS:-}"
BLOODHOUND_SSRF_ALLOWLIST="$(grep -v '^[[:space:]]*#' "$ALLOWLIST" | grep -v '^[[:space:]]*$' | paste -sd, -)"
export BLOODHOUND_SSRF_ALLOWLIST

cd "$ROOT"
# -x: the root build finalizes every Test task with jacocoTestReport, which depends on the unit suite.
exec ./gradlew :worker:ruleIntegrationTest --no-daemon -x test -x jacocoTestReport "$@"
