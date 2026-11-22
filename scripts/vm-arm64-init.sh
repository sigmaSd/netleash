#!/bin/busybox sh
# init of the arm64 VM that scripts/vm-arm64.sh boots: a server in its own
# network namespace behind a veth pair, a cgroup named like a desktop app's
# scope, and netleash fed commands through a fifo.

/bin/busybox --install -s /bin
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mount -t cgroup2 none /sys/fs/cgroup
mount -t tmpfs run /run

PASS=0
FAIL=0
check() {
  if eval "$2"; then
    echo "PASS $1"
    PASS=$((PASS + 1))
  else
    echo "FAIL $1"
    FAIL=$((FAIL + 1))
  fi
}
echo "$(uname -m), Linux $(uname -r)"

insmod /veth.ko
# The server waits for its end of the link, then serves two files.
unshare -n sh -c '
  echo $$ > /run/srv.pid
  until ip link show veth1 > /dev/null 2>&1; do sleep 0.1; done
  ip link set lo up
  ip addr add 10.9.0.2/24 dev veth1
  ip link set veth1 up
  mkdir -p /run/www
  dd if=/dev/zero of=/run/www/big bs=1M count=50 2> /dev/null
  dd if=/dev/zero of=/run/www/small bs=1M count=20 2> /dev/null
  exec httpd -f -p 9001 -h /run/www
' &
until [ -s /run/srv.pid ]; do sleep 0.1; done
# busybox ip ignores the peer's name: it gets the kernel's first free vethN,
# veth0 here.
ip link add name veth1 type veth peer name veth0
ip link set veth1 netns "$(cat /run/srv.pid)"
ip addr add 10.9.0.1/24 dev veth0
ip link set veth0 up
sleep 2

APP=/sys/fs/cgroup/app-gnome-org.example.Fetcher-42.scope
mkdir -p "$APP"
in_app() { sh -c 'echo $$ > '"$APP"'/cgroup.procs; exec "$@"' sh "$@"; }

mkfifo /run/commands
netleash < /run/commands > /run/events.jsonl 2> /run/stderr.log &
exec 3> /run/commands
for _ in $(seq 100); do
  grep -q '"type":"ready"' /run/events.jsonl && break
  sleep 0.2
done
check "netleash loads and attaches its programs" \
  "grep -q '\"type\":\"ready\"' /run/events.jsonl"
echo '{"cmd":"interface","name":"veth0"}' >&3
sleep 1

in_app wget -q -O /dev/null http://10.9.0.2:9001/big
sleep 3
check "the download is attributed to the app" \
  "grep -q '\"id\":\"org.example.Fetcher\",\"kind\":\"app\"' /run/events.jsonl"

echo '{"cmd":"limit","app":"org.example.Fetcher","down":2000000,"up":null}' >&3
sleep 1
start=$(date +%s)
in_app wget -q -O /dev/null http://10.9.0.2:9001/small
elapsed=$(($(date +%s) - start))
[ "$elapsed" -gt 0 ] || elapsed=1
rate=$((20971520 / elapsed))
echo "20 MB limited to 2 MB/s: $rate B/s over ${elapsed}s"
check "the download limit holds" "[ $rate -ge 1000000 ] && [ $rate -le 2400000 ]"

echo '{"cmd":"stop"}' >&3
exec 3>&-
sleep 2
check "netleash stops" "grep -q '\"type\":\"stopped\"' /run/events.jsonl"
if [ -s /run/stderr.log ]; then
  echo "netleash stderr:"
  head -n 5 /run/stderr.log
fi
echo "RESULT: $PASS passed, $FAIL failed"
poweroff -f
