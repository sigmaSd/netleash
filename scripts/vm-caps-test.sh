#!/bin/sh
# Live test of netleash without root, as root in a VM (see scripts/vm.sh):
# the binary gets cap_bpf,cap_net_admin,cap_perfmon+ep, then the unprivileged user
# nobody runs it, measures and limits traffic.

set -eu
HELPER=${HELPER:-target/release/netleash}
OUT=${OUT:-vm-test-out}
mkdir -p "$OUT"
rm -f "$OUT"/*
. scripts/vm-net.sh
as_nobody() { setpriv --reuid=65534 --regid=65534 --clear-groups "$@"; }
chmod 666 /dev/null

# nobody can't read the build directory under $HOME; use copies.
cp "$HELPER" /run/netleash-plain
cp "$HELPER" /run/netleash
chmod 755 /run/netleash /run/netleash-plain
setcap cap_bpf,cap_net_admin,cap_perfmon+ep /run/netleash

check "--capable says no without capabilities" "! as_nobody /run/netleash-plain --capable > /dev/null"
echo '{"cmd":"stop"}' | as_nobody /run/netleash-plain > /run/plain.jsonl 2>&1 || true
check "without them, it reports an error and exits" "grep -q '\"type\":\"error\"' /run/plain.jsonl"
check "--capable says yes with them" "as_nobody /run/netleash --capable > /dev/null"

mkfifo /run/in
chmod 666 /run/in
as_nobody /run/netleash < /run/in > /run/out.jsonl 2> /run/err.log &
NETLEASH=$!
exec 3> /run/in
send() { echo "$1" >&3; }
sleep 1
check "nobody starts it and it attaches" "grep -q '\"type\":\"ready\"' /run/out.jsonl"
send '{"cmd":"interface","name":"veth0"}'

R=$(traffic "$APP_A" down 10.9.0.2 100000000)
sleep 2
check "traffic is attributed to the app" "grep -q '\"id\":\"org.example.Fetcher\"' /run/out.jsonl"
check "and to its process" "grep -q '\"processTraffic\":\[{\"pid\":' /run/out.jsonl"
check "the socket programs load with these capabilities" "! grep -q 'not counting traffic per process' /run/err.log"

send '{"cmd":"limit","app":"org.example.Fetcher","down":2000000,"up":null}'
sleep 1
R=$(traffic "$APP_A" down 10.9.0.2 10000000)
echo "download limited to 2 MB/s by nobody: $R B/s"
check "a download limit holds" "within $R 2000000"

retransmits() { awk '/^Tcp:/ { if (n++) print $13 }' /proc/net/snmp; }
send '{"cmd":"limit","app":"org.example.Uploader","down":null,"up":1000000}'
sleep 1
check "tc installs fq with the passed-on capability" "tc qdisc show dev veth0 root | grep -q '^qdisc fq '"
BEFORE=$(retransmits)
R=$(traffic "$APP_B" up fd00::2 5000000)
RETRANSMITS=$(($(retransmits) - BEFORE))
echo "upload limited to 1 MB/s by nobody: $R B/s, $RETRANSMITS TCP retransmissions"
check "an upload limit holds, paced" "within $R 1000000 && [ $RETRANSMITS -lt 20 ]"

send '{"cmd":"stop"}'
exec 3>&-
wait "$NETLEASH" || true
check "it stops cleanly" "grep -q '\"type\":\"stopped\"' /run/out.jsonl"
check "the default queueing discipline is back" "! tc qdisc show dev veth0 root | grep -q '^qdisc fq '"
R=$(traffic "$APP_A" down 10.9.0.2 100000000)
check "nothing is left attached" "[ $R -gt 20000000 ]"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
