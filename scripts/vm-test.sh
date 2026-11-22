#!/bin/sh
# Live test of netleash as root, inside a throwaway VM running the host
# kernel (no sudo needed on the host). Run from the repository root:
#
#   scripts/vm.sh
#
# Builds a veth pair to a server in its own network namespace, runs traffic
# from two fake app scopes over IPv4 and IPv6, and checks what the helper
# reports and how its limits hold.

set -eu
HELPER=${HELPER:-target/release/netleash}
OUT=${OUT:-vm-test-out}
mkdir -p "$OUT"
rm -f "$OUT"/*
. scripts/vm-net.sh

# The helper, fed commands through a fifo.
mkfifo "$OUT/commands"
"$HELPER" < "$OUT/commands" > "$OUT/events.jsonl" 2> "$OUT/stderr.log" &
HELPER_PID=$!
exec 3> "$OUT/commands"
send() { echo "$1" >&3; }
sleep 1
check "helper starts and attaches" "grep -q '\"type\":\"ready\"' $OUT/events.jsonl"
send '{"cmd":"interface","name":"veth0"}'

# Unlimited: measure both apps, IPv4 and IPv6.
FREE_DOWN=$(traffic "$APP_A" down 10.9.0.2 200000000)
FREE_UP6=$(traffic "$APP_B" up fd00::2 200000000)
echo "unlimited: download $FREE_DOWN B/s (IPv4), upload $FREE_UP6 B/s (IPv6)"
sleep 2

# Samples name the apps and carry their traffic.
check "download attributed to org.example.Fetcher" \
  "grep -q '\"id\":\"org.example.Fetcher\",\"kind\":\"app\"' $OUT/events.jsonl"
check "IPv6 upload attributed to org.example.Uploader" \
  "grep -q '\"id\":\"org.example.Uploader\",\"kind\":\"app\"' $OUT/events.jsonl"
check "connections carry remote addresses and ports" \
  "grep -q '\"remote\":\"10.9.0.2\"' $OUT/events.jsonl && grep -q '\"remote\":\"fd00::2\"' $OUT/events.jsonl && grep -q '\"remotePort\":9000' $OUT/events.jsonl"
check "loopback is not counted" "! grep -q '\"remote\":\"127.0.0.1\"' $OUT/events.jsonl"

# Apps add up to the interface's own counters, link-layer headers included:
# per mille of busy samples' bytes attributed to apps, in each direction.
attributed() { # rx|tx
  python3 - "$OUT/events.jsonl" "$1" <<'PY'
import json, sys
direction = sys.argv[2]
shares = []
for line in open(sys.argv[1]):
    event = json.loads(line)
    if event.get("type") != "sample" or event["total"][direction] < 10_000_000:
        continue
    apps = sum(app[direction] for app in event["apps"])
    shares.append(apps * 1000 // event["total"][direction])
print(min(shares) if shares else 0)
PY
}
RX=$(attributed rx)
TX=$(attributed tx)
echo "apps' share of busy samples: download $RX/1000, upload $TX/1000"
check "apps add up to the interface's counters" "[ $RX -ge 990 ] && [ $RX -le 1010 ] && [ $TX -ge 990 ] && [ $TX -le 1010 ]"

# Per-app download limit, IPv4.
send '{"cmd":"limit","app":"org.example.Fetcher","down":2000000,"up":null}'
sleep 1
R=$(traffic "$APP_A" down 10.9.0.2 10000000)
echo "Fetcher download limited to 2 MB/s: $R B/s"
check "per-app download limit holds (IPv4)" "within $R 2000000"
R=$(traffic "$APP_B" down 10.9.0.2 100000000)
echo "Uploader download, not limited: $R B/s"
check "other apps are not limited" "[ $R -gt 20000000 ]"

# Per-app upload limit, IPv6, paced rather than dropped.
retransmits() { awk '/^Tcp:/ { if (n++) print $13 }' /proc/net/snmp; }
send '{"cmd":"limit","app":"org.example.Uploader","down":null,"up":1000000}'
sleep 1
check "fq is installed for paced uploads" "tc qdisc show dev veth0 root | grep -q '^qdisc fq '"
BEFORE=$(retransmits)
R=$(traffic "$APP_B" up fd00::2 5000000)
RETRANSMITS=$(($(retransmits) - BEFORE))
echo "Uploader upload limited to 1 MB/s (IPv6): $R B/s, $RETRANSMITS TCP retransmissions"
check "per-app upload limit holds (IPv6)" "within $R 1000000"
check "paced uploads barely retransmit" "[ $RETRANSMITS -lt 20 ]"

# Without fq (a tunnel device, or someone changed it), limits drop instead.
tc qdisc del dev veth0 root
BEFORE=$(retransmits)
R=$(traffic "$APP_B" up fd00::2 5000000)
RETRANSMITS=$(($(retransmits) - BEFORE))
echo "same limit without fq: $R B/s, $RETRANSMITS TCP retransmissions"
check "upload limits hold without fq too" "within $R 1000000"

# Removing limits.
send '{"cmd":"limit","app":"org.example.Fetcher","down":null,"up":null}'
send '{"cmd":"limit","app":"org.example.Uploader","down":null,"up":null}'
sleep 1
check "the default queueing discipline is back" "! tc qdisc show dev veth0 root | grep -q '^qdisc fq '"
R=$(traffic "$APP_A" down 10.9.0.2 100000000)
echo "Fetcher download after removing its limit: $R B/s"
check "removing a limit restores full speed" "[ $R -gt 20000000 ]"

# Global limit covers every app.
send '{"cmd":"limit","app":null,"down":3000000,"up":null}'
sleep 1
R=$(traffic "$APP_B" down fd00::2 15000000)
echo "global download limit 3 MB/s, Uploader over IPv6: $R B/s"
check "global limit holds" "within $R 3000000"
send '{"cmd":"limit","app":null,"down":null,"up":null}'

# A bad command is reported, not fatal.
send '{"cmd":"interface","name":"nope0"}'
sleep 1
check "errors are reported" "grep -q 'no network interface named nope0' $OUT/events.jsonl"

# Stop: the programs detach with the helper.
send '{"cmd":"stop"}'
exec 3>&-
wait "$HELPER_PID" || true
check "helper stops cleanly" "grep -q '\"type\":\"stopped\"' $OUT/events.jsonl"
R=$(traffic "$APP_A" down 10.9.0.2 100000000)
echo "download after the helper stopped: $R B/s"
check "nothing is left attached" "[ $R -gt 20000000 ]"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
