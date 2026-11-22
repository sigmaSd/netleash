# Sourced by the VM tests: a veth pair to a traffic server in namespace srv,
# cgroups named like desktop app scopes, and helpers to run traffic.
mkdir -p /run/netns
ip link add veth0 type veth peer name veth1
ip netns add srv
ip link set veth1 netns srv
ip addr add 10.9.0.1/24 dev veth0
ip addr add fd00::1/64 dev veth0 nodad
ip link set veth0 up
ip -n srv link set lo up
ip -n srv addr add 10.9.0.2/24 dev veth1
ip -n srv addr add fd00::2/64 dev veth1 nodad
ip -n srv link set veth1 up
# Make the link count frames the way hardware does: no TSO, so the stack
# splits GSO packets into frames before the link (as for Wi-Fi), and no GRO,
# so received frames arrive one by one.
ethtool -K veth0 tso off gro off > /dev/null
ip netns exec srv ethtool -K veth1 tso off gro off > /dev/null

CG=/sys/fs/cgroup
APP_A="app-gnome-org.example.Fetcher-42.scope"
APP_B="app-flatpak-org.example.Uploader-7.scope"
SERVER="traffic-server.service"
for unit in "$APP_A" "$APP_B" "$SERVER"; do mkdir -p "$CG/$unit"; done
in_cgroup() { # unit, command...
  unit=$1
  shift
  sh -c 'echo $$ > "$0/cgroup.procs" && exec "$@"' "$CG/$unit" "$@"
}
in_cgroup "$SERVER" ip netns exec srv python3 scripts/traffic.py serve 9000 &
sleep 1

traffic() { # unit, mode, host, bytes -> rate in bytes/s
  in_cgroup "$1" python3 scripts/traffic.py "$2" "$3" 9000 "$4" | sed 's/.*"rate": \([0-9]*\).*/\1/'
}
within() { # rate, limit: at most 115% and at least 50% of the limit
  [ "$1" -le $(($2 * 115 / 100)) ] && [ "$1" -ge $(($2 / 2)) ]
}
PASS=0
FAIL=0
check() { # description, condition
  if eval "$2"; then echo "PASS $1"; PASS=$((PASS + 1)); else echo "FAIL $1"; FAIL=$((FAIL + 1)); fi
}
