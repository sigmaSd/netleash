#!/bin/sh
# Live test of the D-Bus service, as root in a VM (see scripts/vm.sh): a
# private system bus loads dist/'s policy, the service runs as root, and the
# client runs as the unprivileged user nobody.

set -eu
HELPER=${HELPER:-target/release/netleash}
OUT=${OUT:-vm-test-out}
mkdir -p "$OUT"
rm -f "$OUT"/*
. scripts/vm-net.sh

# nobody can't read the build directory under $HOME; use a copy.
cp "$HELPER" /run/netleash
chmod 755 /run/netleash

# A system bus like the real one: deny by default, plus dist/'s policy.
cat > /run/bus.conf <<CONF
<busconfig>
  <type>system</type>
  <listen>unix:path=/run/test-system-bus</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <deny own="*"/>
    <deny send_type="method_call"/>
    <allow send_type="signal"/>
    <allow send_requested_reply="true" send_type="method_return"/>
    <allow send_requested_reply="true" send_type="error"/>
    <allow receive_type="method_call"/>
    <allow receive_type="method_return"/>
    <allow receive_type="error"/>
    <allow receive_type="signal"/>
    <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus"/>
    <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus.Introspectable"/>
    <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus.Properties"/>
  </policy>
  <include>$PWD/dist/io.github.sigmasd.Netleash.conf</include>
</busconfig>
CONF
dbus-daemon --config-file=/run/bus.conf --fork
export DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/test-system-bus
as_nobody() { setpriv --reuid=65534 --regid=65534 --clear-groups "$@"; }

# netleash --install puts the binary and service files under a prefix.
/run/netleash --install --prefix /run/prefix > /run/install.log 2>&1
check "--install writes the service files" \
  "[ -x /run/prefix/bin/netleash ] && [ -f /run/prefix/share/dbus-1/system.d/io.github.sigmasd.Netleash.conf ] && [ -f /run/prefix/share/polkit-1/actions/io.github.sigmasd.Netleash.policy ]"
check "--install points the service at its binary" \
  "grep -q 'Exec=/run/prefix/bin/netleash --dbus' /run/prefix/share/dbus-1/system-services/io.github.sigmasd.Netleash.service"
as_nobody /run/netleash --install --prefix /run/prefix2 > /run/install2.log 2>&1 || true
check "--install refuses without root" "grep -q 'as root' /run/install2.log"
/run/netleash --uninstall --prefix /run/prefix > /dev/null 2>&1
check "--uninstall removes them" "[ ! -e /run/prefix/bin/netleash ] && [ ! -e /run/prefix/share/dbus-1/system.d/io.github.sigmasd.Netleash.conf ]"

# Without the service, the client says so.
as_nobody /run/netleash --client < /dev/null > /run/client0.jsonl 2>&1 || true
check "client reports a missing service" "grep -q 'netleash --install' /run/client0.jsonl"

# Only root may own the name.
as_nobody /run/netleash --dbus --insecure-no-polkit > /run/nobody-service.log 2>&1 || true
check "nobody can't run the service" "grep -q '\"type\":\"error\"' /run/nobody-service.log"

# With polkit on and no polkit daemon, commands are refused: fail closed.
/run/netleash --dbus > /run/service-polkit.log 2>&1 &
SERVICE=$!
sleep 2
echo '{"cmd":"limit","app":null,"down":1000,"up":null}' |
  as_nobody /run/netleash --client > /run/client1.jsonl 2>&1 || true
check "without polkit's answer, commands are refused" "grep -q '\"type\":\"error\"' /run/client1.jsonl"
kill "$SERVICE"
wait "$SERVICE" 2>/dev/null || true
R=$(traffic "$APP_A" down 10.9.0.2 100000000)
check "a refused limit isn't applied" "[ $R -gt 20000000 ]"

# The service, with authorization skipped for the test.
/run/netleash --dbus --insecure-no-polkit > /run/service.log 2>&1 &
SERVICE=$!
sleep 2

mkfifo /run/client-in
chmod 666 /run/client-in
as_nobody /run/netleash --client < /run/client-in > /run/client2.jsonl 2>&1 &
CLIENT=$!
exec 3> /run/client-in
sleep 1
echo '{"cmd":"interface","name":"veth0"}' >&3
echo '{"cmd":"limit","app":"org.example.Fetcher","down":2000000,"up":null}' >&3
sleep 1
R=$(traffic "$APP_A" down 10.9.0.2 10000000)
echo "Fetcher download limited to 2 MB/s through the service: $R B/s"
check "an unprivileged client sets a limit through the service" "within $R 2000000"
sleep 2
check "the client receives samples" "grep -q '\"type\":\"sample\"' /run/client2.jsonl"
check "samples name the app" "grep -q '\"id\":\"org.example.Fetcher\"' /run/client2.jsonl"

# Closing the client removes its limits.
exec 3>&-
wait "$CLIENT" || true
sleep 1
R=$(traffic "$APP_A" down 10.9.0.2 100000000)
echo "Fetcher download after the client left: $R B/s"
check "a client's limits go when it leaves" "[ $R -gt 20000000 ]"
check "the service keeps running for the next client" "kill -0 $SERVICE"
kill "$SERVICE"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
