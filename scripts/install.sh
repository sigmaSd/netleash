#!/bin/sh
# Install netleash as a system D-Bus service, for packagers (DESTDIR and
# PREFIX work as usual). On your own machine, `sudo netleash --install` does
# the same from the binary alone.
#   cargo build --release && sudo scripts/install.sh
set -eu
cd "$(dirname "$0")/.."
BIN=${BIN:-${CARGO_TARGET_DIR:-target}/release/netleash}
PREFIX=${PREFIX:-/usr}
DEST=${DESTDIR:-}
put() { # mode, source, target: with /usr/bin/netleash pointed at PREFIX
  install -d "$(dirname "$DEST$PREFIX/$3")"
  sed "s#/usr/bin/netleash#$PREFIX/bin/netleash#" "$2" > "$DEST$PREFIX/$3"
  chmod "$1" "$DEST$PREFIX/$3"
}
install -Dm755 "$BIN" "$DEST$PREFIX/bin/netleash"
put 644 dist/io.github.sigmasd.Netleash.conf share/dbus-1/system.d/io.github.sigmasd.Netleash.conf
put 644 dist/io.github.sigmasd.Netleash.service share/dbus-1/system-services/io.github.sigmasd.Netleash.service
put 644 dist/netleash.service lib/systemd/system/netleash.service
put 644 dist/io.github.sigmasd.Netleash.policy share/polkit-1/actions/io.github.sigmasd.Netleash.policy
if [ -z "$DEST" ]; then
  systemctl daemon-reload 2>/dev/null || true
  busctl call org.freedesktop.DBus / org.freedesktop.DBus ReloadConfig 2>/dev/null || true
fi
echo "Installed. Front ends such as Bandito use it from their next start."
