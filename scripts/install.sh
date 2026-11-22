#!/bin/sh
# Install bandito-helper as a system D-Bus service. Run as root:
#   cargo build --release && sudo scripts/install.sh
# DESTDIR and PREFIX work as usual for packaging.
set -eu
cd "$(dirname "$0")/.."
BIN=${BIN:-${CARGO_TARGET_DIR:-target}/release/bandito-helper}
PREFIX=${PREFIX:-/usr}
DEST=${DESTDIR:-}
install -Dm755 "$BIN" "$DEST$PREFIX/libexec/bandito-helper"
install -Dm644 dist/io.github.sigmasd.Bandito.Helper.conf "$DEST$PREFIX/share/dbus-1/system.d/io.github.sigmasd.Bandito.Helper.conf"
install -Dm644 dist/io.github.sigmasd.Bandito.Helper.service "$DEST$PREFIX/share/dbus-1/system-services/io.github.sigmasd.Bandito.Helper.service"
install -Dm644 dist/bandito-helper.service "$DEST$PREFIX/lib/systemd/system/bandito-helper.service"
install -Dm644 dist/io.github.sigmasd.Bandito.Helper.policy "$DEST$PREFIX/share/polkit-1/actions/io.github.sigmasd.Bandito.Helper.policy"
if [ -z "$DEST" ]; then
  systemctl daemon-reload 2>/dev/null || true
  busctl call org.freedesktop.DBus / org.freedesktop.DBus ReloadConfig 2>/dev/null || true
fi
echo "Installed. Bandito uses it automatically from the next start."
