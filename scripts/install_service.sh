#!/bin/bash
#
# install_service.sh — run io-tracer-mac as a launchd daemon.
#
# macOS counterpart of the Linux systemd service installer. Installs a
# LaunchDaemon that runs the tracer at boot (as root, required for DTrace).
#
# Usage: sudo bash ./scripts/install_service.sh {install|uninstall|status|start|stop|restart|logs}

set -e

LABEL="dev.cachemon.iotracer"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="$(command -v python3 || echo /usr/bin/python3)"
LOG_DIR="/var/log/io-tracer-mac"

require_root() {
    if [ "$EUID" -ne 0 ]; then echo "Must run as root (sudo)."; exit 1; fi
}

cmd_install() {
    require_root
    mkdir -p "$LOG_DIR"
    cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${PYTHON}</string>
        <string>${REPO_DIR}/iotrc.py</string>
    </array>
    <key>WorkingDirectory</key><string>${REPO_DIR}</string>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>${LOG_DIR}/iotracer.out.log</string>
    <key>StandardErrorPath</key><string>${LOG_DIR}/iotracer.err.log</string>
</dict>
</plist>
EOF
    launchctl load -w "$PLIST"
    echo "Installed and loaded ${LABEL}."
}

cmd_uninstall() {
    require_root
    launchctl unload -w "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"
    echo "Uninstalled ${LABEL}."
}

cmd_status()  { launchctl list | grep "$LABEL" || echo "Not loaded."; }
cmd_start()   { require_root; launchctl start "$LABEL"; echo "Started."; }
cmd_stop()    { require_root; launchctl stop "$LABEL"; echo "Stopped."; }
cmd_restart() { cmd_stop || true; cmd_start; }
cmd_logs()    { tail -f "${LOG_DIR}/iotracer.out.log" "${LOG_DIR}/iotracer.err.log"; }

case "$1" in
    install) cmd_install ;;
    uninstall) cmd_uninstall ;;
    status) cmd_status ;;
    start) cmd_start ;;
    stop) cmd_stop ;;
    restart) cmd_restart ;;
    logs) cmd_logs ;;
    *) echo "Usage: sudo bash $0 {install|uninstall|status|start|stop|restart|logs}"; exit 1 ;;
esac
