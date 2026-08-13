#!/bin/bash

set -euo pipefail

if [ "${EUID}" -ne 0 ]; then
    echo "uninstall.sh must be run as root" >&2
    exit 1
fi

echo "Stopping and disabling service..."

if ! systemctl disable --now outboxd 2>/dev/null; then
    echo "Service was not running or enabled."
fi

echo "Removing installed service files..."
rm -f /etc/systemd/system/outboxd.service
rm -f /usr/lib/sysusers.d/outboxd.conf
# Remove the path used by older installations, including a stale symlink.
rm -f /etc/sysusers.d/outboxd.conf

echo "Reloading daemon..."
systemctl daemon-reload

if ! systemctl reset-failed outboxd 2>/dev/null; then
    echo "Service had no failed state to reset."
fi

echo "Uninstall complete. /opt/outboxd and /var/lib/outboxd were preserved."
echo "The outboxd account was retained so preserved private state keeps a valid owner."
