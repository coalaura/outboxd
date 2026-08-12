#!/bin/bash

set -euo pipefail

echo "Stopping service..."
systemctl stop "outboxd" 2>/dev/null || true

echo "Disabling service..."
systemctl disable "outboxd" 2>/dev/null || true

echo "Removing unit file..."
rm -f "/etc/systemd/system/outboxd.service"

echo "Removing sysusers config..."
rm -f "/etc/sysusers.d/outboxd.conf"

echo "Reloading daemon..."
systemctl daemon-reload
systemctl reset-failed "outboxd" 2>/dev/null || true

echo "Removing user and group..."
if id "outboxd" &>/dev/null; then
    userdel "outboxd" 2>/dev/null || true
fi

if getent group "outboxd" &>/dev/null; then
    groupdel "outboxd" 2>/dev/null || true
fi

echo "Uninstall complete. Private state at /var/lib/outboxd was preserved."
