#!/bin/bash

set -euo pipefail

if [ "${EUID}" -ne 0 ]; then
    echo "setup.sh must be run as root" >&2
    exit 1
fi

payload=/opt/outboxd
sysusers_file=/usr/lib/sysusers.d/outboxd.conf
service_file=/etc/systemd/system/outboxd.service

for file in outboxd conf/outboxd.conf conf/outboxd.service; do
    if [ ! -f "$payload/$file" ]; then
        echo "missing payload file: $payload/$file" >&2
        exit 1
    fi
done

if [ ! -x "$payload/outboxd" ]; then
    echo "payload binary is not executable: $payload/outboxd" >&2
    exit 1
fi

echo "Installing sysusers config..."
install -d -o root -g root -m 0755 /usr/lib/sysusers.d

if [ -e /etc/sysusers.d/outboxd.conf ]; then
    rm -f /etc/sysusers.d/outboxd.conf
elif [ -L /etc/sysusers.d/outboxd.conf ]; then
    rm -f /etc/sysusers.d/outboxd.conf
fi

if [ -L "$sysusers_file" ]; then
    rm -f "$sysusers_file"
fi

install -o root -g root -m 0644 "$payload/conf/outboxd.conf" "$sysusers_file"

echo "Creating user..."
systemd-sysusers "$sysusers_file"

echo "Preparing private state directory..."
install -d -o outboxd -g outboxd -m 0700 /var/lib/outboxd

echo "Installing unit..."

if [ -L "$service_file" ]; then
    rm -f "$service_file"
fi

install -o root -g root -m 0644 "$payload/conf/outboxd.service" "$service_file"

echo "Reloading daemon..."
systemctl daemon-reload
systemctl enable outboxd

echo "Setup complete. Create and edit the private configuration, then provision and start the service:"
echo "  sudo -u outboxd /opt/outboxd/outboxd -config /var/lib/outboxd/config.yml provision"
echo "  sudo -u outboxd vi /var/lib/outboxd/config.yml"
echo "  sudo -u outboxd /opt/outboxd/outboxd -config /var/lib/outboxd/config.yml provision"
echo "  systemctl start outboxd"
echo "Logs are available with: journalctl -u outboxd"
