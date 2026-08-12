#!/bin/bash

set -euo pipefail

echo "Linking sysusers config..."

mkdir -p /etc/sysusers.d

if [ -f /etc/sysusers.d/outboxd.conf ]; then
    rm /etc/sysusers.d/outboxd.conf
fi

ln -s "/opt/outboxd/conf/outboxd.conf" /etc/sysusers.d/outboxd.conf

echo "Creating user..."

systemd-sysusers

echo "Preparing private state directory..."

install -d -o outboxd -g outboxd -m 0700 /var/lib/outboxd

echo "Checking installation ownership..."

chown -R root:root /opt/outboxd
find /opt/outboxd -type d -exec chmod 0755 {} +
find /opt/outboxd -type f -exec chmod 0644 {} +
chmod 0755 /opt/outboxd/outboxd

echo "Linking unit..."

if [ -f /etc/systemd/system/outboxd.service ]; then
    rm /etc/systemd/system/outboxd.service
fi

systemctl link "/opt/outboxd/conf/outboxd.service"

echo "Reloading daemon..."

systemctl daemon-reload
systemctl enable outboxd

echo "Setup complete. Create and edit the private configuration, then provision and start the service:"
echo "  sudo -u outboxd /opt/outboxd/outboxd -config /var/lib/outboxd/config.yml provision"
echo "  sudo -u outboxd vi /var/lib/outboxd/config.yml"
echo "  sudo -u outboxd /opt/outboxd/outboxd -config /var/lib/outboxd/config.yml provision"
echo "  systemctl start outboxd"
echo "Logs are available with: journalctl -u outboxd"
