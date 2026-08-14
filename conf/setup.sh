#!/bin/bash

set -euo pipefail

enable_service=true
case "$#" in
    0)
        ;;
    1)
        if [ "$1" != "--no-enable" ]; then
            echo "usage: setup.sh [--no-enable]" >&2
            exit 1
        fi

        enable_service=false
        ;;
    *)
        echo "usage: setup.sh [--no-enable]" >&2
        exit 1
        ;;
esac

if [ "${EUID}" -ne 0 ]; then
    echo "setup.sh must be run as root" >&2
    exit 1
fi

payload=/opt/outboxd
data_directory=$payload/data
config_file=$payload/config.yml
config_lock=$config_file.outboxd.lock
sysusers_file=/usr/lib/sysusers.d/outboxd.conf
service_file=/etc/systemd/system/outboxd.service

if [ -L "$payload" ]; then
    echo "payload and conf directory must not be symlinks" >&2
    exit 1
fi

if [ -L "$payload/conf" ]; then
    echo "payload and conf directory must not be symlinks" >&2
    exit 1
fi

for file in outboxd conf/outboxd.conf conf/outboxd.service conf/setup.sh conf/uninstall.sh; do
    if [ -L "$payload/$file" ]; then
        echo "missing payload file: $payload/$file" >&2
        exit 1
    fi

    if [ ! -f "$payload/$file" ]; then
        echo "missing payload file: $payload/$file" >&2
        exit 1
    fi
done

if [ ! -x "$payload/outboxd" ]; then
    echo "payload binary is not executable: $payload/outboxd" >&2
    exit 1
fi

# The linked system files are trusted by root, so their source hierarchy must
# not be replaceable by the service account.
chown root:root \
    "$payload" \
    "$payload/outboxd" \
    "$payload/conf" \
    "$payload/conf/outboxd.conf" \
    "$payload/conf/outboxd.service" \
    "$payload/conf/setup.sh" \
    "$payload/conf/uninstall.sh"
chmod 0755 \
    "$payload" \
    "$payload/outboxd" \
    "$payload/conf" \
    "$payload/conf/setup.sh" \
    "$payload/conf/uninstall.sh"
chmod 0644 "$payload/conf/outboxd.conf" "$payload/conf/outboxd.service"

echo "Installing sysusers config..."
install -d -o root -g root -m 0755 /usr/lib/sysusers.d

if [ -e /etc/sysusers.d/outboxd.conf ]; then
    rm -f /etc/sysusers.d/outboxd.conf
elif [ -L /etc/sysusers.d/outboxd.conf ]; then
    rm -f /etc/sysusers.d/outboxd.conf
fi

rm -f "$sysusers_file"
ln -s "$payload/conf/outboxd.conf" "$sysusers_file"

echo "Creating user..."
systemd-sysusers "$sysusers_file"

echo "Preparing private data directory..."

if [ -L "$data_directory" ]; then
    echo "data path must be a directory and not a symlink: $data_directory" >&2
    exit 1
fi

if [ -e "$data_directory" ]; then
    if [ ! -d "$data_directory" ]; then
        echo "data path must be a directory and not a symlink: $data_directory" >&2
        exit 1
    fi
fi

install -d -o outboxd -g outboxd -m 0700 "$data_directory"

if [ -e "$config_file" ]; then
    if [ -L "$config_file" ]; then
        echo "config must be a regular file: $config_file" >&2
        exit 1
    fi

    if [ ! -f "$config_file" ]; then
        echo "config must be a regular file: $config_file" >&2
        exit 1
    fi

    chown root:outboxd "$config_file"
    chmod 0440 "$config_file"
fi

if [ -e "$config_lock" ]; then
    if [ -L "$config_lock" ]; then
        echo "config ownership lock must be a regular file: $config_lock" >&2
        exit 1
    fi

    if [ ! -f "$config_lock" ]; then
        echo "config ownership lock must be a regular file: $config_lock" >&2
        exit 1
    fi
else
    install -o outboxd -g outboxd -m 0600 /dev/null "$config_lock"
fi

chown outboxd:outboxd "$config_lock"
chmod 0600 "$config_lock"

echo "Installing unit..."

rm -f "$service_file"
ln -s "$payload/conf/outboxd.service" "$service_file"

echo "Reloading daemon..."
systemctl daemon-reload
if [ "$enable_service" = true ]; then
    systemctl enable outboxd
    systemctl try-restart outboxd
else
    # disable removes linked unit files, so restore the canonical link afterward.
    systemctl disable --now outboxd
    rm -f "$service_file"
    ln -s "$payload/conf/outboxd.service" "$service_file"
    systemctl daemon-reload
fi

echo "Setup complete. Create and edit the private configuration, then provision and start the service:"
echo "  sudo -g outboxd /opt/outboxd/outboxd -config /opt/outboxd/config.yml provision"
echo "  sudoedit /opt/outboxd/config.yml"
echo "  sudo /opt/outboxd/conf/setup.sh"
echo "  sudo -u outboxd /opt/outboxd/outboxd -config /opt/outboxd/config.yml provision"
echo "  systemctl start outboxd"
echo "Logs are available with: journalctl -u outboxd"
