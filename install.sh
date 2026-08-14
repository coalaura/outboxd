#!/bin/sh

set -eu
set -f
umask 077

repository=coalaura/outboxd
install_directory=/opt/outboxd
config_file=$install_directory/config.yml
binary=$install_directory/outboxd
installed=0
temporary_directory=
color_blue=
color_bold=
color_green=
color_red=
color_reset=
color_yellow=

say() {
    printf '%s\n' "$*" >&4
}

heading() {
    printf '\n%s%s%s\n' "$color_bold" "$*" "$color_reset" >&4
}

step() {
    printf '%s==>%s %s\n' "$color_blue" "$color_reset" "$*" >&4
}

success() {
    printf '%s[ok]%s %s\n' "$color_green" "$color_reset" "$*" >&4
}

warning() {
    printf '%swarning:%s %s\n' "$color_yellow" "$color_reset" "$*" >&4
}

fail() {
    printf '%soutboxd installer:%s %s\n' "$color_red" "$color_reset" "$*" >&2
    exit 1
}

cleanup() {
    cleanup_status=$?
    trap - 0 HUP INT TERM

    if [ -n "$temporary_directory" ]; then
        rm -rf -- "$temporary_directory"
    fi

    if [ "$cleanup_status" -ne 0 ]; then
        if [ "$installed" -eq 1 ]; then
            printf '%s\n' "Installation did not complete. The partial installation remains at $install_directory for inspection." >&2
        fi
    fi

    exit "$cleanup_status"
}

trap cleanup 0
trap 'exit 1' HUP INT TERM

if ! exec 3</dev/tty 4>/dev/tty; then
    fail "an interactive controlling terminal is required"
fi

case ${TERM-} in
    '' | dumb)
        ;;
    *)
        if [ -z "${NO_COLOR+x}" ]; then
            color_blue=$(printf '\033[34m')
            color_bold=$(printf '\033[1m')
            color_green=$(printf '\033[32m')
            color_red=$(printf '\033[31m')
            color_reset=$(printf '\033[0m')
            color_yellow=$(printf '\033[33m')
        fi
        ;;
esac

run_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

run_outboxd() {
    if [ "$(id -u)" -eq 0 ]; then
        runuser -u outboxd -g outboxd -- "$@"
    else
        sudo -u outboxd -g outboxd -- "$@"
    fi
}

run_admin() {
    if [ "$(id -u)" -eq 0 ]; then
        runuser -u root -g outboxd -- "$@"
    else
        sudo -g outboxd -- "$@"
    fi
}

run_setup() {
    setup_log=$temporary_directory/setup.log

    if ! run_root "$install_directory/conf/setup.sh" --no-enable >"$setup_log" 2>&1; then
        cat "$setup_log" >&4
        fail "system service setup failed"
    fi
}

prompt() {
    prompt_text=$1
    prompt_default=${2-}

    if [ -n "$prompt_default" ]; then
        printf '%s [%s]: ' "$prompt_text" "$prompt_default" >&4
    else
        printf '%s: ' "$prompt_text" >&4
    fi

    if ! IFS= read -r REPLY <&3; then
        fail "could not read from terminal"
    fi

    if [ -z "$REPLY" ]; then
        REPLY=$prompt_default
    fi
}

confirm() {
    confirm_prompt=$1
    confirm_default=${2-n}

    while :; do
        if [ "$confirm_default" = y ]; then
            printf '%s [Y/n]: ' "$confirm_prompt" >&4
        else
            printf '%s [y/N]: ' "$confirm_prompt" >&4
        fi

        if ! IFS= read -r confirm_reply <&3; then
            fail "could not read from terminal"
        fi

        if [ -z "$confirm_reply" ]; then
            confirm_reply=$confirm_default
        fi

        case $confirm_reply in
            y | Y | yes | YES | Yes)
                return 0
                ;;
            n | N | no | NO | No)
                return 1
                ;;
            *)
                printf '%s\n' "Please answer yes or no." >&4
                ;;
        esac
    done
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        fail "required command not found: $1"
    fi
}

valid_domain() {
    printf '%s\n' "$1" | awk '
        length($0) < 1 || length($0) > 253 {
            exit 1
        }
        $0 !~ /^[A-Za-z0-9.-]+$/ {
            exit 1
        }
        {
            count = split($0, labels, ".")
            if (count < 2) {
                exit 1
            }
            for (i = 1; i <= count; i++) {
                if (length(labels[i]) < 1 || length(labels[i]) > 63) {
                    exit 1
                }
                if (labels[i] !~ /^[A-Za-z0-9]/ || labels[i] !~ /[A-Za-z0-9]$/) {
                    exit 1
                }
            }
        }
    '
}

valid_ipv4() {
    printf '%s\n' "$1" | awk -F. '
        NF != 4 {
            exit 1
        }
        {
            for (i = 1; i <= 4; i++) {
                if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255) {
                    exit 1
                }
            }
        }
    '
}

valid_ipv6_shape() {
    case $1 in
        *:*)
            printf '%s\n' "$1" | grep -Eq '^[0-9A-Fa-f:.]+$'
            ;;
        *)
            return 1
            ;;
    esac
}

set_config_value() {
    config_section=$1
    config_key=$2
    config_value=$3
    config_next=$temporary_directory/config.next

    if ! awk -v wanted_section="$config_section" -v wanted_key="$config_key" -v wanted_value="$config_value" '
        /^[a-z_][a-z0-9_]*:$/ {
            section = substr($0, 1, length($0) - 1)
        }
        section == wanted_section && $0 ~ "^  " wanted_key ":" {
            print "  " wanted_key ": " wanted_value
            replaced++
            next
        }
        { print }
        END {
            if (replaced != 1) {
                exit 1
            }
        }
    ' "$temporary_directory/config.yml" >"$config_next"; then
        fail "could not update $config_section.$config_key"
    fi

    mv "$config_next" "$temporary_directory/config.yml"
}

lowercase() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

install_certbot_hook() {
    cert_name=$1
    hook_source=$temporary_directory/outboxd-certbot-hook
    hook_destination=/etc/letsencrypt/renewal-hooks/deploy/outboxd

    cat >"$hook_source" <<EOF
#!/bin/sh

set -eu
umask 077

lineage='/etc/letsencrypt/live/$cert_name'
destination=/opt/outboxd/tls

if [ -n "\${RENEWED_LINEAGE:-}" ]; then
    if [ "\$RENEWED_LINEAGE" != "\$lineage" ]; then
        exit 0
    fi
fi

certificate=\$lineage/fullchain.pem
private_key=\$lineage/privkey.pem

if [ ! -f "\$certificate" ]; then
    echo "outboxd certificate lineage is incomplete: \$lineage" >&2
    exit 1
fi

if [ ! -f "\$private_key" ]; then
    echo "outboxd certificate lineage is incomplete: \$lineage" >&2
    exit 1
fi

if [ -L "\$destination" ]; then
    echo "outboxd TLS destination must be a directory and not a symlink: \$destination" >&2
    exit 1
fi

if [ -e "\$destination" ]; then
    if [ ! -d "\$destination" ]; then
        echo "outboxd TLS destination must be a directory and not a symlink: \$destination" >&2
        exit 1
    fi
fi

install -d -o root -g outboxd -m 0750 "\$destination"
chown root:outboxd "\$destination"
chmod 0750 "\$destination"
certificate_tmp=\$(mktemp "\$destination/.fullchain.pem.XXXXXX")
private_key_tmp=\$(mktemp "\$destination/.privkey.pem.XXXXXX")
cleanup() {
    rm -f -- "\$certificate_tmp" "\$private_key_tmp"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM

install -o root -g root -m 0600 "\$certificate" "\$certificate_tmp"
install -o root -g root -m 0600 "\$private_key" "\$private_key_tmp"
mv -f -- "\$certificate_tmp" "\$destination/fullchain.pem"
mv -f -- "\$private_key_tmp" "\$destination/privkey.pem"
chown outboxd:outboxd "\$destination/fullchain.pem" "\$destination/privkey.pem"
chmod 0644 "\$destination/fullchain.pem"
chmod 0600 "\$destination/privkey.pem"
EOF

    run_root install -d -o root -g root -m 0755 /etc/letsencrypt/renewal-hooks/deploy
    run_root install -o root -g root -m 0755 "$hook_source" "$hook_destination"
    run_root "$hook_destination"
}

main() {
    heading "outboxd guided installer"
    say "This installs the latest stable Linux release into /opt/outboxd."
    say "It is intended for a fresh server and will not overwrite an existing installation."
    say ""

    if [ "$(uname -s)" != Linux ]; then
        fail "only Linux is supported"
    fi

    required_commands="
    awk bash cat chmod chown cp curl grep id install journalctl ln mkdir mktemp
    mv rm runuser sleep systemctl systemd-sysusers tar tr uname wc
"
    for required in $required_commands; do
        require_command "$required"
    done

    if [ "$(id -u)" -ne 0 ]; then
        require_command sudo
        sudo -v <&3
    fi

    case $(uname -m) in
        x86_64 | amd64)
            architecture=amd64
            ;;
        aarch64 | arm64)
            architecture=arm64
            ;;
        *)
            fail "unsupported architecture: $(uname -m)"
            ;;
    esac

    if [ -L "$install_directory" ]; then
        fail "$install_directory already exists; use the documented manual upgrade procedure"
    fi

    if [ -e "$install_directory" ]; then
        fail "$install_directory already exists; use the documented manual upgrade procedure"
    fi

    if run_root systemctl is-active --quiet outboxd; then
        fail "an outboxd service is already running"
    fi

    temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/outboxd-install.XXXXXXXX")

    step "Resolving the latest stable release"
    latest_url=$(curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 \
        --output /dev/null --write-out '%{url_effective}' \
        "https://github.com/$repository/releases/latest")
    tag=${latest_url##*/}

    case $latest_url in
        "https://github.com/$repository/releases/tag/"*)
            ;;
        *)
            fail "GitHub returned an unexpected latest-release URL: $latest_url"
            ;;
    esac

    if ! printf '%s\n' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
        fail "latest release is not stable SemVer: $tag"
    fi
    version=${tag#v}

    version_supported=$(printf '%s\n' "$version" | awk -F. '{
    if ($1 > 0 || ($1 == 0 && ($2 > 2 || ($2 == 2 && $3 >= 1)))) {
        print "yes"
    }
}')
    if [ "$version_supported" != yes ]; then
        fail "guided installation requires outboxd v0.2.1 or newer; latest is $tag"
    fi

    archive="outboxd_${version}_linux_${architecture}.tar.gz"
    archive_base=${archive%.tar.gz}
    release_url="https://github.com/$repository/releases/download/$tag"

    step "Downloading $tag for linux/$architecture"
    curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 \
        --output "$temporary_directory/$archive" "$release_url/$archive"
    curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 \
        --output "$temporary_directory/SHA256SUMS" "$release_url/SHA256SUMS"

    checksum_size=$(wc -c <"$temporary_directory/SHA256SUMS" | tr -d ' ')
    if [ "$checksum_size" -le 0 ]; then
        fail "SHA256SUMS has an invalid size"
    fi

    if [ "$checksum_size" -gt 1048576 ]; then
        fail "SHA256SUMS has an invalid size"
    fi

    if ! expected_checksum=$(awk -v filename="$archive" '
    $2 == filename || $2 == "*" filename {
        if (length($1) != 64 || $1 !~ /^[0-9A-Fa-f]+$/) {
            exit 2
        }
        count++
        checksum = tolower($1)
    }
    END {
        if (count != 1) {
            exit 1
        }
        print checksum
    }
' "$temporary_directory/SHA256SUMS"); then
        fail "SHA256SUMS does not contain exactly one valid entry for $archive"
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        actual_checksum=$(sha256sum "$temporary_directory/$archive" | awk '{ print tolower($1) }')
    elif command -v shasum >/dev/null 2>&1; then
        actual_checksum=$(shasum -a 256 "$temporary_directory/$archive" | awk '{ print tolower($1) }')
    else
        fail "sha256sum or shasum is required"
    fi

    if [ "$actual_checksum" != "$expected_checksum" ]; then
        fail "checksum verification failed for $archive"
    fi

    success "Release checksum verified"

    tar -tzf "$temporary_directory/$archive" >"$temporary_directory/archive.list"

    if ! awk -v root="$archive_base/" '
    index($0, root) != 1 {
        exit 1
    }
    {
        count = split($0, components, "/")
        for (i = 1; i <= count; i++) {
            if (components[i] == "..") {
                exit 1
            }
        }
    }
' "$temporary_directory/archive.list"; then
        fail "archive contains an unsafe path"
    fi

    if ! tar -tvzf "$temporary_directory/$archive" | awk '
    substr($0, 1, 1) != "-" && substr($0, 1, 1) != "d" {
        exit 1
    }
'; then
        fail "archive contains a link or unsupported entry type"
    fi

    mkdir "$temporary_directory/staging"
    tar --no-same-owner --no-same-permissions -xzf "$temporary_directory/$archive" -C "$temporary_directory/staging"
    payload=$temporary_directory/staging/$archive_base

    for required_file in outboxd conf/outboxd.conf conf/outboxd.service conf/setup.sh conf/uninstall.sh; do
        if [ -L "$payload/$required_file" ]; then
            fail "release is missing $required_file"
        fi

        if [ ! -f "$payload/$required_file" ]; then
            fail "release is missing $required_file"
        fi
    done

    if [ ! -x "$payload/outboxd" ]; then
        fail "release binary is not executable"
    fi

    if [ "$("$payload/outboxd" --version)" != "$tag" ]; then
        fail "release binary version does not match $tag"
    fi

    if ! grep -Fq 'config_file=$payload/config.yml' "$payload/conf/setup.sh"; then
        fail "release does not use the /opt/outboxd configuration layout"
    fi

    if ! grep -Fq 'usage: setup.sh [--no-enable]' "$payload/conf/setup.sh"; then
        fail "release setup does not support guided installation"
    fi

    if ! grep -Fq 'ExecStart=/opt/outboxd/outboxd -config /opt/outboxd/config.yml serve' "$payload/conf/outboxd.service"; then
        fail "release service layout is incompatible"
    fi

    heading "Configuration"
    step "Creating the initial configuration"
    "$payload/outboxd" -config "$temporary_directory/config.yml" provision

    while :; do
        prompt "Submission hostname (for example mail.example.com)"
        smtp_hostname=$(lowercase "$REPLY")

        case $smtp_hostname in
            *.invalid)
                ;;
            *)
                if valid_domain "$smtp_hostname"; then
                    break
                fi
                ;;
        esac

        printf '%s\n' "Enter a valid fully qualified hostname." >&4
    done

    default_domain=${smtp_hostname#*.}

    if [ "$default_domain" = "$smtp_hostname" ]; then
        default_domain=
    fi

    while :; do
        prompt "Sending domain" "$default_domain"
        sending_domain=$(lowercase "$REPLY")

        case $sending_domain in
            *.invalid)
                ;;
            *)
                if valid_domain "$sending_domain"; then
                    break
                fi
                ;;
        esac

        printf '%s\n' "Enter a valid sending domain." >&4
    done

    while :; do
        prompt "Public IPv4 address (leave blank if IPv6-only)"
        public_ipv4=$REPLY

        if [ -z "$public_ipv4" ]; then
            break
        fi

        if valid_ipv4 "$public_ipv4"; then
            break
        fi

        printf '%s\n' "Enter a valid IPv4 address or leave it blank." >&4
    done

    while :; do
        prompt "Public IPv6 address (optional)"
        public_ipv6=$REPLY

        if [ -z "$public_ipv6" ]; then
            break
        fi

        if valid_ipv6_shape "$public_ipv6"; then
            break
        fi

        printf '%s\n' "Enter a valid IPv6 address or leave it blank." >&4
    done

    if [ -z "$public_ipv4" ]; then
        if [ -z "$public_ipv6" ]; then
            fail "at least one public IP address is required"
        fi
    fi

    use_letsencrypt=0

    if confirm "Import an existing Let's Encrypt certificate?" n; then
        use_letsencrypt=1

        while :; do
            prompt "Certbot certificate name" "$smtp_hostname"
            certificate_name=$REPLY

            case $certificate_name in
                '' | . | .. | *[!A-Za-z0-9_.-]*)
                    printf '%s\n' "Enter a valid Certbot certificate name." >&4
                    ;;
                *)
                    if run_root test -f "/etc/letsencrypt/live/$certificate_name/fullchain.pem"; then
                        if run_root test -f "/etc/letsencrypt/live/$certificate_name/privkey.pem"; then
                            break
                        fi
                    fi

                    printf '%s\n' "That lineage does not contain fullchain.pem and privkey.pem." >&4
                    ;;
            esac
        done
    else
        warning "A publicly trusted certificate is recommended for production submission."

        if ! confirm "Use a self-signed development certificate so outboxd can start?" n; then
            fail "a serving TLS certificate is required"
        fi
    fi

    set_config_value server hostname "$smtp_hostname"
    set_config_value server domain "$sending_domain"
    set_config_value server data_directory /opt/outboxd/data
    set_config_value dns public_ipv4 "${public_ipv4:-\"\"}"
    set_config_value dns public_ipv6 "${public_ipv6:-\"\"}"

    if [ "$use_letsencrypt" -eq 1 ]; then
        set_config_value tls mode files
        set_config_value tls allow_self_signed_serving false
        set_config_value tls certificate_file /opt/outboxd/tls/fullchain.pem
        set_config_value tls private_key_file /opt/outboxd/tls/privkey.pem
    else
        set_config_value tls mode self_signed
        set_config_value tls allow_self_signed_serving true
        set_config_value tls certificate_file tls/server.crt
        set_config_value tls private_key_file tls/server.key
    fi

    step "Validating the configuration"
    "$payload/outboxd" -config "$temporary_directory/config.yml" config update >/dev/null

    heading "SMTP users"
    say "At least one enabled SMTP user is required."
    user_count=0
    : >"$temporary_directory/openpgp-plans"
    : >"$temporary_directory/openpgp-senders"

    while :; do
        prompt "SMTP username"
        smtp_username=$REPLY
        if [ -z "$smtp_username" ]; then
            fail "username must not be empty"
        fi

        case $smtp_username in
            *[!A-Za-z0-9_.@+-]*)
                printf '%s\n' "The guided installer limits usernames to letters, digits, _, ., @, + and -." >&4
                continue
                ;;
        esac

        case $smtp_username in
            *@*)
                default_sender=$smtp_username
                ;;
            *)
                default_sender="$smtp_username@$sending_domain"
                ;;
        esac

        prompt "Allowed sender addresses (space-separated)" "$default_sender"
        allowed_senders=$REPLY

        if [ -z "$allowed_senders" ]; then
            fail "at least one sender is required"
        fi

        set -- $allowed_senders

        if ! "$payload/outboxd" -config "$temporary_directory/config.yml" user add "$smtp_username" "$@" <&3 >&4; then
            printf '%s\n' "The user was not added. Check the username and sender addresses, then try again." >&4
            continue
        fi

        user_count=$((user_count + 1))

        for openpgp_sender in "$@"; do
            case $openpgp_sender in
                \**)
                    printf '%s\n' "OpenPGP generation is unavailable for wildcard sender $openpgp_sender; add an exact sender to generate a key." >&4
                    continue
                    ;;
            esac

            if confirm "Generate an encrypted OpenPGP signing key for $openpgp_sender?" n; then
                sender_local=${openpgp_sender%@*}
                sender_domain=${openpgp_sender##*@}
                sender_identity="$sender_local@$(lowercase "$sender_domain")"

                if grep -Fxq "$sender_identity" "$temporary_directory/openpgp-senders"; then
                    printf '%s\n' "An OpenPGP key is already planned for $openpgp_sender; skipping the duplicate." >&4
                else
                    printf '%s\n' "$sender_identity" >>"$temporary_directory/openpgp-senders"
                    printf '%s\t%s\n' "$smtp_username" "$openpgp_sender" >>"$temporary_directory/openpgp-plans"
                fi
            fi
        done

        if ! confirm "Add another SMTP user?" n; then
            break
        fi
    done

    if [ "$user_count" -le 0 ]; then
        fail "at least one user is required"
    fi

    if ! confirm "Install $tag to $install_directory?" y; then
        fail "installation cancelled"
    fi

    heading "Installation"
    step "Installing release payload"
    run_root install -d -o root -g root -m 0755 "$install_directory"
    installed=1
    run_root cp -R "$payload/." "$install_directory/"
    run_root systemd-sysusers "$install_directory/conf/outboxd.conf"
    run_root install -o root -g outboxd -m 0440 "$temporary_directory/config.yml" "$config_file"
    step "Installing the systemd service"
    run_setup
    success "Release payload and service definition installed"
    run_outboxd "$binary" -config "$config_file" provision

    if [ "$use_letsencrypt" -eq 1 ]; then
        step "Importing the Let's Encrypt certificate and installing its Certbot deploy hook"
        install_certbot_hook "$certificate_name"
    fi

    tab=$(printf '\t')

    while IFS="$tab" read -r openpgp_username openpgp_sender; do
        if [ -z "$openpgp_username" ]; then
            continue
        fi

        if ! run_admin "$binary" -config "$config_file" openpgp create "$openpgp_username" "$openpgp_sender" >&4; then
            if run_root test -d /opt/outboxd/data/openpgp; then
                run_root chown -R --no-dereference outboxd:outboxd /opt/outboxd/data/openpgp
            fi

            if ! run_root "$install_directory/conf/setup.sh" --no-enable; then
                warning "Could not restore service setup after OpenPGP generation failed."
            fi

            fail "OpenPGP key generation failed for $openpgp_sender"
        fi

        run_root chown -R --no-dereference outboxd:outboxd /opt/outboxd/data/openpgp
    done <"$temporary_directory/openpgp-plans"

    if run_root test -d /opt/outboxd/data/openpgp; then
        run_root chown -R --no-dereference outboxd:outboxd /opt/outboxd/data/openpgp
    fi

    step "Finalizing ownership and service configuration"
    run_setup
    run_outboxd "$binary" -config "$config_file" provision
    success "Private key material validated"

    heading "DNS records"
    run_outboxd "$binary" -config "$config_file" dns >&4

    heading "Service"
    step "Starting outboxd"
    run_root systemctl enable --now outboxd
    sleep 5
    service_state=$(run_root systemctl show outboxd --property=ActiveState --value)
    service_substate=$(run_root systemctl show outboxd --property=SubState --value)
    service_restarts=$(run_root systemctl show outboxd --property=NRestarts --value)
    service_healthy=true

    if [ "$service_state" != active ]; then
        service_healthy=false
    fi

    if [ "$service_substate" != running ]; then
        service_healthy=false
    fi

    if [ "$service_restarts" != 0 ]; then
        service_healthy=false
    fi

    if [ "$service_healthy" = false ]; then
        if ! run_root journalctl -u outboxd -n 50 --no-pager >&4; then
            warning "Could not read the outboxd journal."
        fi

        fail "outboxd did not remain stably active"
    fi

    success "outboxd $tag is installed and running"
    say ""
    say "Publish the records in /opt/outboxd/data/dns-records.txt and configure matching reverse DNS."
    say "After DNS propagation, verify the deployment with:"
    say "  sudo -u outboxd /opt/outboxd/outboxd -config /opt/outboxd/config.yml check"
    say "Logs are available with: journalctl -u outboxd"
}

main "$@"
