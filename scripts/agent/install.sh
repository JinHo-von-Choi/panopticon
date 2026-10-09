#!/usr/bin/env bash
# PANOPTICON_CONSOLE_URL=https://console.example PANOPTICON_ENROLLMENT_TOKEN=... \
# PANOPTICON_AGENT_BINARY_URL=https://artifacts.example/linux-x86_64/panopticon-agent \
# PANOPTICON_AGENT_SHA256=... bash install.sh
set -euo pipefail
umask 077
fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ ${EUID} -eq 0 ]] || fail 'Run as root (sudo must preserve the PANOPTICON_* environment variables).'
[[ $(uname -s) == Linux ]] || fail 'Only Linux is supported.'
case $(uname -m) in
    x86_64|aarch64) architecture=$(uname -m) ;;
    *) fail 'Supported architectures: x86_64, aarch64.' ;;
esac
command -v systemctl >/dev/null || fail 'systemd is required.'
[[ -d /run/systemd/system ]] || fail 'systemd must be running.'
: "${PANOPTICON_CONSOLE_URL:?Set PANOPTICON_CONSOLE_URL}"
: "${PANOPTICON_ENROLLMENT_TOKEN:?Set PANOPTICON_ENROLLMENT_TOKEN}"
console_pattern='^https://(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+)(:[0-9]+)?$'
[[ $PANOPTICON_CONSOLE_URL =~ $console_pattern || $PANOPTICON_CONSOLE_URL =~ ^http://(localhost|127\.0\.0\.1)(:[0-9]+)?$ ]] || fail 'Use an HTTPS console origin (loopback HTTP is allowed for development).'
[[ $PANOPTICON_ENROLLMENT_TOKEN =~ ^[a-zA-Z0-9._~-]{16,512}$ ]] || fail 'Enrollment token must contain 16-512 URL-safe characters.'
workspace=$(mktemp -d)
trap 'rm -rf -- "$workspace"' EXIT
if [[ -n ${PANOPTICON_AGENT_BINARY:-} ]]; then
    [[ -f $PANOPTICON_AGENT_BINARY ]] || fail 'Local binary does not exist.'
    cp -- "$PANOPTICON_AGENT_BINARY" "$workspace/panopticon-agent"
else
    : "${PANOPTICON_AGENT_BINARY_URL:?Set PANOPTICON_AGENT_BINARY_URL or PANOPTICON_AGENT_BINARY}"
    : "${PANOPTICON_AGENT_SHA256:?Set the trusted binary SHA-256}"
    [[ $PANOPTICON_AGENT_BINARY_URL == https://* && $PANOPTICON_AGENT_BINARY_URL != *'?'* && $PANOPTICON_AGENT_BINARY_URL != *'@'* ]] || fail 'Binary URL must use HTTPS without query credentials.'
    [[ $PANOPTICON_AGENT_SHA256 =~ ^[a-fA-F0-9]{64}$ ]] || fail 'Invalid SHA-256.'
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 10 --max-time 120 "$PANOPTICON_AGENT_BINARY_URL" -o "$workspace/panopticon-agent"
    printf '%s  %s\n' "$PANOPTICON_AGENT_SHA256" "$workspace/panopticon-agent" | sha256sum --check --status || fail 'Binary checksum mismatch.'
fi
[[ $(stat -c %s "$workspace/panopticon-agent") -le 15728640 ]] || fail 'Binary exceeds the 15 MiB size budget.'
chmod 700 "$workspace/panopticon-agent"
"$workspace/panopticon-agent" --version >/dev/null || fail "Binary cannot run on $architecture."
install -m 755 "$workspace/panopticon-agent" /usr/local/bin/panopticon-agent
install -d -m 700 /etc/panopticon-agent
printf 'PANOPTICON_CONSOLE_URL=%s\nPANOPTICON_ENROLLMENT_TOKEN=%s\nPANOPTICON_STATE_DIR=/var/lib/panopticon-agent\n' \
    "$PANOPTICON_CONSOLE_URL" "$PANOPTICON_ENROLLMENT_TOKEN" > /etc/panopticon-agent/agent.env
chmod 600 /etc/panopticon-agent/agent.env
cat > /etc/systemd/system/panopticon-agent.service <<'UNIT'
[Unit]
Description=Panopticon host telemetry agent
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/panopticon-agent
EnvironmentFile=/etc/panopticon-agent/agent.env
DynamicUser=yes
StateDirectory=panopticon-agent
StateDirectoryMode=0700
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=
MemoryHigh=15M
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now panopticon-agent.service
printf '%s\n' "Installed panopticon-agent for $architecture." \
    'Status: systemctl status panopticon-agent' \
    'Logs: journalctl -u panopticon-agent' \
    'Enrollments are single-use; rotate the gateway token for each new host.'
