#!/usr/bin/env bash
#
# harden.sh — baseline hardening for a fresh Debian 12/13 server.
#
# Idempotent: safe to run more than once. Each step checks the current state
# before changing anything. Designed not to lock you out of SSH.
#
# What it does (each step can be skipped with a flag):
#   1. Optional admin user with sudo + your SSH public key.
#   2. SSH hardening via a drop-in (no root login, key-only auth).
#   3. UFW firewall: default deny incoming, allow SSH (+ extra ports).
#   4. Fail2Ban: sshd jail backed by systemd + ufw.
#   5. Unattended security upgrades.
#
# Usage:
#   sudo ./harden.sh [options]
#
# Options:
#   --ssh-port N           SSH port to allow/protect (default: 22)
#   --admin-user NAME      create/ensure this sudo user before locking SSH
#   --pubkey "ssh-ed25519 AAAA..."   public key to install for --admin-user
#   --no-passwordless-sudo don't grant --admin-user passwordless sudo
#                          (they have no password, so they couldn't sudo at all)
#   --allow-port N[/proto] extra port to open in UFW (repeatable), e.g. 80/tcp
#   --no-ssh               skip SSH hardening
#   --no-ufw               skip firewall
#   --no-fail2ban          skip Fail2Ban
#   --no-autoupdates       skip unattended-upgrades
#   --force-no-password    disable SSH password auth even if no key is found
#                          (DANGEROUS: only with console access)
#   --dry-run              print what would change, do nothing
#   -y, --yes              don't ask for confirmation
#   -h, --help             this help
#
set -euo pipefail

# ---- Defaults -------------------------------------------------------------
SSH_PORT=22
ADMIN_USER=""
ADMIN_PUBKEY=""
EXTRA_PORTS=()
DO_SSH=1
DO_UFW=1
DO_FAIL2BAN=1
DO_AUTOUPDATES=1
FORCE_NO_PASSWORD=0
PASSWORDLESS_SUDO=1
DRY_RUN=0
ASSUME_YES=0

SSHD_DROPIN="/etc/ssh/sshd_config.d/99-hardening.conf"
F2B_JAIL="/etc/fail2ban/jail.local"

# ---- Pretty logging -------------------------------------------------------
c_reset=$'\e[0m'; c_blue=$'\e[34m'; c_green=$'\e[32m'; c_yellow=$'\e[33m'; c_red=$'\e[31m'
log()  { printf '%s[*]%s %s\n' "$c_blue"   "$c_reset" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$c_green"  "$c_reset" "$*"; }
warn() { printf '%s[!]%s %s\n' "$c_yellow" "$c_reset" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$c_red"    "$c_reset" "$*" >&2; }

# run CMD ARGS... — execute a command, or just print it under --dry-run.
# Takes a real argument vector (no eval): keeps quoting intact. Commands that
# need redirection or shell operators are handled inline, not through run().
run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s %s\n' "$c_yellow" "$c_reset" "$*"
    else
        "$@"
    fi
}

# ---- Arg parsing ----------------------------------------------------------
usage() { sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# Parse argv into the global flags. Kept as a function (rather than top-level
# code) so the script can be sourced for unit tests without running it.
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --ssh-port)        SSH_PORT="$2"; shift 2;;
            --admin-user)      ADMIN_USER="$2"; shift 2;;
            --pubkey)          ADMIN_PUBKEY="$2"; shift 2;;
            --allow-port)      EXTRA_PORTS+=("$2"); shift 2;;
            --no-ssh)          DO_SSH=0; shift;;
            --no-ufw)          DO_UFW=0; shift;;
            --no-fail2ban)     DO_FAIL2BAN=0; shift;;
            --no-autoupdates)  DO_AUTOUPDATES=0; shift;;
            --force-no-password) FORCE_NO_PASSWORD=1; shift;;
            --no-passwordless-sudo) PASSWORDLESS_SUDO=0; shift;;
            --dry-run)         DRY_RUN=1; shift;;
            -y|--yes)          ASSUME_YES=1; shift;;
            -h|--help)         usage 0;;
            *) err "Unknown option: $1"; usage 1;;
        esac
    done
}

# ---- Preflight ------------------------------------------------------------
require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        err "Run as root (sudo $0 ...)."; exit 1
    fi
}

check_debian() {
    if ! grep -qi debian /etc/os-release 2>/dev/null; then
        warn "This does not look like Debian. Continuing anyway."
    fi
}

confirm() {
    [ "$ASSUME_YES" -eq 1 ] && return 0
    [ "$DRY_RUN" -eq 1 ] && return 0
    printf '%s[?]%s %s [y/N] ' "$c_yellow" "$c_reset" "$1"
    read -r ans
    case "$ans" in y|Y|yes|YES) return 0;; *) return 1;; esac
}

# Does the target account have at least one authorized SSH key?
has_authorized_key() {
    local user="$1" home akf
    home=$(getent passwd "$user" | cut -d: -f6)
    [ -n "$home" ] || return 1
    akf="$home/.ssh/authorized_keys"
    [ -s "$akf" ]
}

# ---- Steps ----------------------------------------------------------------
ensure_admin_user() {
    [ -n "$ADMIN_USER" ] || return 0
    log "Ensuring sudo user '$ADMIN_USER'"
    if id "$ADMIN_USER" >/dev/null 2>&1; then
        ok "User '$ADMIN_USER' already exists"
    else
        run adduser --disabled-password --gecos "" "$ADMIN_USER"
        ok "Created user '$ADMIN_USER'"
    fi
    # sudo group membership (idempotent)
    if id -nG "$ADMIN_USER" 2>/dev/null | grep -qw sudo; then
        ok "'$ADMIN_USER' already in sudo"
    else
        run usermod -aG sudo "$ADMIN_USER"
        ok "Added '$ADMIN_USER' to sudo"
    fi
    # The account is created with --disabled-password (key-only login), so the
    # sudo group alone isn't enough to escalate — there's no password to type.
    # Grant passwordless sudo via a drop-in, validated with visudo before it
    # goes live, so a bad rule can never break sudo on the host.
    if [ -n "$ADMIN_USER" ] && [ "$PASSWORDLESS_SUDO" -eq 1 ]; then
        local sudoers_file="/etc/sudoers.d/$ADMIN_USER"
        local sudoers_rule="$ADMIN_USER ALL=(ALL) NOPASSWD:ALL"
        if [ "$DRY_RUN" -eq 1 ]; then
            printf '    %s(dry-run)%s write %s: %s\n' "$c_yellow" "$c_reset" "$sudoers_file" "$sudoers_rule"
        elif [ -f "$sudoers_file" ] && grep -qxF "$sudoers_rule" "$sudoers_file"; then
            ok "Passwordless sudo already configured for '$ADMIN_USER'"
        else
            local tmp
            tmp=$(mktemp)
            printf '%s\n' "$sudoers_rule" > "$tmp"
            if visudo -cf "$tmp" >/dev/null 2>&1; then
                install -m 440 -o root -g root "$tmp" "$sudoers_file"
                ok "Configured passwordless sudo for '$ADMIN_USER'"
            else
                rm -f "$tmp"
                err "Generated sudoers rule failed validation — not installing"
                return 1
            fi
            rm -f "$tmp"
        fi
    fi
    # install pubkey if given and not already present
    if [ -n "$ADMIN_PUBKEY" ]; then
        local home akf
        home=$(getent passwd "$ADMIN_USER" | cut -d: -f6)
        akf="$home/.ssh/authorized_keys"
        run install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$home/.ssh"
        if [ "$DRY_RUN" -eq 1 ]; then
            printf '    %s(dry-run)%s append public key to %s\n' "$c_yellow" "$c_reset" "$akf"
        elif grep -qsF "$ADMIN_PUBKEY" "$akf"; then
            ok "Public key already installed for '$ADMIN_USER'"
        else
            printf '%s\n' "$ADMIN_PUBKEY" >> "$akf"
            chown "$ADMIN_USER:$ADMIN_USER" "$akf"
            chmod 600 "$akf"
            ok "Installed public key for '$ADMIN_USER'"
        fi
    fi
}

harden_ssh() {
    [ "$DO_SSH" -eq 1 ] || { log "Skipping SSH hardening"; return 0; }
    log "Hardening SSH (drop-in $SSHD_DROPIN)"

    # Lockout guard: PasswordAuthentication stays "yes" unless we can confirm
    # there's a usable SSH key (or the user forces it with console access).
    local pw_auth="no"
    local key_owner="${ADMIN_USER:-root}"
    if ! has_authorized_key "$key_owner" && ! has_authorized_key root; then
        if [ "$FORCE_NO_PASSWORD" -eq 1 ]; then
            warn "No authorized_keys found, but --force-no-password set. Disabling password auth anyway."
        else
            pw_auth="yes"
            warn "No authorized_keys found for '$key_owner' or root."
            warn "Keeping PasswordAuthentication ENABLED to avoid locking you out."
            warn "Add a key (or use --pubkey) and re-run, or pass --force-no-password."
        fi
    fi

    local content
    content=$(cat <<EOF
# Managed by debian-hardening (harden.sh). Edit flags, not this file.
Port ${SSH_PORT}
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication ${pw_auth}
KbdInteractiveAuthentication no
EOF
)
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would write %s:\n' "$c_yellow" "$c_reset" "$SSHD_DROPIN"
        printf '%s\n' "$content" | sed 's/^/        /'
        return 0
    fi

    install -d -m 755 /etc/ssh/sshd_config.d
    printf '%s\n' "$content" > "$SSHD_DROPIN"
    chmod 644 "$SSHD_DROPIN"
    if sshd -t; then
        systemctl reload ssh 2>/dev/null || systemctl reload sshd
        ok "SSH config applied and reloaded"
    else
        err "sshd config test FAILED — not reloading. Check $SSHD_DROPIN"
        return 1
    fi
}

setup_ufw() {
    [ "$DO_UFW" -eq 1 ] || { log "Skipping UFW"; return 0; }
    log "Configuring UFW firewall"
    command -v ufw >/dev/null 2>&1 || run apt-get install -y ufw
    run ufw --force default deny incoming
    run ufw --force default allow outgoing
    run ufw allow "${SSH_PORT}/tcp"
    local p
    for p in "${EXTRA_PORTS[@]:-}"; do
        [ -n "$p" ] || continue
        run ufw allow "$p"
        ok "Allowed extra port: ${p}"
    done
    run ufw --force enable
    ok "UFW enabled (deny incoming, SSH on ${SSH_PORT})"
}

setup_fail2ban() {
    [ "$DO_FAIL2BAN" -eq 1 ] || { log "Skipping Fail2Ban"; return 0; }
    log "Configuring Fail2Ban (sshd jail)"
    command -v fail2ban-client >/dev/null 2>&1 || run apt-get install -y fail2ban
    local jail
    jail=$(cat <<EOF
# Managed by debian-hardening (harden.sh).
[DEFAULT]
banaction = ufw
backend   = systemd

[sshd]
enabled  = true
port     = ${SSH_PORT}
bantime  = 1h
findtime = 10m
maxretry = 5
EOF
)
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would write %s\n' "$c_yellow" "$c_reset" "$F2B_JAIL"
        return 0
    fi
    printf '%s\n' "$jail" > "$F2B_JAIL"
    systemctl enable --now fail2ban >/dev/null 2>&1 || true
    systemctl restart fail2ban
    ok "Fail2Ban configured (ban 1h, maxretry 5, backend systemd)"
}

setup_autoupdates() {
    [ "$DO_AUTOUPDATES" -eq 1 ] || { log "Skipping unattended-upgrades"; return 0; }
    log "Enabling unattended security upgrades"
    run apt-get install -y unattended-upgrades
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s write /etc/apt/apt.conf.d/20auto-upgrades and enable service\n' "$c_yellow" "$c_reset"
        return 0
    fi
    printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
        > /etc/apt/apt.conf.d/20auto-upgrades
    systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
    ok "Unattended security upgrades enabled"
}

# ---- Main -----------------------------------------------------------------
main() {
    require_root
    check_debian

    log "Plan:"
    [ -n "$ADMIN_USER" ]        && echo "    - ensure sudo user '$ADMIN_USER'"
    [ "$DO_SSH" -eq 1 ]         && echo "    - harden SSH (port $SSH_PORT, key-only, no root)"
    [ "$DO_UFW" -eq 1 ]         && echo "    - UFW: deny incoming, allow $SSH_PORT/tcp ${EXTRA_PORTS[*]:-}"
    [ "$DO_FAIL2BAN" -eq 1 ]    && echo "    - Fail2Ban sshd jail"
    [ "$DO_AUTOUPDATES" -eq 1 ] && echo "    - unattended security upgrades"
    [ "$DRY_RUN" -eq 1 ]        && warn "DRY-RUN: nothing will be changed."

    confirm "Proceed?" || { warn "Aborted."; exit 0; }

    if [ "$DRY_RUN" -eq 0 ]; then
        log "Updating package lists"
        apt-get update -qq || warn "apt-get update failed"
    fi

    ensure_admin_user
    harden_ssh
    setup_ufw
    setup_fail2ban
    setup_autoupdates

    ok "Done. Review with: sshd -T | grep -Ei 'passwordauth|permitroot' ; ufw status verbose ; fail2ban-client status sshd"
}

# Only run when executed directly; sourcing (e.g. from the test suite) just
# loads the functions without parsing args or touching the system.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    parse_args "$@"
    main
fi
