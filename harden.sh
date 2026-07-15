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
#   6. Kernel hardening via sysctl (no ICMP redirects, no source routing,
#      rp_filter, syncookies, restricted dmesg/kptr).
#   7. Account policies: password aging in login.defs (max 365 / min 1 /
#      warn 7) and a 30-day inactivity lock for accounts created from now on.
#   8. Mount options: /dev/shm remounted (and pinned in fstab) with
#      nodev,nosuid,noexec — world-writable shared memory stops being a
#      launchpad for droppers.
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
#   --no-sysctl            skip kernel hardening (sysctl)
#   --no-account-policies  skip password-aging / inactivity policies
#   --no-mount-options     skip /dev/shm mount hardening
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
DO_SYSCTL=1
DO_ACCOUNT_POLICIES=1
DO_MOUNT_OPTIONS=1
FORCE_NO_PASSWORD=0
PASSWORDLESS_SUDO=1
DRY_RUN=0
ASSUME_YES=0

SSHD_DROPIN="/etc/ssh/sshd_config.d/99-hardening.conf"
F2B_JAIL="/etc/fail2ban/jail.local"
SYSCTL_DROPIN="/etc/sysctl.d/99-hardening.conf"

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
usage() { sed -n '2,43p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

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
            --no-sysctl)       DO_SYSCTL=0; shift;;
            --no-account-policies) DO_ACCOUNT_POLICIES=0; shift;;
            --no-mount-options) DO_MOUNT_OPTIONS=0; shift;;
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
# CIS-style extra hardening.
MaxAuthTries 4
X11Forwarding no
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 3
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
# OpenSSH >= 9.8 splits auth into an 'sshd-session' process, so the stock
# filter's '_COMM=sshd' journal match misses the failures and never bans.
# Match on the ssh unit alone (covers sshd and its sshd-session children).
journalmatch = _SYSTEMD_UNIT=ssh.service
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

setup_sysctl() {
    [ "$DO_SYSCTL" -eq 1 ] || { log "Skipping kernel hardening (sysctl)"; return 0; }
    log "Hardening kernel parameters (drop-in $SYSCTL_DROPIN)"
    local content
    content=$(cat <<'EOF'
# Managed by debian-hardening (harden.sh). Edit flags, not this file.
#
# Deliberately NOT set here, to keep the "won't lock you out" promise:
#   net.ipv6.conf.*.accept_ra  — would break IPv6 SLAAC on many VPSes
#   net.ipv4.ip_forward        — would break routers / Docker hosts

# ICMP redirects: don't accept or send them (route injection / MITM).
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Source-routed packets: legacy feature, only useful for spoofing.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Reverse-path filtering: drop packets whose return route doesn't match.
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log packets with impossible source addresses ("martians").
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# SYN-flood protection and ICMP noise reduction.
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Kernel info leaks and setuid core dumps.
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1
fs.suid_dumpable = 0
EOF
)
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would write %s and apply it with sysctl -p\n' "$c_yellow" "$c_reset" "$SYSCTL_DROPIN"
        return 0
    fi
    printf '%s\n' "$content" > "$SYSCTL_DROPIN"
    chmod 644 "$SYSCTL_DROPIN"
    # UFW ships an explicit log_martians=0 in /etc/ufw/sysctl.conf and
    # re-applies it on every start/reload (IPT_SYSCTL in /etc/default/ufw) —
    # silently undoing our drop-in after any reboot or ufw reload. Keep both
    # sources in agreement.
    if [ -f /etc/ufw/sysctl.conf ]; then
        sed -i 's|^net/ipv4/conf/all/log_martians=0$|net/ipv4/conf/all/log_martians=1|; s|^net/ipv4/conf/default/log_martians=0$|net/ipv4/conf/default/log_martians=1|' /etc/ufw/sysctl.conf
    fi
    # -e ignores keys this kernel doesn't have. In an unprivileged container
    # some keys are read-only; the file is still in place for the next boot,
    # so that's a warning, not a failure.
    if sysctl -e -p "$SYSCTL_DROPIN" >/dev/null 2>&1; then
        ok "Kernel parameters applied (sysctl)"
    else
        warn "Some sysctl keys could not be applied live (container?). They will apply on boot."
    fi
}

setup_account_policies() {
    [ "$DO_ACCOUNT_POLICIES" -eq 1 ] || { log "Skipping account policies (login.defs)"; return 0; }
    log "Tightening account policies (password aging + inactivity lock)"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would set PASS_MAX_DAYS 365 / PASS_MIN_DAYS 1 / PASS_WARN_AGE 7 in /etc/login.defs, INACTIVE=30 in useradd defaults, and age existing password-holding accounts\n' "$c_yellow" "$c_reset"
        return 0
    fi
    # login.defs: Debian ships these keys active (99999 / 0 / 7) — replace in
    # place; append if a future image drops one. CIS 5.4.1: max 365, min 1,
    # warn 7.
    local spec key val
    for spec in "PASS_MAX_DAYS 365" "PASS_MIN_DAYS 1" "PASS_WARN_AGE 7"; do
        key=${spec% *}; val=${spec#* }
        if grep -qE "^${key}\b" /etc/login.defs; then
            sed -i -E "s|^${key}\b.*|${key}\t${val}|" /etc/login.defs
        else
            printf '%s\t%s\n' "$key" "$val" >> /etc/login.defs
        fi
    done
    # Accounts created from now on get locked 30 days after their password
    # expires (CIS 5.4.2). Written to /etc/default/useradd.
    useradd -D -f 30 >/dev/null
    # Existing accounts that actually hold a password: apply the same aging.
    # login.defs only affects accounts created later, so without this pass the
    # policy would be theater on a server with existing users. Two deliberate
    # exclusions to keep the "won't lock you out" promise:
    #   - locked/passwordless accounts ("!", "*") are untouched — key-only
    #     admins (like the one step 1 creates) never see any of this;
    #   - --inactive is NOT applied to existing accounts: one whose password
    #     expired more than 30 days ago would be locked ON THE SPOT.
    local u hash
    while IFS=: read -r u hash _; do
        case "$hash" in
            ''|'!'*|'*') continue;;
        esac
        chage --maxdays 365 --mindays 1 --warndays 7 "$u"
    done < /etc/shadow
    ok "Account policies set (aging 365/1/7; 30-day inactivity lock for new accounts)"
}

setup_mount_options() {
    [ "$DO_MOUNT_OPTIONS" -eq 1 ] || { log "Skipping mount options (/dev/shm)"; return 0; }
    log "Hardening /dev/shm mount options (nodev,nosuid,noexec)"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would pin /dev/shm in /etc/fstab with nodev,nosuid,noexec and remount it live\n' "$c_yellow" "$c_reset"
        return 0
    fi
    # /dev/shm is world-writable by design — any user or compromised service
    # can write there. With exec/suid/dev allowed it's the classic staging
    # ground for droppers (CIS 1.1.2.2). Only /dev/shm is touched: /tmp is
    # deliberately left alone because a noexec /tmp breaks well-behaved
    # installers, and Debian doesn't ship it as a separate mount anyway.

    # fstab: Debian normally has NO /dev/shm entry (systemd mounts it), so the
    # options must be pinned to survive reboots. If an entry already exists,
    # only its options field is edited — a custom size= or quota stays intact.
    if grep -qE '^[^#[:space:]]+[[:space:]]+/dev/shm[[:space:]]' /etc/fstab; then
        local tmp
        tmp=$(mktemp)
        awk '
            $1 !~ /^#/ && $2 == "/dev/shm" {
                n = split($4, have, ",")
                for (i = 1; i <= n; i++) seen[have[i]] = 1
                split("nodev,nosuid,noexec", want, ",")
                for (i = 1; i <= 3; i++) if (!seen[want[i]]) $4 = $4 "," want[i]
                delete seen
                if ($5 == "") $5 = "0"
                if ($6 == "") $6 = "0"
                print $1 "\t" $2 "\t" $3 "\t" $4 "\t" $5 "\t" $6
                next
            }
            { print }
        ' /etc/fstab > "$tmp"
        if cmp -s "$tmp" /etc/fstab; then
            ok "fstab entry for /dev/shm already has nodev,nosuid,noexec"
            rm -f "$tmp"
        else
            install -m 644 -o root -g root "$tmp" /etc/fstab
            rm -f "$tmp"
            ok "Added missing options to the existing /dev/shm fstab entry"
        fi
    else
        printf 'tmpfs\t/dev/shm\ttmpfs\tdefaults,nodev,nosuid,noexec\t0\t0\n' >> /etc/fstab
        ok "Pinned /dev/shm in /etc/fstab with nodev,nosuid,noexec"
    fi

    # Live remount, only if something is actually missing (keeps idempotence
    # honest: a second pass must not touch the mount table).
    if mountpoint -q /dev/shm; then
        local opts o missing=0
        opts=$(findmnt -no OPTIONS /dev/shm)
        for o in nodev nosuid noexec; do
            case ",$opts," in *",$o,"*) ;; *) missing=1;; esac
        done
        if [ "$missing" -eq 1 ]; then
            run mount -o remount,nodev,nosuid,noexec /dev/shm
            ok "Remounted /dev/shm with nodev,nosuid,noexec"
        else
            ok "/dev/shm already mounted with nodev,nosuid,noexec"
        fi
    else
        warn "/dev/shm is not a mountpoint here — fstab pinned, nothing to remount"
    fi
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
    [ "$DO_SYSCTL" -eq 1 ]      && echo "    - kernel hardening (sysctl drop-in)"
    [ "$DO_ACCOUNT_POLICIES" -eq 1 ] && echo "    - account policies (password aging + inactivity lock)"
    [ "$DO_MOUNT_OPTIONS" -eq 1 ]    && echo "    - mount options (/dev/shm nodev,nosuid,noexec)"
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
    setup_sysctl
    setup_account_policies
    setup_mount_options

    ok "Done. Review with: sshd -T | grep -Ei 'passwordauth|permitroot' ; ufw status verbose ; fail2ban-client status sshd"
}

# Only run when executed directly; sourcing (e.g. from the test suite) just
# loads the functions without parsing args or touching the system.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    parse_args "$@"
    main
fi
