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
#   9. Warning banners (CIS 1.7): legal notice in /etc/issue, /etc/issue.net
#      and /etc/motd (no OS/kernel leak), presented by sshd BEFORE login.
#  10. Sudo hardening (CIS 5.3): use_pty (commands run in their own pty)
#      and a dedicated /var/log/sudo.log, via a visudo-validated drop-in.
#  11. SSH session policies (CIS 5.2): what an authenticated session may do —
#      no TCP/agent forwarding, session/connection caps, verbose logging,
#      no user environment / rhosts / empty passwords. Own drop-in.
#  12. Core dump limits (CIS 1.5): hard core 0 for every account via a
#      limits.d drop-in (root gets its own line — '*' never matches root)
#      and systemd-coredump capped off (Storage=none), so a crashed
#      process can't leave its memory (keys, passwords) on disk.
#  13. Default umask & shell timeout (CIS 5.4): umask 027 in login.defs
#      (pam_umask) plus a profile.d drop-in for login shells, and an idle
#      timeout — readonly TMOUT=900 — so new files aren't group-writable
#      and walked-away-from sessions close themselves.
#  14. Cron restrictions (CIS 5.1): /etc/crontab and the cron.* drop-in
#      directories become root-only, and crontab/at switch from Debian's
#      deny-list model to an allow-list with just root — unprivileged
#      users can't schedule jobs (persistence 101) or read root's.
#  15. Password policy (CIS 5.3/5.4): libpam-pwquality enforcing length 14,
#      all four character classes and no long repeats — for root too
#      (enforce_for_root) — plus the hashing algorithm pinned to yescrypt
#      in login.defs so no tool quietly falls back to a weaker crypt.
#  16. File integrity (CIS 1.4): AIDE fingerprints the system binaries and
#      /etc, so a backdoored sudo or an edited /etc/passwd shows up on the
#      next check. Own config + baseline DB, checked daily by a systemd
#      timer — tampering stops being invisible.
#  17. Rootkit detection: rkhunter checks for known rootkits, backdoors and
#      local exploits, plus suspicious file properties. A property baseline
#      is taken now and re-checked daily by a systemd timer — a second
#      detection layer alongside AIDE (AIDE = generic file integrity,
#      rkhunter = known-threat signatures).
#  18. Kernel module blacklist (CIS 1.1.1 / 3.4): rarely-used filesystems
#      (cramfs, freevxfs, jffs2, hfs, hfsplus, udf) and network protocols
#      (dccp, sctp, rds, tipc) disabled in modprobe.d — an `install
#      /bin/false` line defeats explicit loads, `blacklist` stops alias
#      auto-loading. Every one is kernel attack surface a server never uses.
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
#   --no-banners           skip warning banners
#   --no-sudo-hardening    skip sudo use_pty / logfile
#   --no-ssh-policies      skip SSH session policies (forwarding, caps, ...)
#   --no-coredump-limits   skip core dump limits (hard core 0)
#   --no-umask-tmout       skip default umask 027 / TMOUT shell timeout
#   --no-cron-restrictions skip cron/at allow-list + spool permissions
#   --no-password-policy   skip pwquality rules + yescrypt pin
#   --no-aide              skip AIDE file-integrity baseline + daily timer
#   --no-rkhunter          skip rkhunter rootkit-detection baseline + timer
#   --no-module-blacklist  skip the kernel module blacklist (rare fs + protocols)
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
DO_BANNERS=1
DO_SUDO_HARDENING=1
DO_SSH_POLICIES=1
DO_COREDUMP_LIMITS=1
DO_UMASK_TMOUT=1
DO_CRON_RESTRICTIONS=1
DO_PASSWORD_POLICY=1
DO_AIDE=1
DO_RKHUNTER=1
DO_MODULE_BLACKLIST=1
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
usage() { sed -n '2,90p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

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
            --no-banners)      DO_BANNERS=0; shift;;
            --no-sudo-hardening) DO_SUDO_HARDENING=0; shift;;
            --no-ssh-policies) DO_SSH_POLICIES=0; shift;;
            --no-coredump-limits) DO_COREDUMP_LIMITS=0; shift;;
            --no-umask-tmout)  DO_UMASK_TMOUT=0; shift;;
            --no-cron-restrictions) DO_CRON_RESTRICTIONS=0; shift;;
            --no-password-policy) DO_PASSWORD_POLICY=0; shift;;
            --no-aide)         DO_AIDE=0; shift;;
            --no-rkhunter)     DO_RKHUNTER=0; shift;;
            --no-module-blacklist) DO_MODULE_BLACKLIST=0; shift;;
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

setup_banners() {
    [ "$DO_BANNERS" -eq 1 ] || { log "Skipping warning banners"; return 0; }
    log "Installing pre-auth warning banners (CIS 1.7)"
    local banner="Authorized access only. All activity may be monitored and reported."
    local sshd_banner_dropin="/etc/ssh/sshd_config.d/98-banner.conf"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would write the legal banner to /etc/issue, /etc/issue.net and /etc/motd, and point sshd Banner at /etc/issue.net\n' "$c_yellow" "$c_reset"
        return 0
    fi
    # The stock files advertise the exact OS ("Debian GNU/Linux 13 \n \l"),
    # handing pre-auth reconnaissance to anyone who connects. Replace all
    # three with a fixed legal notice: no \m \r \s \v escapes, no OS name —
    # and the warning itself is what makes monitoring legally defensible.
    local f
    for f in /etc/issue /etc/issue.net /etc/motd; do
        if [ "$(cat "$f" 2>/dev/null)" = "$banner" ]; then
            ok "$f already carries the banner"
        else
            printf '%s\n' "$banner" > "$f"
            chown root:root "$f"
            chmod 644 "$f"
            ok "Banner written to $f"
        fi
    done
    # sshd shows /etc/issue.net BEFORE authentication. Own drop-in (not the
    # step-2 one, so --no-ssh and --no-banners stay independent), validated
    # with sshd -t before reloading — a bad config must never go live.
    if ! command -v sshd >/dev/null 2>&1; then
        warn "sshd not installed — banner files written, ssh Banner skipped"
        return 0
    fi
    if [ -f "$sshd_banner_dropin" ] && grep -qxF "Banner /etc/issue.net" "$sshd_banner_dropin"; then
        ok "sshd already presents the banner before login"
    else
        printf 'Banner /etc/issue.net\n' > "$sshd_banner_dropin"
        chmod 644 "$sshd_banner_dropin"
        if sshd -t 2>/dev/null; then
            systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
            ok "sshd now presents the banner before authentication"
        else
            rm -f "$sshd_banner_dropin"
            err "sshd config validation failed after adding the banner — reverted"
            return 1
        fi
    fi
}

setup_sudo_hardening() {
    [ "$DO_SUDO_HARDENING" -eq 1 ] || { log "Skipping sudo hardening"; return 0; }
    log "Hardening sudo (use_pty + dedicated log, CIS 5.3)"
    local dropin="/etc/sudoers.d/99-hardening-sudo"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would write %s: Defaults use_pty + Defaults logfile=/var/log/sudo.log\n' "$c_yellow" "$c_reset" "$dropin"
        return 0
    fi
    # use_pty (CIS 5.3.2): every sudo command gets its own pseudo-terminal,
    # so a malicious command can't inject keystrokes into the calling
    # session's tty once sudo exits. logfile (CIS 5.3.3): sudo activity in
    # one dedicated file instead of scattered through auth.log — the first
    # thing a forensics pass wants. Validated with visudo before it goes
    # live, same as the admin-user rule: a bad drop-in can never break sudo.
    local content
    content=$(printf 'Defaults use_pty\nDefaults logfile="/var/log/sudo.log"\n')
    if [ -f "$dropin" ] && [ "$(cat "$dropin")" = "$content" ]; then
        ok "sudo hardening drop-in already in place"
        return 0
    fi
    local tmp
    tmp=$(mktemp)
    printf '%s\n' "$content" > "$tmp"
    if visudo -cf "$tmp" >/dev/null 2>&1; then
        install -m 440 -o root -g root "$tmp" "$dropin"
        rm -f "$tmp"
        ok "sudo now runs commands in their own pty and logs to /var/log/sudo.log"
    else
        rm -f "$tmp"
        err "Generated sudoers drop-in failed visudo validation — not installing"
        return 1
    fi
}

setup_ssh_policies() {
    [ "$DO_SSH_POLICIES" -eq 1 ] || { log "Skipping SSH session policies"; return 0; }
    log "Applying SSH session policies (CIS 5.2)"
    local dropin="/etc/ssh/sshd_config.d/97-hardening-policies.conf"
    # Step 2 hardens WHO gets in (auth); this one limits WHAT a session may
    # do once inside. Own drop-in so --no-ssh and --no-ssh-policies stay
    # independent — same convention as the banner drop-in. No keyword here
    # repeats another drop-in's: in sshd the FIRST occurrence wins, so a
    # duplicate would silently fight over precedence by filename.
    local content
    content=$(cat <<'EOF'
# Managed by debian-hardening (harden.sh). Edit flags, not this file.
# Session/channel policies: what an authenticated session may do.
#
# LogLevel VERBOSE records the fingerprint of the key that logged in —
# without it, "who exactly connected" is guesswork in a shared-key world.
LogLevel VERBOSE
# An SSH account whose shell you locked down is still a SOCKS proxy /
# pivot into the network unless forwarding is off.
AllowTcpForwarding no
AllowAgentForwarding no
# Caps against multiplexed-session abuse and connection-slot exhaustion.
MaxSessions 4
MaxStartups 10:30:60
# No user-controlled environment (LD_PRELOAD-style tricks), no legacy
# rhosts trust, and empty passwords are never a valid credential.
PermitUserEnvironment no
HostbasedAuthentication no
IgnoreRhosts yes
PermitEmptyPasswords no
EOF
)
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would write %s:\n' "$c_yellow" "$c_reset" "$dropin"
        printf '%s\n' "$content" | sed 's/^/        /'
        return 0
    fi
    if ! command -v sshd >/dev/null 2>&1; then
        warn "sshd not installed — SSH session policies skipped"
        return 0
    fi
    if [ -f "$dropin" ] && [ "$(cat "$dropin")" = "$content" ]; then
        ok "SSH session policies already in place"
        return 0
    fi
    install -d -m 755 /etc/ssh/sshd_config.d
    printf '%s\n' "$content" > "$dropin"
    chmod 644 "$dropin"
    # Same contract as every sshd change in this script: validate before it
    # goes live, revert if sshd rejects it — a bad config must never ship.
    if sshd -t 2>/dev/null; then
        systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
        ok "SSH sessions can no longer forward, and logins log key fingerprints"
    else
        rm -f "$dropin"
        err "sshd config validation failed after adding session policies — reverted"
        return 1
    fi
}

setup_coredump_limits() {
    [ "$DO_COREDUMP_LIMITS" -eq 1 ] || { log "Skipping core dump limits"; return 0; }
    log "Disabling core dumps (CIS 1.5)"
    # A core dump is the crashed process's memory written to disk: keys,
    # passwords, session tokens — everything it held at the moment it died.
    # Three doors, three locks: the ulimit door closes here (hard = the
    # session can't raise it back; '*' never matches root, so root gets its
    # own line), the systemd-coredump door gets Storage=none in case that
    # collector is ever installed (it bypasses ulimit entirely), and the
    # setuid door (fs.suid_dumpable=0) is already locked by the sysctl step.
    local dropin="/etc/security/limits.d/99-hardening-coredumps.conf"
    local cdropin="/etc/systemd/coredump.conf.d/99-hardening.conf"
    local content ccontent
    content=$(cat <<'EOF'
# Managed by debian-hardening (harden.sh). Edit flags, not this file.
*    hard    core    0
root hard    core    0
EOF
)
    ccontent=$(cat <<'EOF'
# Managed by debian-hardening (harden.sh). Edit flags, not this file.
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
)
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would write %s (hard core 0, root included)\n' "$c_yellow" "$c_reset" "$dropin"
        printf '    %s(dry-run)%s would write %s (Storage=none, ProcessSizeMax=0)\n' "$c_yellow" "$c_reset" "$cdropin"
        return 0
    fi
    if [ -f "$dropin" ] && [ "$(cat "$dropin")" = "$content" ] &&
       [ -f "$cdropin" ] && [ "$(cat "$cdropin")" = "$ccontent" ]; then
        ok "core dump limits already in place"
        return 0
    fi
    install -d -m 755 /etc/security/limits.d /etc/systemd/coredump.conf.d
    printf '%s\n' "$content" > "$dropin"
    chmod 644 "$dropin"
    printf '%s\n' "$ccontent" > "$cdropin"
    chmod 644 "$cdropin"
    ok "core dumps disabled: hard limit 0 for every session, systemd-coredump storage off"
}

setup_umask_tmout() {
    [ "$DO_UMASK_TMOUT" -eq 1 ] || { log "Skipping umask & shell timeout"; return 0; }
    log "Setting default umask 027 and shell timeout (CIS 5.4)"
    # umask 022 (the stock default) makes every new file world-readable —
    # logs, dumps, home directories. 027 keeps group read but shuts the
    # world out. Two doors: login.defs (pam_umask applies it to every PAM
    # session where enabled) and a profile.d drop-in (login shells source
    # it even where pam_umask is absent). TMOUT closes the third classic
    # gap: the unlocked terminal someone walked away from — readonly so
    # the session can't simply unset it.
    local umask_dropin="/etc/profile.d/99-hardening-umask.sh"
    local tmout_dropin="/etc/profile.d/99-hardening-tmout.sh"
    local umask_content tmout_content
    umask_content=$(cat <<'EOF'
# Managed by debian-hardening (harden.sh). Edit flags, not this file.
umask 027
EOF
)
    tmout_content=$(cat <<'EOF'
# Managed by debian-hardening (harden.sh). Edit flags, not this file.
# Idle interactive shells log out after 15 minutes. readonly so the
# session cannot unset or raise it.
readonly TMOUT=900
export TMOUT
EOF
)
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would set UMASK 027 in /etc/login.defs\n' "$c_yellow" "$c_reset"
        printf '    %s(dry-run)%s would write %s (umask 027) and %s (readonly TMOUT=900)\n' "$c_yellow" "$c_reset" "$umask_dropin" "$tmout_dropin"
        return 0
    fi
    # login.defs ships an UMASK line — replace it in place; append if a
    # future image drops it. Same pattern as the account-policies step.
    if grep -qE '^UMASK[[:space:]]' /etc/login.defs; then
        sed -i 's/^UMASK[[:space:]].*/UMASK\t\t027/' /etc/login.defs
    else
        printf 'UMASK\t\t027\n' >> /etc/login.defs
    fi
    if [ -f "$umask_dropin" ] && [ "$(cat "$umask_dropin")" = "$umask_content" ] &&
       [ -f "$tmout_dropin" ] && [ "$(cat "$tmout_dropin")" = "$tmout_content" ]; then
        ok "umask & shell timeout already in place"
        return 0
    fi
    printf '%s\n' "$umask_content" > "$umask_dropin"
    printf '%s\n' "$tmout_content" > "$tmout_dropin"
    chmod 644 "$umask_dropin" "$tmout_dropin"
    ok "new files default to umask 027; idle shells close after 15 minutes (readonly TMOUT)"
}

setup_cron_restrictions() {
    [ "$DO_CRON_RESTRICTIONS" -eq 1 ] || { log "Skipping cron restrictions"; return 0; }
    log "Restricting cron/at to root (CIS 5.1)"
    # Scheduled jobs are persistence 101: a foothold that re-runs itself
    # survives reboots and cleanups. Two moves. First, tighten the spool —
    # /etc/crontab and the cron.* drop-in dirs are world-readable by
    # default, leaking commands, paths and timings to any local user.
    # Second, switch crontab/at from Debian's deny-list model (everyone
    # may schedule unless listed in cron.deny) to an allow-list with just
    # root. Existing user crontabs keep RUNNING — the allow-list gates
    # the crontab(1) command, not the daemon — so nothing already
    # deployed breaks; unprivileged users just can't schedule anew.
    if [ ! -f /etc/crontab ]; then
        warn "cron does not seem to be installed — skipping cron restrictions"
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would chmod 600 /etc/crontab and 700 the cron.* directories\n' "$c_yellow" "$c_reset"
        printf '    %s(dry-run)%s would write a root-only /etc/cron.allow and remove /etc/cron.deny (same for at, if present)\n' "$c_yellow" "$c_reset"
        return 0
    fi
    local changed=0 d
    if [ "$(stat -c '%a %U %G' /etc/crontab)" != "600 root root" ]; then
        chown root:root /etc/crontab; chmod 600 /etc/crontab; changed=1
    fi
    for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
        [ -d "$d" ] || continue
        if [ "$(stat -c '%a %U %G' "$d")" != "700 root root" ]; then
            chown root:root "$d"; chmod 700 "$d"; changed=1
        fi
    done
    if [ ! -f /etc/cron.allow ]; then
        printf 'root\n' > /etc/cron.allow; changed=1
    elif ! grep -qx 'root' /etc/cron.allow; then
        # An admin-curated allow-list is respected — just make sure root is on it.
        printf 'root\n' >> /etc/cron.allow; changed=1
    fi
    if [ "$(stat -c '%a %U %G' /etc/cron.allow)" != "640 root root" ]; then
        chown root:root /etc/cron.allow; chmod 640 /etc/cron.allow; changed=1
    fi
    if [ -e /etc/cron.deny ]; then rm -f /etc/cron.deny; changed=1; fi
    # at ships separately; give it the same allow-list only if it's around.
    if command -v at >/dev/null 2>&1 || [ -e /etc/at.deny ]; then
        if [ ! -f /etc/at.allow ]; then printf 'root\n' > /etc/at.allow; changed=1; fi
        if [ "$(stat -c '%a %U %G' /etc/at.allow)" != "640 root root" ]; then
            chown root:root /etc/at.allow; chmod 640 /etc/at.allow; changed=1
        fi
        if [ -e /etc/at.deny ]; then rm -f /etc/at.deny; changed=1; fi
    fi
    if [ "$changed" -eq 0 ]; then
        ok "cron/at restrictions already in place"
    else
        ok "cron locked down: root-only spool, allow-list active (existing crontabs unaffected)"
    fi
}

setup_password_policy() {
    [ "$DO_PASSWORD_POLICY" -eq 1 ] || { log "Skipping password policy"; return 0; }
    log "Enforcing password quality and hashing policy (CIS 5.3/5.4)"
    # The aging step (7) decides WHEN a password must change; this one
    # decides WHAT a password may be and HOW it is stored. Quality first:
    # libpam-pwquality gates every PAM password change — 14 characters,
    # all four classes, no long repeats, dictionary words rejected — and
    # enforce_for_root closes the classic hole where root "fixing" a user
    # account types 'temp123' straight past the policy. Hashing second:
    # Debian already defaults to yescrypt through PAM, but chpasswd and
    # newusers read ENCRYPT_METHOD from login.defs — pin it so no path
    # quietly falls back to a weaker crypt.
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would install libpam-pwquality and set minlen=14, minclass=4, maxrepeat=3, retry=3, enforce_for_root in /etc/security/pwquality.conf\n' "$c_yellow" "$c_reset"
        printf '    %s(dry-run)%s would pin ENCRYPT_METHOD YESCRYPT in /etc/login.defs\n' "$c_yellow" "$c_reset"
        return 0
    fi
    # cracklib-runtime is explicit on purpose: it is only a Recommends of
    # libpwquality1, so a no-recommends install leaves the dictionary
    # missing — and pwquality then fails CLOSED, rejecting every password
    # ("error loading dictionary"). The e2e suite caught exactly that.
    if ! dpkg -s libpam-pwquality >/dev/null 2>&1 || ! dpkg -s cracklib-runtime >/dev/null 2>&1; then
        run apt-get install -y libpam-pwquality cracklib-runtime
    fi
    # pwquality.conf ships fully commented — uncomment-or-append each
    # setting, same reconcile pattern as login.defs elsewhere.
    local conf="/etc/security/pwquality.conf" key val
    for kv in "minlen 14" "minclass 4" "maxrepeat 3" "retry 3"; do
        key="${kv% *}"; val="${kv#* }"
        if grep -qE "^${key}[[:space:]]*=" "$conf"; then
            sed -i "s/^${key}[[:space:]]*=.*/${key} = ${val}/" "$conf"
        else
            printf '%s = %s\n' "$key" "$val" >> "$conf"
        fi
    done
    # enforce_for_root is a bare flag, not key = value.
    grep -qE '^enforce_for_root([[:space:]]|$)' "$conf" || printf 'enforce_for_root\n' >> "$conf"
    if grep -qE '^ENCRYPT_METHOD[[:space:]]' /etc/login.defs; then
        sed -i 's/^ENCRYPT_METHOD[[:space:]].*/ENCRYPT_METHOD\tYESCRYPT/' /etc/login.defs
    else
        printf 'ENCRYPT_METHOD\tYESCRYPT\n' >> /etc/login.defs
    fi
    ok "passwords need 14 chars / 4 classes (root included); hashing pinned to yescrypt"
}

# Own config + DB path rather than reusing Debian's aide-common machinery:
# the default aide.conf watches most of the filesystem, whose baseline is
# huge and slow to build. This scopes the fingerprint to what actually
# matters after a compromise — the system binaries and /etc — so the check
# is fast enough to run daily and the config is deterministic (idempotent).
AIDE_CONF="/etc/aide/hardening.conf"
AIDE_DB="/var/lib/aide/hardening.db"

setup_aide() {
    [ "$DO_AIDE" -eq 1 ] || { log "Skipping AIDE file integrity"; return 0; }
    log "Setting up AIDE file-integrity monitoring (CIS 1.4)"
    # A file-integrity baseline answers the question every other step leaves
    # open: "did someone change something after I hardened it?" AIDE hashes
    # the watched paths now; a daily check re-hashes and reports anything
    # added, removed or modified — a backdoored `sudo`, an edited
    # /etc/passwd, a new SUID binary. The baseline lives in /var/lib/aide;
    # on a real box you'd copy it somewhere the attacker can't reach so they
    # can't just regenerate it, which the README notes.
    local conf_content
    conf_content=$(cat <<EOF
# Managed by debian-hardening (harden.sh). Edit flags, not this file.
database_in=file:$AIDE_DB
database_out=file:$AIDE_DB.new
gzip_dbout=no
report_url=stdout

# Rule: permissions, inode, ownership, size, mtime/ctime and strong hashes.
Strong = p+i+n+u+g+s+m+c+sha256+sha512

# What matters after a compromise: the system binaries and the config tree.
/etc     Strong
/bin     Strong
/sbin    Strong
/usr/bin Strong
/usr/sbin Strong
/boot    Strong

# Churn that is not tampering — exclude so the daily report stays signal.
!/etc/mtab$
!/etc/aide/hardening.conf$
!/etc/.*\.cache$
EOF
)
    local svc_content timer_content
    svc_content=$(cat <<EOF
[Unit]
Description=AIDE file-integrity check (debian-hardening)

[Service]
Type=oneshot
ExecStart=/usr/bin/aide --config=$AIDE_CONF --check
EOF
)
    timer_content=$(cat <<'EOF'
[Unit]
Description=Daily AIDE file-integrity check (debian-hardening)

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
EOF
)
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would install aide, write %s, build the baseline DB and enable aide-check.timer\n' "$c_yellow" "$c_reset" "$AIDE_CONF"
        return 0
    fi
    command -v aide >/dev/null 2>&1 || run apt-get install -y aide
    install -d -m 755 /etc/aide /var/lib/aide
    local rebuild=0
    if [ ! -f "$AIDE_CONF" ] || [ "$(cat "$AIDE_CONF")" != "$conf_content" ]; then
        printf '%s\n' "$conf_content" > "$AIDE_CONF"
        chmod 644 "$AIDE_CONF"
        rebuild=1
    fi
    # Build the baseline only when missing or the ruleset changed — rebuilding
    # on every run would be slow and would paper over real drift.
    if [ "$rebuild" -eq 1 ] || [ ! -f "$AIDE_DB" ]; then
        log "Building the AIDE baseline (first run can take a minute)"
        aide --config="$AIDE_CONF" --init
        mv -f "$AIDE_DB.new" "$AIDE_DB"
        ok "AIDE baseline built at $AIDE_DB"
    else
        ok "AIDE baseline already present"
    fi
    printf '%s\n' "$svc_content" > /etc/systemd/system/aide-check.service
    printf '%s\n' "$timer_content" > /etc/systemd/system/aide-check.timer
    chmod 644 /etc/systemd/system/aide-check.service /etc/systemd/system/aide-check.timer
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable aide-check.timer >/dev/null 2>&1 || warn "could not enable aide-check.timer (no systemd?)"
    ok "file integrity watched: /etc + system binaries, checked daily by aide-check.timer"
}

RKHUNTER_DB="/var/lib/rkhunter/db/rkhunter.dat"

setup_rkhunter() {
    [ "$DO_RKHUNTER" -eq 1 ] || { log "Skipping rkhunter"; return 0; }
    log "Setting up rkhunter rootkit detection"
    # AIDE (step 16) answers "did any watched file change?"; rkhunter answers
    # "does this box show signs of a known rootkit, backdoor or local
    # exploit?" — signature and heuristic checks AIDE doesn't do. Two layers,
    # different questions. The property baseline (--propupd) records the
    # current binaries so the daily --check can flag ones that change
    # underneath it; a systemd timer runs the check, mirroring AIDE.
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would install rkhunter, take a property baseline and enable rkhunter-check.timer\n' "$c_yellow" "$c_reset"
        return 0
    fi
    # --no-install-recommends: rkhunter recommends a mail-transport-agent
    # (exim4/postfix) to email reports — we don't want an MTA on a hardened
    # box just for this. noninteractive so the MTA debconf prompt never blocks.
    if ! command -v rkhunter >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive run apt-get install -y --no-install-recommends rkhunter
    fi
    # Use our own systemd timer, not Debian's /etc/cron.daily/rkhunter, so
    # the check runs once (not twice) and matches the AIDE step's shape.
    # Also stop the cron job from auto-updating signatures over the network.
    if [ -f /etc/default/rkhunter ]; then
        sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="false"/' /etc/default/rkhunter
        sed -i 's/^CRON_DB_UPDATE=.*/CRON_DB_UPDATE="false"/' /etc/default/rkhunter
        grep -q '^CRON_DAILY_RUN=' /etc/default/rkhunter || printf 'CRON_DAILY_RUN="false"\n' >> /etc/default/rkhunter
        grep -q '^CRON_DB_UPDATE=' /etc/default/rkhunter || printf 'CRON_DB_UPDATE="false"\n' >> /etc/default/rkhunter
    fi
    # Property baseline: take it once (or if the package refreshed and left no
    # db). Re-running --propupd on every pass would "bless" tampering that
    # happened since — the opposite of the point — so only build when missing.
    if [ ! -f "$RKHUNTER_DB" ]; then
        log "Taking the rkhunter property baseline (first run)"
        rkhunter --propupd --nocolors >/dev/null 2>&1 || warn "rkhunter --propupd reported issues"
        ok "rkhunter property baseline recorded at $RKHUNTER_DB"
    else
        ok "rkhunter property baseline already present"
    fi
    local svc_content timer_content
    svc_content=$(cat <<'EOF'
[Unit]
Description=rkhunter rootkit check (debian-hardening)

[Service]
Type=oneshot
ExecStart=/usr/bin/rkhunter --check --skip-keypress --report-warnings-only --nocolors
EOF
)
    timer_content=$(cat <<'EOF'
[Unit]
Description=Daily rkhunter rootkit check (debian-hardening)

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
EOF
)
    printf '%s\n' "$svc_content" > /etc/systemd/system/rkhunter-check.service
    printf '%s\n' "$timer_content" > /etc/systemd/system/rkhunter-check.timer
    chmod 644 /etc/systemd/system/rkhunter-check.service /etc/systemd/system/rkhunter-check.timer
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable rkhunter-check.timer >/dev/null 2>&1 || warn "could not enable rkhunter-check.timer (no systemd?)"
    ok "rootkit detection active: property baseline taken, checked daily by rkhunter-check.timer"
}

MODPROBE_BLACKLIST_CONF="/etc/modprobe.d/99-hardening-blacklist.conf"
# CIS 1.1.1 (filesystems nobody mounts on a server) + CIS 3.4 (network
# protocols nobody speaks): each one is kernel code reachable from userspace
# — a mount(2) or socket(2) away — and several have carried privilege-
# escalation CVEs. usb-storage is deliberately NOT here (CIS lists it as
# site-dependent, and it bites the restore-from-USB path on real boxes);
# squashfs/overlayfs stay untouched too (snaps and container runtimes).
MODULE_BLACKLIST=(cramfs freevxfs jffs2 hfs hfsplus udf dccp sctp rds tipc)

setup_module_blacklist() {
    [ "$DO_MODULE_BLACKLIST" -eq 1 ] || { log "Skipping kernel module blacklist"; return 0; }
    log "Blacklisting rarely-used kernel modules"
    # Two directives per module, closing two different doors: `install m
    # /bin/false` defeats an EXPLICIT `modprobe m` (modprobe runs /bin/false
    # instead of loading anything), and `blacklist m` stops the ALIAS
    # auto-load path (the kernel pulling the module in behind a mount(2) or
    # socket(2) call). One without the other leaves a door open.
    local conf_content m
    conf_content="# debian-hardening: keep rarely-used kernel modules unloadable (CIS 1.1.1 / 3.4)"
    for m in "${MODULE_BLACKLIST[@]}"; do
        conf_content+=$'\n'"install $m /bin/false"$'\n'"blacklist $m"
    done
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would write %s covering: %s\n' "$c_yellow" "$c_reset" "$MODPROBE_BLACKLIST_CONF" "${MODULE_BLACKLIST[*]}"
        return 0
    fi
    # modprobe reads modprobe.d, so the config is useless without kmod — any
    # real server has it, but a minimal container/chroot may not.
    command -v modprobe >/dev/null 2>&1 || run apt-get install -y kmod
    if [ ! -f "$MODPROBE_BLACKLIST_CONF" ] || [ "$(cat "$MODPROBE_BLACKLIST_CONF")" != "$conf_content" ]; then
        printf '%s\n' "$conf_content" > "$MODPROBE_BLACKLIST_CONF"
        chmod 644 "$MODPROBE_BLACKLIST_CONF"
    fi
    # Best-effort unload of anything already resident: the config only stops
    # FUTURE loads. Quietly skipped where it can't work (containers, module
    # not loaded) — on a real box a reboot settles it either way.
    for m in "${MODULE_BLACKLIST[@]}"; do
        if lsmod 2>/dev/null | grep -q "^$m "; then
            if modprobe -r "$m" 2>/dev/null; then
                ok "unloaded resident module $m"
            else
                warn "module $m is loaded and could not be unloaded — reboot to settle"
            fi
        fi
    done
    ok "module blacklist active: ${#MODULE_BLACKLIST[@]} modules defeated in $MODPROBE_BLACKLIST_CONF"
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
    [ "$DO_BANNERS" -eq 1 ]          && echo "    - warning banners (issue/issue.net/motd + sshd Banner)"
    [ "$DO_SUDO_HARDENING" -eq 1 ]   && echo "    - sudo hardening (use_pty + /var/log/sudo.log)"
    [ "$DO_SSH_POLICIES" -eq 1 ]     && echo "    - SSH session policies (no forwarding, caps, verbose log)"
    [ "$DO_COREDUMP_LIMITS" -eq 1 ]  && echo "    - core dump limits (hard core 0 + systemd-coredump off)"
    [ "$DO_UMASK_TMOUT" -eq 1 ]      && echo "    - default umask 027 + shell timeout (readonly TMOUT=900)"
    [ "$DO_CRON_RESTRICTIONS" -eq 1 ] && echo "    - cron restrictions (root-only spool + cron.allow/at.allow)"
    [ "$DO_PASSWORD_POLICY" -eq 1 ]  && echo "    - password policy (pwquality 14/4 classes + yescrypt pin)"
    [ "$DO_AIDE" -eq 1 ]             && echo "    - AIDE file integrity (baseline of /etc + binaries, daily timer)"
    [ "$DO_RKHUNTER" -eq 1 ]         && echo "    - rkhunter rootkit detection (property baseline, daily timer)"
    [ "$DO_MODULE_BLACKLIST" -eq 1 ] && echo "    - kernel module blacklist (rare filesystems + network protocols)"
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
    setup_banners
    setup_sudo_hardening
    setup_ssh_policies
    setup_coredump_limits
    setup_umask_tmout
    setup_cron_restrictions
    setup_password_policy
    setup_aide
    setup_rkhunter
    setup_module_blacklist

    ok "Done. Review with: sshd -T | grep -Ei 'passwordauth|permitroot' ; ufw status verbose ; fail2ban-client status sshd"
}

# Only run when executed directly; sourcing (e.g. from the test suite) just
# loads the functions without parsing args or touching the system.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    parse_args "$@"
    main
fi
