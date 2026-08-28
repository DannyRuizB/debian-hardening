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
#  19. Account lockout (CIS 5.3.2): pam_faillock locks an account after 5
#      failed password attempts for 15 minutes — brute force over any PAM
#      path (su, login, password SSH) hits a wall the ban and the quality
#      policy don't provide. Key-only SSH never touches the auth stack, so
#      the admin user this script sets up can't be locked out by it.
#  20. File permissions (CIS 6.1): exact owner/group/mode on the account
#      database (passwd, shadow, group, gshadow and their '-' backups),
#      world-writable bit cleared on files, orphan (unowned/ungrouped)
#      files adopted by root, sticky bit on world-writable directories,
#      and a SUID/SGID inventory logged for review (never auto-removed).
##  21. SSH access control (CIS 5.2): only members of a dedicated
#      `ssh-users` group may log in (sshd AllowGroups). The admin user is
#      added to it first; if there is no admin user the step is SKIPPED,
#      because an AllowGroups nobody satisfies locks everyone out.
##  22. Service sandboxing (systemd): a hardening drop-in for the fail2ban
#      unit — NoNewPrivileges, PrivateTmp, ProtectSystem=full, ProtectHome,
#      ProtectKernelTunables, ProtectControlGroups, RestrictSUIDSGID. If the
#      unit fails to start with it, the drop-in is reverted. A conservative
#      set on purpose: fail2ban still needs the network and to run ufw.
##  23. Journald persistence (CIS 4.2.2): a drop-in makes systemd-journald
#      store logs on disk (Storage=persistent) so they survive a reboot for
#      forensics, compresses them, and caps their size (SystemMaxUse). The
#      volatile default loses every log on restart — useless after an
#      incident that reboots the box.
##  24. Su restriction (CIS 5.7): pam_wheel gates `su` on membership of the
#      `sugroup` group, checked by real uid (use_uid) BEFORE the password is
#      even considered — a stolen root password alone no longer buys a
#      shell. The group is created EMPTY on purpose: admins use sudo, and
#      the group is the explicit, auditable exception list.
#  25. System accounts (CIS 5.4): every service account gets a nologin
#      shell and a locked password, so a daemon identity can never become
#      an interactive login.
#  26. Log file permissions (CIS 4.2.3): everything under /var/log loses
#      group-write and all world access (utmp family excepted by design),
#      and an rsyslog drop-in pins FileCreateMode 0640 so tomorrow's files
#      are born restricted too.
#  27. Logrotate permissions (CIS 4.4): the global `create` is pinned to
#      0640 and loose per-package create modes are tightened, so rotation
#      (the third way a log is born) re-creates logs restricted.
#  28. Audit daemon (CIS 4.1): auditd installed with a staged ruleset —
#      identity files, sudoers, sshd config, time changes and kernel module
#      syscalls all leave a kernel-level trail keyed for ausearch. Config is
#      the promise (package, rules, enabled at boot); loading into the
#      running kernel is best-effort, because containers have no audit
#      netlink and real servers activate the rules on their next boot.
#  29. Home directory permissions (CIS 6.2): every interactive user's home
#      loses group-write and all world access (750 or tighter), and the
#      legacy credential files that grant passwordless login — .netrc,
#      .rhosts, .forward — are removed. A 755 home is the default on many
#      distros and it hands every local account a reading pass over
#      ~/.ssh, ~/.aws and shell history.
#  30. Process isolation: your neighbour's process is private. /proc is
#      remounted (and pinned in fstab) with hidepid, so an unprivileged user
#      no longer sees other users' processes — no more reading passwords and
#      tokens straight off someone else's command line with `ps aux`. And
#      kernel.yama.ptrace_scope=1 stops one process from attaching to
#      another of the SAME user: without it, anything you run can read the
#      memory of your browser, ssh-agent or gpg-agent.
#  31. Guess cost: every wrong password guess gets expensive, offline and
#      online. yescrypt's cost factor is raised to its maximum in
#      login.defs, so each attempt against a stolen shadow file costs ~1 s
#      of CPU instead of milliseconds — a cracking rig drops from millions
#      of guesses a second to a handful. And pam_faildelay makes every
#      failed LIVE login wait FAIL_DELAY seconds before the next prompt,
#      capping online guessing at ~12 attempts a minute. A correct
#      password pays neither price.
#  32. Root PATH integrity (CIS 6.2.8): every command root types is looked
#      up along PATH in order, so whoever can write to a directory early in
#      that list chooses what root actually runs. Empty entries (`::` — they
#      mean "the current directory"), relative entries and group/world-
#      writable directories are dropped from ENV_SUPATH / ENV_PATH, and the
#      surviving directories lose any group/other write bit. The admin's own
#      additions are kept: only unsafe entries go.
#  33. Apt updater sandboxing (systemd): a hardening drop-in for the
#      apt-daily-upgrade unit — NoNewPrivileges, PrivateTmp, ProtectHome,
#      ProtectControlGroups. Deliberately WITHOUT ProtectSystem or
#      RestrictSUIDSGID: both were measured to break apt (dpkg writes /usr and
#      installs setuid binaries). If systemd rejects the drop-in, it's reverted.
#  34. Password history (CIS 5.3.3): pam_pwhistory keeps the last 24 hashes
#      per account in /etc/security/opasswd and refuses any new password
#      that matches one — a forced change is pointless if the user rotates
#      straight back. Wired via a pam-auth-update profile (priority 512,
#      between pwquality and pam_unix), enforce_for_root included, and
#      opasswd pinned root:root 0600 (it holds hashes).
#  35. SSH crypto policy (CIS 5.2): what the transport may negotiate,
#      pinned in its own drop-in — no hmac-sha1 / umac-64 MACs,
#      encrypt-then-MAC only, and a key-exchange list of the post-quantum
#      hybrids plus curve25519 (the NIST P-curve tail is gone). Validated
#      with sshd -t, reverted if rejected.
#  36. Legacy protocol purge (CIS 2.2/2.3): telnet, rsh, talk, NIS, tftp
#      and the inetd superservers are purged — protocols whose DESIGN is
#      the vulnerability (cleartext credentials, trust by source IP, no
#      authentication at all). dpkg is asked first and only packages it
#      knows get purged: apt-get exits 100 on a name the sources never
#      heard of, and Debian 13 already dropped some of these.
#  37. Filesystem protections (CIS 1.5.x): the fs.protected_* sysctls that
#      defend the TOCTOU/symlink class in world-writable directories — a
#      local user can't make root follow their symlink out of /tmp, open a
#      hardlink to a file they can't read, or plant a FIFO/regular file for
#      a root-run process to clobber. Its own drop-in, and the CI plants all
#      four weak first because modern kernels ship them already on — the
#      step must prove it TIGHTENS, not confirm a default.
#  38. Account database hygiene (CIS 6.2): the logins hiding in the account
#      DATA, invisible to every PAM-stack step. Legacy NIS compat entries
#      ('+'/'-' lines) are removed from passwd/shadow/group — inert today,
#      but the day nsswitch flips to `compat` an unrestricted '+' imports
#      every NIS account, uid 0 included. A password hash sitting in
#      world-readable /etc/passwd still authenticates (measured) AND is an
#      offline cracking target for every local user — pwconv moves it into
#      /etc/shadow with the password intact. And an EMPTY password field in
#      /etc/shadow is a free login: Debian ships pam_unix with `nullok`, so
#      pressing Enter IS the password (measured) — those accounts get
#      locked (reversible with passwd -u once a real password is set).
#      Runs BEFORE the account-policy steps, so aging applies to a freshly
#      migrated hash in the same pass.
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
#   --no-faillock          skip account lockout after failed logins (pam_faillock)
#   --no-file-permissions  skip file permission hardening (CIS 6.1 sweeps)
#   --no-ssh-access        skip limiting SSH login to the ssh-users group
#   --no-service-sandboxing  skip the systemd sandboxing drop-in for fail2ban
#   --no-journald          skip persistent + size-capped journald logging
#   --no-su-restriction    skip restricting su to the sugroup group (pam_wheel)
#   --no-system-accounts   skip locking system accounts (nologin shell + locked password)
#   --no-log-permissions   skip log file permissions (/var/log sweep + rsyslog create mode)
#   --no-logrotate-perms   skip logrotate hardening (rotated logs re-created 0640)
#   --no-auditd            skip the audit daemon (staged ruleset + enabled at boot)
#   --no-home-permissions  skip home directory permissions (750 + legacy dotfiles)
#   --no-process-isolation skip process isolation (/proc hidepid + ptrace_scope)
#   --no-guess-cost        skip the guess-cost step (yescrypt cost factor + fail delay)
#   --no-root-path         skip root PATH integrity (unsafe PATH entries + dir modes)
#   --no-apt-sandboxing    skip the systemd sandboxing drop-in for the apt updater
#   --no-pw-history        skip password history (pam_pwhistory, no reuse of old ones)
#   --no-ssh-crypto        skip the SSH crypto policy (pinned ciphers/MACs/kex)
#   --no-legacy-protocols  skip the legacy protocol purge (telnet/rsh/talk/NIS/tftp/inetd)
#   --no-fs-protected      skip the filesystem-protection sysctls (fs.protected_*)
#   --no-account-hygiene   skip account database hygiene (NIS '+' entries,
#                          unshadowed hashes, empty passwords)
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
DO_FAILLOCK=1
DO_FILE_PERMISSIONS=1
DO_SSH_ACCESS=1
DO_SERVICE_SANDBOXING=1
DO_JOURNALD=1
DO_SU_RESTRICTION=1
DO_SYSTEM_ACCOUNTS=1
DO_LOG_PERMISSIONS=1
DO_LOGROTATE_PERMS=1
DO_AUDITD=1
DO_HOME_PERMISSIONS=1
DO_PROCESS_ISOLATION=1
DO_GUESS_COST=1
DO_ROOT_PATH=1
DO_APT_SANDBOXING=1
DO_PW_HISTORY=1
DO_SSH_CRYPTO=1
DO_LEGACY_PROTOCOLS=1
DO_FS_PROTECTED=1
DO_ACCOUNT_HYGIENE=1
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
# Print the header comment block, from line 2 to the `-h, --help` line that
# ends it. The range used to be hard-coded and went stale twice — every time
# the header grew, the help silently lost its tail — so it ends on a pattern
# now: the last option line is the last option line, whatever number it is.
usage() { sed -n '2,/^#   -h, --help/p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

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
            --no-faillock)     DO_FAILLOCK=0; shift;;
            --no-file-permissions) DO_FILE_PERMISSIONS=0; shift;;
            --no-ssh-access)   DO_SSH_ACCESS=0; shift;;
            --no-service-sandboxing) DO_SERVICE_SANDBOXING=0; shift;;
            --no-journald)     DO_JOURNALD=0; shift;;
            --no-su-restriction) DO_SU_RESTRICTION=0; shift;;
            --no-system-accounts) DO_SYSTEM_ACCOUNTS=0; shift;;
            --no-log-permissions) DO_LOG_PERMISSIONS=0; shift;;
            --no-logrotate-perms) DO_LOGROTATE_PERMS=0; shift;;
            --no-auditd) DO_AUDITD=0; shift;;
            --no-home-permissions) DO_HOME_PERMISSIONS=0; shift;;
            --no-process-isolation) DO_PROCESS_ISOLATION=0; shift;;
            --no-guess-cost) DO_GUESS_COST=0; shift;;
            --no-root-path) DO_ROOT_PATH=0; shift;;
            --no-apt-sandboxing) DO_APT_SANDBOXING=0; shift;;
            --no-pw-history) DO_PW_HISTORY=0; shift;;
            --no-ssh-crypto) DO_SSH_CRYPTO=0; shift;;
            --no-legacy-protocols) DO_LEGACY_PROTOCOLS=0; shift;;
            --no-fs-protected) DO_FS_PROTECTED=0; shift;;
            --no-account-hygiene) DO_ACCOUNT_HYGIENE=0; shift;;
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

FAILLOCK_CONF="/etc/security/faillock.conf"

setup_faillock() {
    [ "$DO_FAILLOCK" -eq 1 ] || { log "Skipping account lockout (faillock)"; return 0; }
    log "Enabling account lockout after failed logins (CIS 5.3.2)"
    # The password-quality step (15) makes each guess expensive; Fail2Ban
    # (step 4) blocks the SSH *source*. This closes the third face: lock the
    # ACCOUNT itself after 5 failed password attempts, so brute force over any
    # PAM path — su, console login, keyboard-interactive SSH — hits a wall,
    # not just network scanners. deny=5, unlock_time=900 (15 min), audit on.
    #
    # Crucially, key-only SSH never touches the PAM *auth* stack, so the admin
    # user this script installs (locked password, key login) can never be
    # locked out by this — the lockout only bites password authentication.
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would set deny=5 unlock_time=900 in %s and enable the pam-auth-update faillock profiles\n' "$c_yellow" "$c_reset" "$FAILLOCK_CONF"
        return 0
    fi
    # faillock.conf is the single source of truth for the tunables (both PAM
    # lines read it), so pam_faillock.so needs no inline arguments — which is
    # also what keeps pam-auth-update's generated common-auth deterministic.
    local conf_content
    conf_content=$(cat <<'EOF'
# Managed by debian-hardening (faillock step). CIS 5.3.2.
deny = 5
unlock_time = 900
audit
EOF
)
    if [ ! -f "$FAILLOCK_CONF" ] || [ "$(cat "$FAILLOCK_CONF")" != "$conf_content" ]; then
        printf '%s\n' "$conf_content" > "$FAILLOCK_CONF"
        chmod 644 "$FAILLOCK_CONF"
    fi
    # Debian wires PAM modules through pam-auth-update profiles, not by hand-
    # editing common-auth (which the tool would clobber). Two profiles: the
    # high-priority `preauth` gate that refuses a locked account before the
    # password prompt, and the low-priority `authfail` tally that records a
    # failure and dies. Priorities put preauth above pam_unix and authfail
    # below it — the ordering pam_faillock requires.
    install -d -m 755 /usr/share/pam-configs
    cat > /usr/share/pam-configs/hardening-faillock <<'EOF'
Name: Account lockout — refuse locked accounts (debian-hardening, preauth)
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
	requisite			pam_faillock.so preauth
Account-Type: Additional
Account:
	required			pam_faillock.so
EOF
    cat > /usr/share/pam-configs/hardening-faillock-authfail <<'EOF'
Name: Account lockout — tally failures and lock (debian-hardening, authfail)
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[default=die]			pam_faillock.so authfail
EOF
    if command -v pam-auth-update >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive pam-auth-update --package \
            --enable hardening-faillock --enable hardening-faillock-authfail \
            || warn "pam-auth-update could not enable the faillock profiles"
        ok "account lockout active: 5 failed logins → 15-minute lock (key-only SSH unaffected)"
    else
        warn "pam-auth-update not found — faillock profiles written but not wired"
    fi
}

setup_file_permissions() {
    [ "$DO_FILE_PERMISSIONS" -eq 1 ] || { log "Skipping file permission hardening"; return 0; }
    log "Hardening critical file permissions (CIS 6.1)"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would pin account-DB modes, clear world-writable bits, adopt orphan files and sticky world-writable dirs\n' "$c_yellow" "$c_reset"
        return 0
    fi
    # 1. The account database (CIS 6.1.2-6.1.8): exact owner/group/mode on
    #    passwd/group (world-readable by design) and shadow/gshadow (hashes —
    #    group `shadow` only). The '-' files are the shadow suite's one-step
    #    backups: same secrets, same modes, and routinely forgotten.
    local f
    for f in /etc/passwd /etc/passwd- /etc/group /etc/group-; do
        [ -e "$f" ] && { chown root:root "$f"; chmod 644 "$f"; }
    done
    for f in /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow-; do
        [ -e "$f" ] && { chown root:shadow "$f"; chmod 640 "$f"; }
    done
    # 2. World-writable files (CIS 6.1.9): any local user can rewrite them —
    #    a config, a script some cron runs as root... -xdev keeps the sweep on
    #    the root filesystem (skips /proc, /sys and other mounts on its own);
    #    /tmp-style scratch is excluded on purpose: transient by design and
    #    already guarded by the sticky bit on the directory.
    local ww_files n
    ww_files=$(find / -xdev \( -path /tmp -o -path /var/tmp \) -prune -o -type f -perm -0002 -print 2>/dev/null || true)
    if [ -n "$ww_files" ]; then
        n=$(printf '%s\n' "$ww_files" | wc -l)
        printf '%s\n' "$ww_files" | while IFS= read -r f; do chmod o-w "$f"; done
        warn "cleared the world-writable bit on $n file(s):"
        printf '%s\n' "$ww_files" | sed 's/^/      /'
    fi
    # 3. Orphan files (CIS 6.1.10/11): a deleted account leaves its files
    #    behind, and the next account created with the recycled UID silently
    #    inherits them. Adopting them as root:root closes that door.
    local orphans
    orphans=$(find / -xdev \( -path /tmp -o -path /var/tmp \) -prune -o \( -nouser -o -nogroup \) -print 2>/dev/null || true)
    if [ -n "$orphans" ]; then
        n=$(printf '%s\n' "$orphans" | wc -l)
        printf '%s\n' "$orphans" | while IFS= read -r f; do chown root:root "$f"; done
        warn "adopted $n unowned/ungrouped file(s) as root:root:"
        printf '%s\n' "$orphans" | sed 's/^/      /'
    fi
    # 4. A world-writable directory without the sticky bit lets any user
    #    delete or replace anyone else's files in it (the bit is why /tmp
    #    works at all). Adding +t is always safe; removing o+w might not be.
    local ww_dirs d
    ww_dirs=$(find / -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null || true)
    if [ -n "$ww_dirs" ]; then
        printf '%s\n' "$ww_dirs" | while IFS= read -r d; do chmod +t "$d"; done
        warn "added the sticky bit to world-writable dir(s): $(printf '%s\n' "$ww_dirs" | wc -l)"
    fi
    # 5. SUID/SGID binaries (CIS 6.1.13/14): site-dependent by definition —
    #    stripping bits here could break sudo/passwd/ping. Surfaced, not touched.
    local suid_count
    suid_count=$(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l || true)
    log "SUID/SGID binaries present: $suid_count (review: find / -xdev -type f -perm -4000 -o -perm -2000)"
    ok "file permissions hardened: account DB pinned, world-writable and orphan sweeps clean"
}

SSH_ACCESS_GROUP="ssh-users"
SSH_ACCESS_DROPIN="/etc/ssh/sshd_config.d/96-hardening-access.conf"

setup_ssh_access_control() {
    [ "$DO_SSH_ACCESS" -eq 1 ] || { log "Skipping SSH access control"; return 0; }
    log "Limiting SSH login to the $SSH_ACCESS_GROUP group (CIS 5.2)"
    # Step 2 hardens HOW you authenticate; this limits WHO may even try:
    # `AllowGroups ssh-users` means sshd rejects anyone not in that group
    # before the auth stack runs — a service account or a stale login can't
    # be brute-forced over SSH if it isn't allowed to reach SSH at all.
    #
    # THE lockout guard: an AllowGroups that no live account satisfies locks
    # EVERYONE out. So the admin user is the anchor — with no --admin-user we
    # have no one we can prove is safe, and the step refuses to run rather
    # than risk bricking remote access.
    if [ -z "$ADMIN_USER" ]; then
        warn "no --admin-user given — skipping SSH access control (an AllowGroups with no allowed user would lock everyone out)"
        return 0
    fi
    if ! command -v sshd >/dev/null 2>&1; then
        warn "sshd not installed — SSH access control skipped"
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would create group %s, add %s to it, and write %s with AllowGroups %s\n' \
            "$c_yellow" "$c_reset" "$SSH_ACCESS_GROUP" "$ADMIN_USER" "$SSH_ACCESS_DROPIN" "$SSH_ACCESS_GROUP"
        return 0
    fi
    # Group first, admin in it, THEN the sshd directive — never the other way
    # round, or there's a window where AllowGroups is live with no member.
    groupadd -f "$SSH_ACCESS_GROUP"
    if ! id -nG "$ADMIN_USER" 2>/dev/null | grep -qw "$SSH_ACCESS_GROUP"; then
        usermod -aG "$SSH_ACCESS_GROUP" "$ADMIN_USER"
    fi
    # Refuse to write the directive unless the admin is provably in the group
    # (usermod could have failed) — the guard that keeps us out of a lockout.
    if ! id -nG "$ADMIN_USER" 2>/dev/null | grep -qw "$SSH_ACCESS_GROUP"; then
        err "could not add $ADMIN_USER to $SSH_ACCESS_GROUP — not writing AllowGroups (would lock everyone out)"
        return 1
    fi
    local content
    content=$(cat <<EOF
# Managed by debian-hardening (harden.sh). Edit flags, not this file.
# Only members of $SSH_ACCESS_GROUP may log in over SSH (CIS 5.2).
AllowGroups $SSH_ACCESS_GROUP
EOF
)
    if [ -f "$SSH_ACCESS_DROPIN" ] && [ "$(cat "$SSH_ACCESS_DROPIN")" = "$content" ]; then
        ok "SSH access already limited to $SSH_ACCESS_GROUP"
        return 0
    fi
    install -d -m 755 /etc/ssh/sshd_config.d
    printf '%s\n' "$content" > "$SSH_ACCESS_DROPIN"
    chmod 644 "$SSH_ACCESS_DROPIN"
    if sshd -t 2>/dev/null; then
        systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
        ok "SSH login limited to $SSH_ACCESS_GROUP ($ADMIN_USER is a member)"
    else
        rm -f "$SSH_ACCESS_DROPIN"
        err "sshd config validation failed after adding AllowGroups — reverted"
        return 1
    fi
}

SANDBOX_UNIT="fail2ban"
SANDBOX_DROPIN_DIR="/etc/systemd/system/fail2ban.service.d"
SANDBOX_DROPIN="$SANDBOX_DROPIN_DIR/99-hardening.conf"

setup_service_sandboxing() {
    [ "$DO_SERVICE_SANDBOXING" -eq 1 ] || { log "Skipping service sandboxing"; return 0; }
    log "Sandboxing the $SANDBOX_UNIT service (systemd)"
    # A network daemon that runs external commands (fail2ban shells out to
    # ufw/iptables) is a juicy foothold if it's ever exploited. systemd can
    # box it in for free: no new privileges, a private /tmp, most of the
    # filesystem read-only, kernel tunables and cgroups protected. The set is
    # deliberately CONSERVATIVE — fail2ban still needs the network and to run
    # ufw, so no PrivateNetwork / ProtectSystem=strict / kernel-module lockout
    # that would break it. If the unit won't start with the drop-in, we revert
    # it: a hardening step must never leave a core service down.
    if ! command -v systemctl >/dev/null 2>&1; then
        warn "systemd not available — service sandboxing skipped"
        return 0
    fi
    if [ "$DO_FAIL2BAN" -ne 1 ]; then
        warn "fail2ban was skipped (--no-fail2ban) — nothing to sandbox"
        return 0
    fi
    local content
    content=$(cat <<'EOF'
# Managed by debian-hardening (service sandboxing step).
# Conservative systemd confinement for fail2ban: hardens the daemon without
# taking away the network or its ability to run ufw. Edit flags, not this file.
[Service]
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
# ProtectSystem=full makes /etc read-only, but the ufw banaction must write
# /etc/ufw/*.rules to install a ban — carve that back out (leading `-` so the
# unit still starts if ufw was skipped and the path doesn't exist).
ReadWritePaths=-/etc/ufw
EOF
)
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would write %s and restart %s\n' "$c_yellow" "$c_reset" "$SANDBOX_DROPIN" "$SANDBOX_UNIT"
        return 0
    fi
    if [ -f "$SANDBOX_DROPIN" ] && [ "$(cat "$SANDBOX_DROPIN")" = "$content" ]; then
        ok "$SANDBOX_UNIT sandboxing already in place"
        return 0
    fi
    install -d -m 755 "$SANDBOX_DROPIN_DIR"
    printf '%s\n' "$content" > "$SANDBOX_DROPIN"
    chmod 644 "$SANDBOX_DROPIN"
    systemctl daemon-reload
    # Restart under the new confinement and confirm it came back — if the
    # sandbox is too tight for this box, roll it back rather than ship a dead
    # intrusion-prevention service.
    if systemctl restart "$SANDBOX_UNIT" 2>/dev/null && systemctl is-active --quiet "$SANDBOX_UNIT"; then
        ok "$SANDBOX_UNIT is sandboxed (NoNewPrivileges, PrivateTmp, ProtectSystem=full, ...)"
    else
        rm -f "$SANDBOX_DROPIN"
        systemctl daemon-reload
        systemctl restart "$SANDBOX_UNIT" 2>/dev/null || true
        err "$SANDBOX_UNIT failed to start with the sandbox drop-in — reverted"
        return 1
    fi
}

JOURNALD_DROPIN_DIR="/etc/systemd/journald.conf.d"
JOURNALD_DROPIN="$JOURNALD_DROPIN_DIR/99-hardening.conf"

setup_journald() {
    [ "$DO_JOURNALD" -eq 1 ] || { log "Skipping journald persistence"; return 0; }
    log "Making journald logs persistent and size-capped (CIS 4.2.2)"
    # By default systemd-journald keeps logs in a tmpfs (/run/log/journal) and
    # loses everything on reboot — so the one event you most want to look at,
    # the compromise that forced a restart, is gone. Storage=persistent moves
    # them to /var/log/journal (survives reboots); Compress keeps that cheap;
    # SystemMaxUse caps the footprint so logs can't fill the disk. A drop-in,
    # not an edit of journald.conf (which a package upgrade would clobber).
    if ! command -v systemctl >/dev/null 2>&1; then
        warn "systemd not available — journald hardening skipped"
        return 0
    fi
    local content
    content=$(cat <<'EOF'
# Managed by debian-hardening (journald step, CIS 4.2.2). Edit flags, not this.
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=200M
EOF
)
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would write %s (Storage=persistent, Compress, SystemMaxUse) and restart systemd-journald\n' "$c_yellow" "$c_reset" "$JOURNALD_DROPIN"
        return 0
    fi
    if [ -f "$JOURNALD_DROPIN" ] && [ "$(cat "$JOURNALD_DROPIN")" = "$content" ]; then
        ok "journald persistence already in place"
        return 0
    fi
    install -d -m 755 "$JOURNALD_DROPIN_DIR"
    printf '%s\n' "$content" > "$JOURNALD_DROPIN"
    chmod 644 "$JOURNALD_DROPIN"
    # /var/log/journal must exist for persistent storage; journald creates it
    # on restart, but making it explicit means the first boot after this is
    # already persistent instead of one-reboot-behind.
    install -d -m 2755 -o root -g systemd-journal /var/log/journal 2>/dev/null || install -d -m 2755 /var/log/journal
    if systemctl restart systemd-journald 2>/dev/null; then
        ok "journald now persistent (/var/log/journal), compressed, capped at 200M"
    else
        warn "wrote the journald drop-in but could not restart systemd-journald"
    fi
}

SU_PAM_FILE="/etc/pam.d/su"
SU_GROUP="sugroup"

setup_su_restriction() {
    [ "$DO_SU_RESTRICTION" -eq 1 ] || { log "Skipping su restriction"; return 0; }
    log "Restricting su to members of the '$SU_GROUP' group (CIS 5.7)"
    # On a host with sudo, nobody should be running su: sudo logs per-command
    # and is revocable per-user, su hands out whole shells against a shared
    # password. pam_wheel makes group membership the gate BEFORE the password
    # is even considered — a stolen root password alone no longer buys a
    # shell. The group is created EMPTY on purpose (CIS suggests exactly
    # that): admins use sudo, and the group is the explicit, auditable
    # exception list. use_uid checks the real uid of the calling process,
    # not getlogin() — which an attacker can spoof via utmp.
    local line="auth       required   pam_wheel.so use_uid group=$SU_GROUP"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would create group %s and gate su on it in %s\n' "$c_yellow" "$c_reset" "$SU_GROUP" "$SU_PAM_FILE"
        return 0
    fi
    if ! getent group "$SU_GROUP" >/dev/null 2>&1; then
        groupadd --system "$SU_GROUP"
    fi
    if grep -Eq "^auth[[:space:]]+required[[:space:]]+pam_wheel\.so[[:space:]]+use_uid[[:space:]]+group=$SU_GROUP" "$SU_PAM_FILE"; then
        ok "su already restricted to $SU_GROUP"
        return 0
    fi
    # Debian ships the hint commented out — activate it in place so the
    # stack keeps its documented order; otherwise insert right after
    # pam_rootok (root itself never walks past that line anyway).
    if grep -Eq '^#[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so[[:space:]]*$' "$SU_PAM_FILE"; then
        sed -i -E "s|^#[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so[[:space:]]*$|$line|" "$SU_PAM_FILE"
    else
        sed -i -E "/^auth[[:space:]]+sufficient[[:space:]]+pam_rootok\.so/a $line" "$SU_PAM_FILE"
    fi
    ok "su now requires membership of '$SU_GROUP' (kept empty: use sudo — add a user only as a deliberate exception)"
}

# Accounts below this UID are the distro's service accounts (Debian's
# SYS_UID_MAX); humans start at 1000 and are never touched by this step.
SYSTEM_UID_MAX=999
NOLOGIN_SHELL="/usr/sbin/nologin"
# Historical exceptions CIS itself carves out: these accounts exist to run
# their namesake command as a login shell and nothing else. `sync` is the
# canonical example — logging in as it flushes buffers and exits.
SYSTEM_ACCOUNT_KEEP=(root sync shutdown halt)

setup_system_accounts() {
    [ "$DO_SYSTEM_ACCOUNTS" -eq 1 ] || { log "Skipping system account lockdown"; return 0; }
    log "Locking system accounts: non-login shell + locked password (CIS 5.4.2 / 6.2.9)"
    # A service account with a real shell is a login waiting to happen: it is
    # a valid `su` target, a valid SSH target while password auth lives, and
    # the landing spot of choice after a service is compromised (the daemon
    # already runs as it). Two independent gates, because either alone leaks:
    # a locked password still lets in anything that skips PAM's auth stage
    # (an SSH key dropped in ~/.ssh, `su -` from root, a cron entry), and a
    # nologin shell still lets a password-only check "succeed" for services
    # that authenticate without spawning a shell. Together the account can
    # own files and run daemons but nobody can BE it interactively.
    #
    # Never touches: root (locking it bricks single-user recovery), the
    # sudo-capable admin user, anything with uid >= 1000 (humans), and the
    # sync/shutdown/halt trio whose whole purpose is a login shell.
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would set %s on system accounts (uid <= %s) with a real shell and lock their passwords\n' \
            "$c_yellow" "$c_reset" "$NOLOGIN_SHELL" "$SYSTEM_UID_MAX"
        return 0
    fi
    local shelled=() locked=() name uid shell keep skip
    while IFS=: read -r name _ uid _ _ _ shell; do
        [ "$uid" -le "$SYSTEM_UID_MAX" ] 2>/dev/null || continue
        [ -n "$ADMIN_USER" ] && [ "$name" = "$ADMIN_USER" ] && continue
        skip=0
        for keep in "${SYSTEM_ACCOUNT_KEEP[@]}"; do
            [ "$name" = "$keep" ] && { skip=1; break; }
        done
        [ "$skip" -eq 1 ] && continue
        # Shell: anything that isn't nologin/false can start a session.
        case "$shell" in
            */nologin|*/false|"") ;;
            *) usermod -s "$NOLOGIN_SHELL" "$name" && shelled+=("$name:$shell");;
        esac
        # Password: 'L' is locked, 'NP' is no password at all (worse). Both
        # get `passwd -l`, which prefixes the hash with '!' — reversible with
        # `passwd -u` if an account ever legitimately needs to log in.
        case "$(passwd -S "$name" 2>/dev/null | awk '{print $2}')" in
            L) ;;
            *) passwd -l "$name" >/dev/null 2>&1 && locked+=("$name");;
        esac
    done < /etc/passwd
    if [ "${#shelled[@]}" -gt 0 ]; then
        warn "replaced the login shell of ${#shelled[@]} system account(s) with $NOLOGIN_SHELL:"
        printf '      %s\n' "${shelled[@]}"
    else
        ok "no system account had a login shell"
    fi
    if [ "${#locked[@]}" -gt 0 ]; then
        warn "locked the password of ${#locked[@]} system account(s): ${locked[*]}"
    else
        ok "every system account password was already locked"
    fi
    ok "System accounts can own files and run daemons, but nobody can log in as them"
}

# ---- Step 26: log file permissions (CIS 4.2.3) ----------------------------
RSYSLOG_DROPIN=/etc/rsyslog.d/99-hardening.conf

setup_log_permissions() {
    [ "$DO_LOG_PERMISSIONS" -eq 1 ] || { log "Skipping log file permissions"; return 0; }
    log "Restricting log file permissions (CIS 4.2.3)"
    # Logs are the forensic record AND a reconnaissance goldmine: auth.log
    # says who logs in from where and which attempts fail, dpkg.log lists
    # the exact package versions to shop CVEs for (and ships 644 on stock
    # Debian). The file-permissions step already guards log INTEGRITY (its
    # world-writable sweep is filesystem-wide); this step adds
    # CONFIDENTIALITY: nothing under /var/log stays readable to everyone.
    # The deliberate exceptions are the utmp family, world-readable BY
    # DESIGN so `who`/`last` work for non-root users — wtmp and lastlog
    # keep 664 root:utmp, while btmp gets 660: failed logins famously
    # record usernames typed into the password prompt.
    #
    # Two halves on purpose: fix the files that exist today, then teach
    # rsyslog to create tomorrow's files restricted too — a sweep without
    # the second half rots on the next logrotate cycle.
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would tighten /var/log (g-wx,o-rwx; utmp family pinned) and pin rsyslog FileCreateMode 0640\n' \
            "$c_yellow" "$c_reset"
        return 0
    fi

    # The utmp family first, pinned to their exact intended modes.
    local f
    for f in /var/log/wtmp /var/log/lastlog; do
        [ -f "$f" ] && { chown root:utmp "$f"; chmod 664 "$f"; }
    done
    [ -f /var/log/btmp ] && { chown root:utmp /var/log/btmp; chmod 660 /var/log/btmp; }
    # Rotated siblings (wtmp.1, btmp.1, ...) keep the same split.
    find /var/log -maxdepth 1 -type f \( -name 'wtmp.*' -o -name 'lastlog.*' \) \
        -exec chown root:utmp {} + -exec chmod 664 {} + 2>/dev/null || true
    find /var/log -maxdepth 1 -type f -name 'btmp.*' \
        -exec chown root:utmp {} + -exec chmod 660 {} + 2>/dev/null || true

    # Everything else: strip group-write/exec and ALL world access. Owner
    # bits and ownership stay (a www-data log keeps belonging to www-data);
    # files already tighter than 640 are left alone. Only files with a bit
    # to lose are touched, so the count below reports real work and the
    # second run finds nothing to do.
    local tightened
    tightened=$(find /var/log -xdev -type f \
        ! -name 'wtmp*' ! -name 'btmp*' ! -name 'lastlog*' \
        -perm /0037 -print -exec chmod g-wx,o-rwx {} + | wc -l)
    if [ "$tightened" -gt 0 ]; then
        warn "tightened $tightened log file(s) that were group-writable or world-accessible"
    else
        ok "no log file was group-writable or world-accessible"
    fi

    # Future logs: rsyslog creates files with FileCreateMode. Debian's stock
    # rsyslog.conf already says 0640 — but that is one drifted edit away
    # from 644-for-everyone, and a drop-in loaded after the main file wins
    # over whatever that line has become (verified against a live daemon).
    # Only written when rsyslog is installed: on journald-only boxes the
    # journald step already owns logging, and journal files are 640 by design.
    if command -v rsyslogd >/dev/null 2>&1; then
        local desired
        desired="# Debian hardening: log files rsyslog creates from now on are born 0640
# (directories 0750). Loaded after rsyslog.conf, so this wins over a
# drifted FileCreateMode there. Existing files are swept by harden.sh.
\$FileCreateMode 0640
\$DirCreateMode 0750"
        if [ ! -f "$RSYSLOG_DROPIN" ] || [ "$(cat "$RSYSLOG_DROPIN")" != "$desired" ]; then
            printf '%s\n' "$desired" > "$RSYSLOG_DROPIN"
            if rsyslogd -N1 >/dev/null 2>&1; then
                systemctl restart rsyslog >/dev/null 2>&1 || warn "could not restart rsyslog (mode applies on next restart)"
                ok "rsyslog now creates log files 0640 (drop-in wins over config drift)"
            else
                rm -f "$RSYSLOG_DROPIN"
                warn "rsyslog rejected the drop-in — reverted, existing config untouched"
            fi
        else
            ok "rsyslog FileCreateMode drop-in already in place"
        fi
    else
        ok "rsyslog not installed — journald owns logging (hardened by the journald step)"
    fi
    ok "Logs stay readable to their service and root — not to every local user"
}

# ---- Step 27: logrotate permissions (CIS 4.4) -----------------------------

# Rewrites every `create MODE [owner group]` line in FILE whose mode grants
# group-write/exec or any world access (the same g-wx,o-rwx threshold as the
# /var/log sweep); owner and group arguments are never touched. Prints how
# many distinct modes it tightened.
tighten_create_modes() {
    local file=$1 mode dec new count=0
    while IFS= read -r mode; do
        [ -n "$mode" ] || continue
        dec=$((8#$mode))
        [ $((dec & 8#0037)) -ne 0 ] || continue
        new=$(printf '%04o' $((dec & ~8#0037)))
        sed -i -E "s/^([[:space:]]*create[[:space:]]+)${mode}\b/\1${new}/" "$file"
        count=$((count + 1))
    done < <(grep -E '^[[:space:]]*create[[:space:]]+[0-7]{3,4}\b' "$file" 2>/dev/null \
             | awk '{print $2}' | sort -u)
    echo "$count"
}

setup_logrotate_perms() {
    [ "$DO_LOGROTATE_PERMS" -eq 1 ] || { log "Skipping logrotate permissions"; return 0; }
    log "Making logrotate re-create logs restricted (CIS 4.4)"
    # Rotation is the THIRD way a log file is born (after the service and
    # rsyslog, both handled by the log-permissions step): logrotate's
    # `create` directive decides the mode of every file it re-creates, and
    # stock Debian ships offenders — dpkg and alternatives say `create 644
    # root root`, so the dpkg.log the sweep just tightened comes back
    # world-readable on the next monthly cycle. Two moves, same shape as
    # the sweep: pin the GLOBAL create in logrotate.conf (stock is a bare
    # `create`, which CLONES the rotated file's mode — drift-preserving),
    # then tighten any per-package snippet whose own create grants
    # group-write or world access. Mode only, on purpose: owner/group
    # arguments stay, so a service's log keeps belonging to the service.
    # The wtmp/btmp snippets keep their designed utmp split (664/660
    # root:utmp) — the same exception the sweep makes.
    if ! command -v logrotate >/dev/null 2>&1; then
        ok "logrotate not installed — nothing re-creates rotated logs"
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would pin the global create to 0640 and strip g-wx,o-rwx from logrotate.d create modes (wtmp/btmp pinned)\n' \
            "$c_yellow" "$c_reset"
        return 0
    fi

    # Snapshot, edit, validate with logrotate's own parser, restore on
    # rejection — the same honesty as the rsyslog drop-in.
    local stash
    stash=$(mktemp -d)
    cp -a /etc/logrotate.conf "$stash/logrotate.conf"
    cp -a /etc/logrotate.d "$stash/logrotate.d"

    local global_changed=0 snips=0 snip n
    if grep -Eq '^[[:space:]]*create[[:space:]]*$' /etc/logrotate.conf; then
        sed -i -E 's/^([[:space:]]*)create[[:space:]]*$/\1create 0640/' /etc/logrotate.conf
        global_changed=1
    elif grep -Eq '^[[:space:]]*create[[:space:]]+[0-7]{3,4}\b' /etc/logrotate.conf; then
        n=$(tighten_create_modes /etc/logrotate.conf)
        [ "$n" -gt 0 ] && global_changed=1
    else
        # No global create at all: add one ABOVE the include, so every
        # snippet defined after it inherits the default (a global at the
        # end of the file would apply to nothing).
        sed -i -E '0,/^[[:space:]]*include\b/s//create 0640\n&/' /etc/logrotate.conf
        grep -Eq '^create 0640$' /etc/logrotate.conf || printf 'create 0640\n' >> /etc/logrotate.conf
        global_changed=1
    fi

    for snip in /etc/logrotate.d/*; do
        [ -f "$snip" ] || continue
        case "$(basename "$snip")" in wtmp|btmp) continue;; esac
        n=$(tighten_create_modes "$snip")
        [ "$n" -gt 0 ] && snips=$((snips + 1))
    done

    if ! logrotate -d /etc/logrotate.conf >/dev/null 2>&1; then
        cp -a "$stash/logrotate.conf" /etc/logrotate.conf
        rm -rf /etc/logrotate.d
        cp -a "$stash/logrotate.d" /etc/logrotate.d
        rm -rf "$stash"
        warn "logrotate rejected the edited config — restored, nothing changed"
        return 0
    fi
    rm -rf "$stash"

    if [ "$global_changed" -eq 1 ]; then
        warn "global create pinned to 0640 (mode only — owner/group stay per file)"
    else
        ok "global create already restrictive"
    fi
    if [ "$snips" -gt 0 ]; then
        warn "tightened loose create modes in $snips logrotate.d snippet(s)"
    else
        ok "no logrotate.d snippet re-creates logs with loose permissions"
    fi
    ok "Rotation re-creates logs restricted — the sweep no longer rots on rotate"
}

# ---- Step 28: audit daemon (CIS 4.1) ---------------------------------------

AUDIT_RULES="/etc/audit/rules.d/hardening.rules"
AUDITD_CONF="/etc/audit/auditd.conf"

# Pin `key = value` in an auditd.conf-style file: replace the line when the
# key exists (whatever its current value or spacing), append when it doesn't.
# Factored out for the bats probe: pure file edit, no service side effects.
pin_auditd_key() {
    local file=$1 key=$2 value=$3
    if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$file"; then
        sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$file"
    else
        printf '%s = %s\n' "$key" "$value" >> "$file"
    fi
}

setup_auditd() {
    [ "$DO_AUDITD" -eq 1 ] || { log "Skipping auditd"; return 0; }
    log "Installing auditd with a staged ruleset (CIS 4.1)"
    # The logging chapter's last piece: journald (23) keeps logs, the sweep
    # (26) guards them, logrotate (27) re-creates them right — auditd records
    # WHO touched the crown jewels, at the kernel, as it happens. AIDE (16)
    # notices a watched file changed by the next daily check; the audit trail
    # says which process, which uid, which syscall, the moment it happened.
    #
    # The split that keeps this honest: the PROMISE is configuration —
    # package installed, ruleset staged in rules.d, service enabled at boot,
    # history kept. LOADING the rules into the running kernel is best-effort
    # on purpose: the audit netlink is not namespaced, so inside a container
    # (this repo's CI node, WSL) auditctl gets EPERM no matter what — while
    # on any real server the enabled service compiles and loads the staged
    # rules on the next boot. A hard failure here would abort the whole run
    # over an environment limitation, not a hardening problem.
    local rules_content
    rules_content=$(cat <<'EOF'
# hardening.rules — staged by harden.sh (step 28, CIS 4.1).
# augenrules compiles every rules.d file into /etc/audit/audit.rules when
# the service starts. Keys (-k) are what you hand to `ausearch -k`.

## Self-protection: the audit config and its logs are themselves watched.
-w /etc/audit/ -p wa -k auditconfig
-w /var/log/audit/ -p wa -k auditlog

## Identity (CIS 4.1.3): every write to the account database is recorded.
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

## Privilege scope: sudoers edits are never silent.
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

## The door: sshd configuration (including this repo's own drop-ins).
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd

## Time manipulation is log forgery 101: both arches, plus the zone file.
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

## Kernel modules: loading code into the kernel is always worth a line.
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k modules

# No `-e 2` (immutable) on purpose: this script is safe to re-run, and an
# immutable config would make every later rule change need a reboot. Flip
# it yourself once the ruleset is final on a production box.
EOF
)
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would install auditd, stage %s, pin keep_logs/syslog in auditd.conf and enable the service\n' \
            "$c_yellow" "$c_reset" "$AUDIT_RULES"
        return 0
    fi
    command -v auditctl >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive run apt-get install -y auditd
    install -d -m 750 /etc/audit/rules.d
    if [ ! -f "$AUDIT_RULES" ] || [ "$(cat "$AUDIT_RULES")" != "$rules_content" ]; then
        printf '%s\n' "$rules_content" > "$AUDIT_RULES"
        warn "audit ruleset staged at $AUDIT_RULES"
    else
        ok "audit ruleset already staged"
    fi
    chmod 0640 "$AUDIT_RULES"
    chown root:root "$AUDIT_RULES"

    # auditd.conf (CIS 4.1.2): keep the history instead of silently rotating
    # it away, and shout to syslog when disk space runs low. syslog rather
    # than the benchmark's email: it needs no mail stack and lands in the
    # journal this baseline already made persistent.
    if [ -f "$AUDITD_CONF" ]; then
        pin_auditd_key "$AUDITD_CONF" max_log_file_action keep_logs
        pin_auditd_key "$AUDITD_CONF" space_left_action syslog
        ok "audit history kept (keep_logs) and low-space warnings go to syslog"
    else
        warn "$AUDITD_CONF not found — package layout changed?"
    fi

    systemctl enable auditd >/dev/null 2>&1 || warn "could not enable auditd (no systemd?)"
    if augenrules --load >/dev/null 2>&1; then
        ok "audit rules loaded into the running kernel"
    else
        warn "kernel audit netlink not reachable (container/WSL) — the enabled service loads the staged rules at boot on real hardware"
    fi
    ok "auditd staged: identity, sudoers, sshd, time and module syscalls leave a trail"
}

# ---- Step 29: home directory permissions (CIS 6.2) -------------------------

# Legacy dotfiles that grant access without a password: .netrc stores
# cleartext logins (and ftp/curl read it), .rhosts and .shosts are the
# rlogin trust files that let a named remote user in with no credential at
# all, and .forward silently ships a user's mail elsewhere. All four are
# relics; none has a legitimate place on a hardened server.
HOME_LEGACY_FILES=".netrc .rhosts .shosts .forward"

# Interactive users' homes, one "user:home" pair per line. Interactive means
# uid >= 1000 (system accounts got their own treatment in step 25) with a
# real shell, plus root — whose /root ships 700 on Debian and stays out of
# the uid sweep. Homes that don't exist yet are skipped: a home that isn't
# there has no permissions to fix.
interactive_homes() {
    awk -F: '($3 >= 1000 && $7 !~ /(nologin|false)$/) || $1 == "root" { print $1 ":" $6 }' /etc/passwd |
        while IFS=: read -r user home; do
            # if-fi, not `&&`: a trailing missing home must not turn into a
            # non-zero exit for the whole pipeline (set -e is watching).
            if [ -n "$home" ] && [ -d "$home" ]; then
                printf '%s:%s\n' "$user" "$home"
            fi
        done
}

setup_home_permissions() {
    [ "$DO_HOME_PERMISSIONS" -eq 1 ] || { log "Skipping home directory permissions"; return 0; }
    log "Tightening home directories (CIS 6.2)"
    # A home directory is the last place default permissions should be
    # generous, and 755 is exactly what most distros create: every local
    # account — including the service accounts step 25 just locked, and
    # anything that gets a shell through a compromised daemon — can read
    # ~/.ssh, ~/.aws, ~/.kube, the shell history with the password someone
    # typed at the wrong prompt. Group-write is worse: on a distro with
    # USERGROUPS_ENAB the group is the user's own, but on a shared-group
    # setup it hands teammates write access to each other's dotfiles, and a
    # writable ~/.bashrc is code execution as that user at the next login.
    # Mode only, ownership untouched: adopting a home to root would break
    # the login it exists for.
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would strip g-w,o-rwx from interactive home directories and remove %s\n' \
            "$c_yellow" "$c_reset" "$HOME_LEGACY_FILES"
        return 0
    fi
    local pair user home mode tightened=0 removed=0 f
    while IFS= read -r pair; do
        [ -n "$pair" ] || continue
        user=${pair%%:*}
        home=${pair#*:}
        mode=$(stat -c '%a' "$home" 2>/dev/null) || continue
        # Anything looser than 750 in the group/other bits gets trimmed;
        # a home that is already 700 or 750 is left exactly as it is.
        if [ $((8#$mode & 8#0027)) -ne 0 ]; then
            chmod g-w,o-rwx "$home"
            warn "$home was $mode — tightened to $(stat -c '%a' "$home") ($user)"
            tightened=$((tightened + 1))
        fi
        for f in $HOME_LEGACY_FILES; do
            if [ -e "$home/$f" ]; then
                rm -f "$home/$f"
                warn "removed $home/$f — passwordless access / mail forwarding relic"
                removed=$((removed + 1))
            fi
        done
    done <<EOF
$(interactive_homes)
EOF
    [ "$tightened" -eq 0 ] && ok "every interactive home is already 750 or tighter"
    [ "$removed" -eq 0 ] && ok "no .netrc / .rhosts / .shosts / .forward files present"
    ok "Home directories are private to their owner"
}

# ---- Step 30: process isolation (/proc hidepid + ptrace_scope) -------------

# hidepid=2 ("invisible" in modern kernels) hides other users' /proc entries
# outright; hidepid=1 would still show the directories. 2 is the useful one:
# with 1, `ps` still enumerates every PID and its owner.
PROCESS_HIDEPID="${PROCESS_HIDEPID:-2}"
# An optional group that keeps full visibility — for a monitoring agent that
# must see the whole process table without running as root. Empty by default:
# no exception until someone asks for one.
PROCESS_HIDEPID_GID="${PROCESS_HIDEPID_GID:-}"
PROCESS_SYSCTL_DROPIN="/etc/sysctl.d/99-hardening-process.conf"

setup_process_isolation() {
    [ "$DO_PROCESS_ISOLATION" -eq 1 ] || { log "Skipping process isolation"; return 0; }
    log "Isolating processes from each other (/proc hidepid + ptrace_scope)"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would pin /proc with hidepid=%s in /etc/fstab, remount it live, and set kernel.yama.ptrace_scope=1\n' \
            "$c_yellow" "$c_reset" "$PROCESS_HIDEPID"
        return 0
    fi

    # ---- Door 1: /proc hidepid --------------------------------------------
    # `ps aux` on a stock box is an information goldmine for any local
    # account: every command line in full, so a `mysql -pSecret`, a curl with
    # a token in the URL or a backup script's `--password=` is there for the
    # taking — plus a free inventory of what runs and as whom. hidepid makes
    # /proc show a user only their own processes; root and the optional
    # monitoring group still see everything.
    local mountopts="hidepid=$PROCESS_HIDEPID"
    [ -n "$PROCESS_HIDEPID_GID" ] && mountopts="$mountopts,gid=$PROCESS_HIDEPID_GID"

    # fstab: Debian has NO /proc line (the initramfs and systemd mount it),
    # so without a pin the hardening dies at the next reboot. An existing
    # entry keeps its own options; only what's missing is added.
    if grep -qE '^[^#[:space:]]+[[:space:]]+/proc[[:space:]]' /etc/fstab; then
        local tmp
        tmp=$(mktemp)
        awk -v want="$mountopts" '
            $1 !~ /^#/ && $2 == "/proc" {
                n = split($4, have, ",")
                for (i = 1; i <= n; i++) seen[have[i]] = 1
                m = split(want, wants, ",")
                for (i = 1; i <= m; i++) {
                    # A key=value option counts as present if the KEY is
                    # already there — an admin who chose hidepid=1 or their
                    # own gid keeps that choice instead of getting a second,
                    # contradictory copy of the same key.
                    split(wants[i], kv, "=")
                    found = 0
                    for (o in seen) { split(o, ok2, "="); if (ok2[1] == kv[1]) found = 1 }
                    if (!found) $4 = $4 "," wants[i]
                }
                delete seen
                if ($5 == "") $5 = "0"
                if ($6 == "") $6 = "0"
                print $1 "\t" $2 "\t" $3 "\t" $4 "\t" $5 "\t" $6
                next
            }
            { print }
        ' /etc/fstab > "$tmp"
        if cmp -s "$tmp" /etc/fstab; then
            ok "fstab entry for /proc already carries a hidepid option"
            rm -f "$tmp"
        else
            install -m 644 -o root -g root "$tmp" /etc/fstab
            rm -f "$tmp"
            ok "Added the hidepid option to the existing /proc fstab entry"
        fi
    else
        printf 'proc\t/proc\tproc\tdefaults,nosuid,nodev,noexec,%s\t0\t0\n' "$mountopts" >> /etc/fstab
        ok "Pinned /proc in /etc/fstab with $mountopts"
    fi

    # Live remount, only when the option isn't already in effect (a second
    # pass must not touch the mount table). Modern kernels report hidepid=2
    # as "invisible" and hidepid=1 as "noaccess", so accept either spelling.
    local live want_live=0
    live=$(findmnt -no OPTIONS /proc 2>/dev/null || true)
    case "$PROCESS_HIDEPID" in
        2) case ",$live," in *",hidepid=2,"*|*",hidepid=invisible,"*) ;; *) want_live=1;; esac;;
        1) case ",$live," in *",hidepid=1,"*|*",hidepid=noaccess,"*) ;; *) want_live=1;; esac;;
        *) case ",$live," in *",hidepid=$PROCESS_HIDEPID,"*) ;; *) want_live=1;; esac;;
    esac
    if [ "$want_live" -eq 1 ]; then
        if mount -o "remount,$mountopts" /proc 2>/dev/null; then
            ok "Remounted /proc with $mountopts — users no longer see each other's processes"
        else
            warn "could not remount /proc with $mountopts (restricted environment) — the fstab pin applies at next boot"
        fi
    else
        ok "/proc is already mounted with hidepid"
    fi

    # ---- Door 2: ptrace_scope --------------------------------------------
    # hidepid hides the process LIST; ptrace_scope stops reading a process's
    # MEMORY. With the default 0, any process can attach to another of the
    # same user: one compromised script reads the session cookies out of the
    # browser, the keys out of ssh-agent, the passphrase out of gpg-agent —
    # no root needed. With 1 only a direct parent may attach, which is all
    # debuggers launched from the shell actually need.
    # Own drop-in (not the step-6 sysctl file) so --no-process-isolation and
    # --no-sysctl stay independent, like the per-step sshd drop-ins.
    local desired
    desired=$(printf '# Managed by harden.sh (process isolation step). Edit the script, not this file.\n# Only a direct parent may ptrace a process: without this, anything running\n# as you can read the memory of your browser, ssh-agent or gpg-agent.\nkernel.yama.ptrace_scope = 1\n')
    if [ -f "$PROCESS_SYSCTL_DROPIN" ] && [ "$(cat "$PROCESS_SYSCTL_DROPIN")" = "$desired" ]; then
        ok "ptrace_scope drop-in already in place"
    else
        printf '%s' "$desired" > "$PROCESS_SYSCTL_DROPIN"
        chmod 644 "$PROCESS_SYSCTL_DROPIN"
        chown root:root "$PROCESS_SYSCTL_DROPIN"
        ok "Wrote $PROCESS_SYSCTL_DROPIN (kernel.yama.ptrace_scope = 1)"
    fi
    # Apply now; the drop-in covers the next boot. Yama may be absent from a
    # kernel built without it, so a failure warns instead of aborting.
    if [ "$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo missing)" = "1" ]; then
        ok "kernel.yama.ptrace_scope is already 1"
    elif sysctl -q -w kernel.yama.ptrace_scope=1 2>/dev/null; then
        ok "Set kernel.yama.ptrace_scope=1 live"
    else
        warn "kernel.yama.ptrace_scope not settable here (no Yama LSM?) — the drop-in applies where it exists"
    fi
    ok "Processes are isolated: no peeking at other users' process lists or memory"
}

setup_guess_cost() {
    [ "$DO_GUESS_COST" -eq 1 ] || { log "Skipping guess cost"; return 0; }
    log "Raising the cost of a wrong password guess (offline and online)"
    # The password steps so far decide WHAT a password may be (15), WHEN it
    # must change (7) and how many live misses lock the account (19). This
    # one prices the guesses themselves. Offline: yescrypt's cost factor at
    # its maximum makes each attempt against a stolen shadow file cost about
    # a second of CPU instead of milliseconds — the difference between a
    # cracking rig testing millions of candidates and testing a handful.
    # Online: pam_faildelay makes every failed live authentication wait
    # FAIL_DELAY seconds before control returns, so even a guesser that
    # dodges fail2ban (console, su, serial) gets ~12 tries a minute. A
    # correct password pays neither price — libpam only applies the delay
    # when the authentication ultimately fails.
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would pin YESCRYPT_COST_FACTOR 11 and FAIL_DELAY 5 in /etc/login.defs\n' "$c_yellow" "$c_reset"
        printf '    %s(dry-run)%s would enable a pam-auth-update profile wiring pam_faildelay into common-auth\n' "$c_yellow" "$c_reset"
        return 0
    fi
    # Both knobs live in login.defs — chpasswd, newusers AND pam_unix read
    # the cost factor from there (verified empirically: a PAM password
    # change also lands a $y$jFT$ hash), and pam_faildelay without inline
    # arguments falls back to FAIL_DELAY. One file, one source of truth.
    local key val
    for kv in "YESCRYPT_COST_FACTOR 11" "FAIL_DELAY 5"; do
        key="${kv% *}"; val="${kv#* }"
        if grep -qE "^${key}[[:space:]]" /etc/login.defs; then
            sed -i "s/^${key}[[:space:]].*/${key}\t${val}/" /etc/login.defs
        else
            printf '%s\t%s\n' "$key" "$val" >> /etc/login.defs
        fi
    done
    # Existing hashes keep the cost they were minted with — only the next
    # password change re-hashes. The admin user this script installs is
    # key-only (locked password), so nothing needs re-hashing here.
    #
    # The delay module must sit on the FAILURE path: after pam_unix (so the
    # guess has actually been judged) but before anything that ends the
    # stack — faillock's authfail dies, and Debian's closing pam_deny is
    # requisite. A line appended after those never runs. Priority 128 puts
    # it exactly there: below pam_unix (256), above authfail (0).
    install -d -m 755 /usr/share/pam-configs
    cat > /usr/share/pam-configs/hardening-faildelay <<'EOF'
Name: Fail delay — every wrong guess waits (debian-hardening)
Default: yes
Priority: 128
Auth-Type: Primary
Auth:
	optional			pam_faildelay.so
EOF
    if command -v pam-auth-update >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive pam-auth-update --package \
            --enable hardening-faildelay \
            || warn "pam-auth-update could not enable the faildelay profile"
        ok "wrong guesses now cost ~1 s of CPU offline and a $(grep -E '^FAIL_DELAY' /etc/login.defs | awk '{print $2}')-second wait live"
    else
        warn "pam-auth-update not found — faildelay profile written but not wired"
    fi
}

setup_pw_history() {
    [ "$DO_PW_HISTORY" -eq 1 ] || { log "Skipping password history"; return 0; }
    log "Enforcing password history (no coming back to an old one)"
    # The password arc so far: pwquality decides WHAT may be a password (15),
    # aging decides WHEN it must change (7), faillock counts live misses (19)
    # and guess-cost prices each try (31). This closes the loop: a forced
    # change is pointless if the user can rotate straight back to the old
    # password. pam_pwhistory keeps the last hashes in /etc/security/opasswd
    # and refuses any new password that matches one of them.
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would ensure /etc/security/opasswd exists as root:root 0600\n' "$c_yellow" "$c_reset"
        printf '    %s(dry-run)%s would enable a pam-auth-update profile wiring pam_pwhistory (remember=24, enforce_for_root) into common-password\n' "$c_yellow" "$c_reset"
        return 0
    fi
    # opasswd holds password HASHES — the same sensitivity as shadow. This
    # Debian ships it empty at 0600 already, but the file is the history
    # database and the step owns its existence and its modes either way.
    [ -f /etc/security/opasswd ] || touch /etc/security/opasswd
    chown root:root /etc/security/opasswd
    chmod 600 /etc/security/opasswd
    # Position (measured on the node before writing this): the profile's
    # priority decides where the line lands in common-password. 512 puts it
    # below pwquality (1024) — strength is judged first, so history is never
    # consulted about a password that would be rejected anyway — and above
    # pam_unix (256), so reuse is refused BEFORE the change lands.
    #
    # enforce_for_root is not decoration (measured both ways): without it,
    # a reuse performed by root — chpasswd included, it traverses this same
    # stack — still PRINTS "Password has been already used" and then goes
    # through anyway. A warning nobody acts on is not a control.
    install -d -m 755 /usr/share/pam-configs
    cat > /usr/share/pam-configs/hardening-pwhistory <<'EOF'
Name: Password history — no coming back to an old one (debian-hardening)
Default: yes
Priority: 512
Password-Type: Primary
Password:
	requisite			pam_pwhistory.so remember=24 use_authtok enforce_for_root
EOF
    if command -v pam-auth-update >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive pam-auth-update --package \
            --enable hardening-pwhistory \
            || warn "pam-auth-update could not enable the pwhistory profile"
        ok "the last 24 passwords per account can no longer be reused (root included)"
    else
        warn "pam-auth-update not found — pwhistory profile written but not wired"
    fi
}

# Judges one PATH entry, printing why it is unsafe (empty output = it is fine).
# The check that matters is the LAST one, and it has a trap: on any modern
# Debian /bin and /sbin are SYMLINKS into /usr (usrmerge), and a symlink is
# always mode 777 — so the obvious `stat -c %a` reports every stock system as
# having world-writable directories in root's PATH. `stat -Lc` follows the
# link and reports the real directory (755). This function is where that
# false positive was cornered; verify.sh and audit.sh dereference too.
path_entry_problem() {
    local dir="$1"
    if [ -z "$dir" ]; then
        printf 'empty entry (means the current directory)'
        return 0
    fi
    case "$dir" in
        .|..|./*|../*) printf 'relative entry (%s)' "$dir"; return 0;;
        /*) : ;;
        *) printf 'relative entry (%s)' "$dir"; return 0;;
    esac
    if [ ! -d "$dir" ]; then
        printf 'not a directory'
        return 0
    fi
    local mode
    mode=$(stat -Lc %a "$dir" 2>/dev/null) || { printf 'unreadable'; return 0; }
    # Pad to 4 digits so the group/other test is positional-safe.
    while [ "${#mode}" -lt 4 ]; do mode="0$mode"; done
    local go="${mode: -2}"
    case "$go" in
        *[2367]) printf 'writable by group or others (mode %s)' "$mode"; return 0;;
    esac
    printf ''
}

# Rewrites a PATH string keeping only the entries that survive the checks
# above, in their original order. Echoes the cleaned value.
sanitize_path_value() {
    local value="$1" out="" entry problem
    local IFS=':'
    # shellcheck disable=SC2086
    set -f
    for entry in $value; do
        problem=$(path_entry_problem "$entry")
        [ -n "$problem" ] && continue
        if [ -z "$out" ]; then out="$entry"; else out="$out:$entry"; fi
    done
    set +f
    printf '%s' "$out"
}

# Collects every directory named by the three PATH sources below, one per
# line, deduplicated. Used by the mode sweep and by the audit.
root_path_dirs() {
    {
        awk '$1=="ENV_SUPATH"{sub(/^[^=]*=/, "", $2); print $2}' /etc/login.defs 2>/dev/null
        grep -hoE '^[[:space:]]*PATH="[^"]*"' /etc/profile 2>/dev/null | sed 's/.*PATH="//; s/"$//'
        awk -F= '$1=="PATH"{print $2}' /etc/crontab 2>/dev/null
    } | tr ':' '\n' | sed '/^$/d' | sort -u
}

setup_root_path() {
    [ "$DO_ROOT_PATH" -eq 1 ] || { log "Skipping root PATH integrity"; return 0; }
    log "Securing root's PATH (CIS 6.2.8)"
    # Every command root types is looked up along PATH, in order — so whoever
    # can write to a directory early in that list chooses what root actually
    # runs. An empty entry (`::`, or a leading/trailing colon) means "the
    # current directory": root cd's into /tmp, types `ls`, and runs whatever
    # a local user left there named ls. A group/world-writable directory
    # anywhere in the list is the same trap, and it survives reboots.
    #
    # THREE SOURCES, because pinning only login.defs is a hollow promise on
    # Debian — verified on the node before writing this step:
    #   1. /etc/login.defs ENV_SUPATH / ENV_PATH — a real login, or `su -`
    #      from an unprivileged account.
    #   2. /etc/profile — which OVERWRITES the value from login.defs for every
    #      login shell with a literal `PATH="..."` per uid branch. This is the
    #      PATH an admin actually sees, and it wins.
    #   3. /etc/crontab PATH= — what root's scheduled jobs get; neither of
    #      the above reaches them.
    # Nothing is imposed: each source keeps the entries the admin put there
    # and loses only the unsafe ones (empty, relative, missing,
    # group/world-writable) — the merge-by-key stance of the process
    # isolation step, so a legitimate /opt/tools survives.
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would drop unsafe entries (empty, relative, world-writable) from ENV_SUPATH / ENV_PATH in /etc/login.defs, the PATH lines of /etc/profile and PATH= in /etc/crontab\n' "$c_yellow" "$c_reset"
        printf '    %s(dry-run)%s would remove group/other write permission from the directories those PATHs name\n' "$c_yellow" "$c_reset"
        return 0
    fi
    local key current cleaned changed_any=0

    # ---- The directories FIRST, then the lists -----------------------------
    # The order of these two halves is not cosmetic, and getting it wrong is
    # a bug this step already had: sanitizing the lists first DELETED any
    # world-writable directory from the PATH instead of fixing it — so a
    # loose /usr/local/bin vanished from root's PATH (breaking every locally
    # installed binary) when the right answer was to tighten its mode and
    # keep it. Fix what can be fixed; only then drop what cannot.
    #
    # Only modes are touched (never ownership — adopting a distro directory
    # would be worse than the problem), and only when actually loose.
    local dir mode tightened=0 target
    while IFS= read -r dir; do
        [ -d "$dir" ] || continue
        mode=$(stat -Lc %a "$dir" 2>/dev/null) || continue
        while [ "${#mode}" -lt 4 ]; do mode="0$mode"; done
        case "${mode: -2}" in
            *[2367])
                # Dereference deliberately: chmod on /bin would change the
                # LINK, which is meaningless — links are always mode 777, and
                # that is exactly why a naive `stat -c %a` check reports every
                # stock Debian as broken here.
                target=$(readlink -f "$dir")
                chmod go-w "$target"
                warn "tightened $dir -> $target (was $mode) — it was writable by group or others"
                tightened=$((tightened + 1))
                ;;
        esac
    done < <(root_path_dirs)
    [ "$tightened" -eq 0 ] && ok "every directory in root's PATH is root-writable only"

    # ---- Source 1: login.defs ---------------------------------------------
    for key in ENV_SUPATH ENV_PATH; do
        current=$(awk -v k="$key" '$1==k{sub(/^[^=]*=/, "", $2); print $2; exit}' /etc/login.defs)
        [ -n "$current" ] || { warn "$key not set in /etc/login.defs — leaving it alone"; continue; }
        cleaned=$(sanitize_path_value "$current")
        if [ -z "$cleaned" ]; then
            warn "$key would be empty after dropping unsafe entries — refusing to touch it"
            continue
        fi
        if [ "$cleaned" = "$current" ]; then
            ok "$key is already free of unsafe entries"
        else
            sed -i "s|^${key}[[:space:]].*|${key}\tPATH=${cleaned}|" /etc/login.defs
            warn "$key had unsafe entries — rewritten to PATH=$cleaned"
            changed_any=1
        fi
    done

    # ---- Source 2: /etc/profile (the one that actually wins) --------------
    # Debian's /etc/profile sets PATH literally, in an if/else on the uid, so
    # there are normally two lines. Each is sanitized in place; the quoting
    # and indentation are preserved by rewriting only what is inside "".
    if [ -f /etc/profile ]; then
        local line_no raw cleaned_p
        while IFS= read -r line_no; do
            raw=$(sed -n "${line_no}p" /etc/profile | sed 's/.*PATH="//; s/"$//')
            cleaned_p=$(sanitize_path_value "$raw")
            if [ -z "$cleaned_p" ]; then
                warn "/etc/profile line $line_no would be left with an empty PATH — skipped"
                continue
            fi
            if [ "$cleaned_p" != "$raw" ]; then
                sed -i "${line_no}s|PATH=\"[^\"]*\"|PATH=\"${cleaned_p}\"|" /etc/profile
                warn "/etc/profile line $line_no had unsafe PATH entries — rewritten"
                changed_any=1
            fi
        done < <(grep -nE '^[[:space:]]*PATH="[^"]*"' /etc/profile | cut -d: -f1)
        [ "$changed_any" -eq 0 ] && ok "/etc/profile PATH lines are already clean"
    fi

    # ---- Source 3: /etc/crontab ------------------------------------------
    if [ -f /etc/crontab ]; then
        local cron_path cleaned_c
        cron_path=$(awk -F= '$1=="PATH"{print $2; exit}' /etc/crontab)
        if [ -n "$cron_path" ]; then
            cleaned_c=$(sanitize_path_value "$cron_path")
            if [ -n "$cleaned_c" ] && [ "$cleaned_c" != "$cron_path" ]; then
                sed -i "s|^PATH=.*|PATH=${cleaned_c}|" /etc/crontab
                warn "/etc/crontab PATH had unsafe entries — rewritten to $cleaned_c"
                changed_any=1
            fi
        fi
    fi

    ok "root's PATH cannot be hijacked by a writable directory or an implicit '.'"
}

APT_SANDBOX_UNIT="apt-daily-upgrade.service"
APT_SANDBOX_DROPIN_DIR="/etc/systemd/system/apt-daily-upgrade.service.d"
APT_SANDBOX_DROPIN="$APT_SANDBOX_DROPIN_DIR/99-hardening.conf"

setup_apt_sandboxing() {
    [ "$DO_APT_SANDBOXING" -eq 1 ] || { log "Skipping apt updater sandboxing"; return 0; }
    log "Sandboxing the $APT_SANDBOX_UNIT unit (systemd)"
    # The unattended-upgrades path runs unattended, on a timer, as root, and
    # reaches out to the network to pull and install packages — a foothold
    # worth boxing in, exactly like fail2ban (step 22). But apt is the
    # ANTI-sandbox workload, and the interesting part is what it will NOT
    # tolerate. Two flags that read like obvious hardening actively break it,
    # BOTH MEASURED on the node before this step was written:
    #   * ProtectSystem=full/strict — dpkg writes /usr, /boot, /etc, /var on
    #     every install; a read-only system tree fails the upgrade outright.
    #     (fail2ban tolerated ProtectSystem=full with a ReadWritePaths carve-out
    #     — apt tolerates none at all.)
    #   * RestrictSUIDSGID=true — dpkg installs setuid binaries (passwd, sudo,
    #     mount, ...). Measured: reinstalling `passwd` under this flag fails
    #     with dpkg error status 100. A single security update that touches a
    #     setuid package would break the unattended run at 6am.
    # So the shipped set is the process-level confinement that CANNOT collide
    # with installing packages: no new privileges, a private /tmp, /home hidden,
    # cgroup fs protected. Measured: apt-daily-upgrade runs to Result=success
    # under exactly this set, including a reinstall of a setuid package.
    if ! command -v systemctl >/dev/null 2>&1; then
        warn "systemd not available — apt sandboxing skipped"
        return 0
    fi
    if ! systemctl list-unit-files "$APT_SANDBOX_UNIT" >/dev/null 2>&1 \
        || ! systemctl cat "$APT_SANDBOX_UNIT" >/dev/null 2>&1; then
        warn "$APT_SANDBOX_UNIT not present (unattended-upgrades not installed?) — nothing to sandbox"
        return 0
    fi
    local content
    content=$(cat <<'EOF'
# Managed by debian-hardening (apt updater sandboxing step).
# Conservative systemd confinement for the unattended apt updater. ONLY the
# process-level flags that cannot collide with installing packages: NO
# ProtectSystem (dpkg writes /usr, /boot, /etc) and NO RestrictSUIDSGID (dpkg
# installs setuid binaries) — both measured to break apt. Edit flags, not this.
[Service]
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectControlGroups=true
EOF
)
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would write %s and reload systemd\n' "$c_yellow" "$c_reset" "$APT_SANDBOX_DROPIN"
        return 0
    fi
    if [ -f "$APT_SANDBOX_DROPIN" ] && [ "$(cat "$APT_SANDBOX_DROPIN")" = "$content" ]; then
        ok "$APT_SANDBOX_UNIT sandboxing already in place"
        return 0
    fi
    install -d -m 755 "$APT_SANDBOX_DROPIN_DIR"
    printf '%s\n' "$content" > "$APT_SANDBOX_DROPIN"
    chmod 644 "$APT_SANDBOX_DROPIN"
    systemctl daemon-reload
    # A oneshot updater can't be "restarted and checked active" like fail2ban.
    # The safety net instead: confirm systemd actually APPLIED the drop-in — a
    # malformed one is rejected by daemon-reload and the property won't reflect.
    # If it didn't take, revert rather than ship a confinement that isn't real.
    if [ "$(systemctl show "$APT_SANDBOX_UNIT" -p NoNewPrivileges --value 2>/dev/null)" = "yes" ]; then
        ok "$APT_SANDBOX_UNIT is sandboxed (NoNewPrivileges, PrivateTmp, ProtectHome, ProtectControlGroups)"
    else
        rm -f "$APT_SANDBOX_DROPIN"
        systemctl daemon-reload
        err "$APT_SANDBOX_UNIT did not accept the sandbox drop-in — reverted"
        return 1
    fi
}

# ---- Main -----------------------------------------------------------------
# ---- Step 35: SSH crypto policy (CIS 5.2) -----------------------------------

setup_ssh_crypto() {
    [ "$DO_SSH_CRYPTO" -eq 1 ] || { log "Skipping SSH crypto policy"; return 0; }
    log "Pinning the SSH crypto policy (ciphers, MACs, key exchange)"
    local dropin="/etc/ssh/sshd_config.d/95-hardening-crypto.conf"
    # Stock OpenSSH 10 on Debian 13 still NEGOTIATES hmac-sha1 and the
    # 64-bit-tag umac-64 when the client asks for them (measured on a fresh
    # node: forcing `-o Ciphers=aes256-ctr -o MACs=hmac-sha1` gets a
    # session), and its key-exchange list drags the NIST P-curves behind the
    # modern hybrids. The MAC pin matters PRECISELY because ctr ciphers stay
    # in the list: with an AEAD cipher (chacha20/GCM) OpenSSH skips MAC
    # selection entirely — the MAC field is decorative — so the real
    # downgrade path is a client asking for aes256-ctr + hmac-sha1, and a
    # stock server obliges (measured both ways).
    # Key exchange keeps only the post-quantum hybrids and curve25519 —
    # what every current client offers first anyway, minus the NIST tail.
    # The hybrids exist for "harvest now, decrypt later": a session recorded
    # today should not become plaintext the day its owner buys the hardware.
    # Precedence, measured: Debian includes sshd_config.d at the TOP of
    # sshd_config and sshd honours the FIRST occurrence of a keyword, so
    # this drop-in beats any legacy-compat Ciphers/MACs/Kex line someone
    # left in the main file.
    local content
    content=$(cat <<'EOF'
# Managed by debian-hardening (harden.sh). Edit flags, not this file.
# Crypto policy: what the transport may negotiate, pinned.
#
# AEAD first; ctr kept for compatibility — which is exactly why the MACs
# line below matters (AEAD ignores the MAC, ctr does not).
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
# Encrypt-then-MAC only, 128-bit tags or better: no sha1, no umac-64.
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
# Post-quantum hybrids + curve25519. The NIST P-curve tail is gone.
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
EOF
)
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would write %s:\n' "$c_yellow" "$c_reset" "$dropin"
        printf '%s\n' "$content" | sed 's/^/        /'
        return 0
    fi
    if ! command -v sshd >/dev/null 2>&1; then
        warn "sshd not installed — SSH crypto policy skipped"
        return 0
    fi
    if [ -f "$dropin" ] && [ "$(cat "$dropin")" = "$content" ]; then
        ok "SSH crypto policy already in place"
        return 0
    fi
    install -d -m 755 /etc/ssh/sshd_config.d
    printf '%s\n' "$content" > "$dropin"
    chmod 644 "$dropin"
    # Same contract as every sshd change in this script: validate before it
    # goes live, revert if sshd rejects it — a bad config must never ship.
    if sshd -t 2>/dev/null; then
        systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
        ok "SSH negotiates modern crypto only (no sha1, no NIST curves, PQ-ready)"
    else
        rm -f "$dropin"
        err "sshd config validation failed after adding the crypto policy — reverted"
    fi
}

# ---- Step 36: legacy protocol purge (CIS 2.2/2.3) ---------------------------

# Packages whose protocol IS the vulnerability: telnet/rlogin/talk move
# credentials and sessions in cleartext, NIS hands the password map to
# whoever asks, tftp has no authentication at all, and the inetd
# superservers exist to expose more of the above. Every variant Debian has
# shipped is listed (netkit, inetutils, redone, hpa) — a wishlist, not an
# inventory: dpkg decides below which of them actually exist on this box.
LEGACY_PROTOCOL_PACKAGES=(
    telnet inetutils-telnet telnetd inetutils-telnetd
    rsh-client rsh-redone-client rsh-server rsh-redone-server
    talk inetutils-talk talkd inetutils-talkd
    nis tftp tftpd atftp atftpd tftp-hpa tftpd-hpa
    xinetd openbsd-inetd inetutils-inetd
)

setup_legacy_protocols() {
    [ "$DO_LEGACY_PROTOCOLS" -eq 1 ] || { log "Skipping legacy protocol purge"; return 0; }
    log "Purging legacy network-protocol packages (CIS 2.2/2.3)"
    # dpkg is asked FIRST and apt-get purge runs ONLY on packages dpkg has
    # actually seen: `apt-get purge` exits 100 on a name the sources never
    # heard of (measured: rsh-client has no installation candidate on
    # Debian 13), which under `set -e` would abort the whole run over a
    # package that was never there. config-files state counts as present:
    # a removed-but-not-purged package still leaves its config behind.
    #
    # The transitional trap, also measured: on Debian 13 `telnet` is a dummy
    # package whose payload is inetutils-telnet (wired through
    # update-alternatives) — purging the dummy alone leaves /usr/bin/telnet
    # working. The list names both halves of every such pair.
    local pkg status
    local present=()
    for pkg in "${LEGACY_PROTOCOL_PACKAGES[@]}"; do
        status=$(dpkg-query -W -f '${db:Status-Status}' "$pkg" 2>/dev/null) || true
        case "$status" in
            installed|config-files) present+=("$pkg");;
        esac
    done
    if [ ${#present[@]} -eq 0 ]; then
        ok "no legacy protocol packages present (${#LEGACY_PROTOCOL_PACKAGES[@]} names checked)"
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would purge: %s\n' "$c_yellow" "$c_reset" "${present[*]}"
        return 0
    fi
    run apt-get purge -y "${present[@]}"
    ok "purged ${#present[@]} legacy protocol package(s): ${present[*]}"
}

# ---- Step 37: filesystem protections (CIS 1.5.x) ----------------------------

FS_PROTECTED_DROPIN="/etc/sysctl.d/99-hardening-fs.conf"

setup_fs_protected() {
    [ "$DO_FS_PROTECTED" -eq 1 ] || { log "Skipping filesystem-protection sysctls"; return 0; }
    log "Pinning filesystem-protection sysctls (fs.protected_*)"
    # The symlink/hardlink TOCTOU class, in a world-writable directory the
    # whole box shares. protected_symlinks: root (or any user) following a
    # symlink in a sticky dir like /tmp only does so when the link's owner
    # matches the directory's or the follower's — the trick where a local
    # user swaps /tmp/foo for a symlink to /etc/shadow between a root
    # process's check and its open stops working. protected_hardlinks: you
    # can only hardlink to a file you could already read/write, so you can't
    # pin someone else's sensitive file to keep it after they delete it.
    # protected_fifos / protected_regular (kernel 4.19+): the same idea for
    # FIFOs and regular files — a root-run process writing to a predictable
    # /tmp path can't be tricked into clobbering an attacker-planted node.
    # Values: 1 for the first three, 2 for regular (the strong setting that
    # also covers same-owner writes in sticky world-writable dirs).
    #
    # Own drop-in, not the step-6 sysctl file, so --no-fs-protected and
    # --no-sysctl stay independent — the per-step drop-in precedent.
    local desired
    desired=$(cat <<'EOF'
# Managed by harden.sh (filesystem protections step). Edit the script, not this file.
# Defend the TOCTOU/symlink class in world-writable dirs (/tmp): a local
# user cannot make a privileged process follow their symlink, open a
# hardlink to a file they can't read, or clobber a planted FIFO/regular.
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 1
fs.protected_regular = 2
EOF
)
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would write %s and apply it with sysctl\n' "$c_yellow" "$c_reset" "$FS_PROTECTED_DROPIN"
        return 0
    fi
    if [ -f "$FS_PROTECTED_DROPIN" ] && [ "$(cat "$FS_PROTECTED_DROPIN")" = "$desired" ]; then
        ok "filesystem-protection drop-in already in place"
    else
        printf '%s\n' "$desired" > "$FS_PROTECTED_DROPIN"
        chmod 644 "$FS_PROTECTED_DROPIN"
        chown root:root "$FS_PROTECTED_DROPIN"
        ok "Wrote $FS_PROTECTED_DROPIN"
    fi
    # Apply live. These are core-VFS knobs present on every kernel this
    # script targets, but keep the same defensive shape as the other sysctl
    # steps: a write that can't happen warns, never aborts.
    local applied=0 skipped=0 k v
    for kv in \
        "fs.protected_symlinks 1" \
        "fs.protected_hardlinks 1" \
        "fs.protected_fifos 1" \
        "fs.protected_regular 2"; do
        k="${kv% *}"; v="${kv#* }"
        if [ "$(sysctl -n "$k" 2>/dev/null || echo missing)" = "$v" ]; then
            skipped=$((skipped + 1))
        elif sysctl -q -w "$k=$v" 2>/dev/null; then
            applied=$((applied + 1))
        else
            warn "$k not settable here — the drop-in applies where it can"
        fi
    done
    if [ "$applied" -gt 0 ]; then
        ok "Applied $applied filesystem-protection sysctl(s) live ($skipped already set)"
    else
        ok "filesystem-protection sysctls already at target ($skipped/4)"
    fi
    ok "Symlink/hardlink/FIFO games in world-writable directories are shut down"
}

# ---- Step 38: account database hygiene (CIS 6.2) ---------------------------

setup_account_hygiene() {
    [ "$DO_ACCOUNT_HYGIENE" -eq 1 ] || { log "Skipping account database hygiene"; return 0; }
    log "Account database hygiene: NIS entries, unshadowed hashes, empty passwords (CIS 6.2)"
    # Three ways the account DATABASE hands out logins on its own — invisible
    # to every step that hardens the PAM stack, because the hole is in the
    # data, not in the modules:
    #
    #   * NIS compat entries: a line starting with '+' or '-' in passwd/
    #     shadow/group is a legacy "splice the NIS map in here" marker. With
    #     nsswitch on `files` (the Debian default) they are inert TODAY, but
    #     the day someone flips a service to `compat`, an unrestricted
    #     '+::0:0:::' imports every NIS account — uid 0 included. Step 36
    #     purged the NIS packages; this removes the trigger data. They also
    #     pollute every field scan below, so they go first.
    #   * A hash in /etc/passwd's password field AUTHENTICATES (measured:
    #     pam_unix accepts it) — and passwd is world-readable, so that hash
    #     is an offline cracking target for every local account. pwconv
    #     moves it into /etc/shadow (0640 root:shadow); the password keeps
    #     working — measured, the login moves, it doesn't break.
    #   * An EMPTY password field in /etc/shadow: Debian ships pam_unix with
    #     `nullok`, so pressing Enter IS that account's password (measured
    #     with pamtester on a stock node). Locking the field closes the door
    #     for humans and services alike; `passwd -u` reopens it once a real
    #     password is set. pwconv turns an empty PASSWD field into an empty
    #     SHADOW field, which is why this check runs last.
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    %s(dry-run)%s would drop NIS +/- entries, shadow any passwd-file hash (pwconv) and lock empty passwords\n' \
            "$c_yellow" "$c_reset"
        return 0
    fi

    # 1. NIS compat ('+'/'-') entries out of the whole account database.
    local f n purged=0
    for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do
        [ -f "$f" ] || continue
        n=$(grep -c '^[+-]' "$f" || true)
        if [ "$n" -gt 0 ]; then
            sed -i '/^[+-]/d' "$f"
            warn "removed $n NIS compat entry(ies) from $f"
            purged=$((purged + n))
        fi
    done
    [ "$purged" -eq 0 ] && ok "no NIS compat entries in the account database"

    # 2. Password material out of world-readable /etc/passwd.
    local unshadowed
    unshadowed=$(awk -F: '$2 != "x" {print $1}' /etc/passwd | tr '\n' ' ')
    if [ -n "${unshadowed// /}" ]; then
        pwconv
        warn "moved the password field of: ${unshadowed}into /etc/shadow (pwconv)"
        if awk -F: '$2 != "x" {bad = 1} END {exit bad}' /etc/passwd; then
            ok "every /etc/passwd password field is now a shadow pointer"
        else
            warn "pwconv left an unshadowed field behind — inspect /etc/passwd"
        fi
    else
        ok "all /etc/passwd password fields already shadowed"
    fi

    # 3. Empty password fields in /etc/shadow -> locked.
    # if-fi, not `[ ] &&`: a bare test as the loop body's last command leaves
    # the loop with rc 1 on a populated final line, and set -e kills the run.
    local name pass empties=()
    while IFS=: read -r name pass _; do
        if [ -z "$pass" ]; then
            empties+=("$name")
        fi
    done < /etc/shadow
    if [ "${#empties[@]}" -gt 0 ]; then
        for name in "${empties[@]}"; do
            passwd -l "$name" >/dev/null 2>&1 || warn "could not lock $name"
            [ "$name" = root ] && warn "root had an EMPTY password — locked; console recovery now needs init=/bin/bash or a reset"
        done
        warn "locked ${#empties[@]} account(s) whose password was EMPTY (nullok made them free logins): ${empties[*]}"
    else
        ok "no account has an empty password"
    fi
    ok "The account database no longer hands out logins on its own"
}

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
    [ "$DO_ACCOUNT_HYGIENE" -eq 1 ] && echo "    - account database hygiene (NIS '+' entries, unshadowed hashes, empty passwords)"
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
    [ "$DO_FAILLOCK" -eq 1 ]         && echo "    - account lockout after 5 failed logins (pam_faillock)"
    [ "$DO_FILE_PERMISSIONS" -eq 1 ] && echo "    - file permissions: account DB modes, world-writable + orphan sweeps"
    [ "$DO_SSH_ACCESS" -eq 1 ]      && echo "    - SSH login limited to the ssh-users group (admin included)"
    [ "$DO_SERVICE_SANDBOXING" -eq 1 ] && echo "    - systemd sandboxing drop-in for the fail2ban service"
    [ "$DO_JOURNALD" -eq 1 ]        && echo "    - persistent, size-capped journald logging"
    [ "$DO_SU_RESTRICTION" -eq 1 ]  && echo "    - su restricted to the (empty) sugroup group"
    [ "$DO_SYSTEM_ACCOUNTS" -eq 1 ] && echo "    - system accounts locked (nologin shell + locked password)"
    [ "$DO_LOG_PERMISSIONS" -eq 1 ] && echo "    - log file permissions (/var/log sweep + rsyslog create mode)"
    [ "$DO_LOGROTATE_PERMS" -eq 1 ] && echo "    - logrotate permissions (rotated logs re-created 0640)"
    [ "$DO_AUDITD" -eq 1 ]           && echo "    - auditd: staged audit ruleset, enabled at boot"
    [ "$DO_HOME_PERMISSIONS" -eq 1 ] && echo "    - home directory permissions (750 + legacy credential dotfiles removed)"
    [ "$DO_PROCESS_ISOLATION" -eq 1 ] && echo "    - process isolation (/proc hidepid + kernel.yama.ptrace_scope=1)"
    [ "$DO_GUESS_COST" -eq 1 ]  && echo "    - guess cost (yescrypt cost factor 11 + 5 s fail delay)"
    [ "$DO_ROOT_PATH" -eq 1 ]   && echo "    - root PATH integrity (drop unsafe entries, tighten directory modes)"
    [ "$DO_APT_SANDBOXING" -eq 1 ] && echo "    - systemd sandboxing drop-in for the apt updater (unattended-upgrades)"
    [ "$DO_PW_HISTORY" -eq 1 ] && echo "    - password history (pam_pwhistory remember=24, root enforced too)"
    [ "$DO_SSH_CRYPTO" -eq 1 ] && echo "    - SSH crypto policy (no sha1/umac-64 MACs, no NIST kex, PQ hybrids pinned)"
    [ "$DO_LEGACY_PROTOCOLS" -eq 1 ] && echo "    - legacy protocol purge (telnet/rsh/talk/NIS/tftp/inetd family)"
    [ "$DO_FS_PROTECTED" -eq 1 ] && echo "    - filesystem protections (fs.protected_symlinks/hardlinks/fifos/regular)"
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
    # Step 38 runs BEFORE the account-policy steps on purpose: pwconv moves a
    # passwd-file hash into /etc/shadow, and the aging step only applies its
    # policy to accounts whose shadow entry holds a real hash — hygiene last
    # would leave that account unaged until the NEXT run (caught by the
    # idempotence gate: /etc/shadow changed on the second pass).
    setup_account_hygiene
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
    setup_faillock
    setup_file_permissions
    setup_ssh_access_control
    setup_service_sandboxing
    setup_journald
    setup_su_restriction
    setup_system_accounts
    setup_log_permissions
    setup_logrotate_perms
    setup_auditd
    setup_home_permissions
    setup_process_isolation
    setup_guess_cost
    setup_root_path
    setup_apt_sandboxing
    setup_pw_history
    setup_ssh_crypto
    setup_legacy_protocols
    setup_fs_protected

    ok "Done. Review with: sshd -T | grep -Ei 'passwordauth|permitroot' ; ufw status verbose ; fail2ban-client status sshd"
}

# Only run when executed directly; sourcing (e.g. from the test suite) just
# loads the functions without parsing args or touching the system.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    parse_args "$@"
    main
fi
