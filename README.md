# debian-hardening

> One idempotent Bash script that turns a fresh **Debian** server into a
> sensible baseline: a sudo user with your SSH key, key-only SSH, a UFW
> firewall, Fail2Ban and automatic security updates — **without locking you
> out**.

[![lint](https://github.com/DannyRuizB/debian-hardening/actions/workflows/lint.yml/badge.svg)](https://github.com/DannyRuizB/debian-hardening/actions/workflows/lint.yml)
[![e2e](https://github.com/DannyRuizB/debian-hardening/actions/workflows/e2e.yml/badge.svg)](https://github.com/DannyRuizB/debian-hardening/actions/workflows/e2e.yml)
![Bash](https://img.shields.io/badge/Bash-4EAA25?logo=gnubash&logoColor=white)
![Debian](https://img.shields.io/badge/Debian-12%20%7C%2013-A81D33?logo=debian&logoColor=white)
![ShellCheck](https://img.shields.io/badge/ShellCheck-clean-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

## Why

Every new server starts with the same chores: create a user, copy your key,
disable root login and passwords, set up a firewall, install Fail2Ban, enable
unattended upgrades. Doing it by hand is slow and easy to get subtly wrong (and
one wrong SSH setting locks you out). This packages that baseline into a single
script you can read, audit and re-run.

It is intentionally small and dependency-free: just Bash + the standard Debian
tools. No Ansible, no Python — drop it on the box and run it.

## What it does

| Step | Detail |
|---|---|
| **Admin user** | Optional: create a sudo user, install your SSH public key, and grant passwordless sudo (the user has no password, so otherwise couldn't escalate). |
| **SSH** | Drop-in `99-hardening.conf`: no root login, key-only auth, custom port, plus CIS extras (`MaxAuthTries`, `X11Forwarding no`, `LoginGraceTime`, idle timeout). Validates with `sshd -t` before reloading. |
| **Firewall** | UFW: default deny incoming, allow SSH (and any extra ports you pass). |
| **Fail2Ban** | `sshd` jail, `backend = systemd`, `banaction = ufw`, ban 1h / maxretry 5, journal match on the ssh unit (works with OpenSSH ≥ 9.8's `sshd-session`). |
| **Updates** | `unattended-upgrades` for automatic security patches. |
| **Kernel (sysctl)** | Drop-in `/etc/sysctl.d/99-hardening.conf`: no ICMP redirects (in or out), no source routing, reverse-path filtering, martian logging, SYN cookies, restricted `dmesg` / kernel pointers, no setuid core dumps. Deliberately leaves `accept_ra` (IPv6 SLAAC on VPSes) and `ip_forward` (routers / Docker hosts) alone. |
| **Account policies** | Password aging per CIS 5.4 (`PASS_MAX_DAYS 365`, `PASS_MIN_DAYS 1`, `PASS_WARN_AGE 7` in `login.defs`) applied also to existing password-holding accounts, and a 30-day post-expiry inactivity lock for accounts created from now on (`useradd -D -f 30`). Key-only accounts (locked hash — like the admin user step 1 creates) are never touched, and existing accounts don't get the inactivity lock: one whose password expired long ago would be locked on the spot. |
| **Mount options** | `/dev/shm` remounted — and pinned in `/etc/fstab` — with `nodev,nosuid,noexec` (CIS 1.1.2.2): world-writable shared memory stops being a launchpad for droppers. An existing fstab entry keeps its custom options (`size=`…); only the missing flags are added. `/tmp` is deliberately left alone — a `noexec /tmp` breaks well-behaved installers, and Debian doesn't ship it as a separate mount. |
| **Warning banners** | CIS 1.7: a fixed legal notice in `/etc/issue`, `/etc/issue.net` and `/etc/motd` — the stock files advertise the exact OS (`Debian GNU/Linux 13 \n \l`) to anyone who connects, before any login. sshd presents it **pre-auth** via its own drop-in (`Banner /etc/issue.net`), validated with `sshd -t` before reload so a bad config never goes live. The warning is also what makes session monitoring legally defensible. |
| **Sudo hardening** | CIS 5.3: `Defaults use_pty` (every sudo command runs in its own pseudo-terminal, so a malicious command can't inject keystrokes into the calling tty once sudo exits) and `Defaults logfile="/var/log/sudo.log"` (sudo activity in one dedicated file instead of scattered through `auth.log` — the first thing a forensics pass wants). Installed as a drop-in validated with `visudo -cf` before it goes live, so a bad rule can never break sudo. |
| **SSH session policies** | CIS 5.2, in its own drop-in (`97-hardening-policies.conf`): step 2 hardens *who gets in*, this one limits *what a session may do once inside*. `AllowTcpForwarding no` + `AllowAgentForwarding no` (an account with a locked-down shell is still a SOCKS pivot into the network otherwise), `MaxSessions 4` and `MaxStartups 10:30:60` (multiplexing and connection-slot caps), `LogLevel VERBOSE` (logins record the key fingerprint — in a shared-key world, "who exactly connected" stops being guesswork), `PermitUserEnvironment no`, `HostbasedAuthentication no`, `IgnoreRhosts yes`, `PermitEmptyPasswords no`. Validated with `sshd -t`, reverted if rejected. |
| **Core dump limits** | CIS 1.5: a core dump is the crashed process's memory written to disk — keys, passwords, session tokens included. Three doors, three locks: a `limits.d` drop-in sets `hard core 0` for every account (**root gets its own line** — `*` never matches root in `limits.conf`, a classic gap), a `coredump.conf.d` drop-in caps systemd-coredump off (`Storage=none`, `ProcessSizeMax=0` — if that collector is ever installed it bypasses ulimit entirely), and the setuid door (`fs.suid_dumpable=0`) was already locked by the sysctl step. `hard` means a session can't raise the limit back up. |
| **Umask & shell timeout** | CIS 5.4: the stock `umask 022` makes every new file world-readable — logs, dumps, home directories. `UMASK 027` in `login.defs` (pam_umask applies it to every PAM session) plus a `profile.d` drop-in (login shells pick it up even where pam_umask is absent). And the third classic gap — the unlocked terminal someone walked away from — gets `readonly TMOUT=900`: idle interactive shells log out after 15 minutes, and `readonly` means the session can't unset or raise it. |
| **Cron restrictions** | CIS 5.1: scheduled jobs are persistence 101 — a foothold that re-runs itself survives reboots and cleanups. Two moves: the spool goes root-only (`/etc/crontab` to `600`, the `cron.*` drop-in dirs to `700` — by default they're world-readable, leaking commands, paths and timings to any local user), and `crontab`/`at` switch from Debian's deny-list model to an **allow-list with just root** (`cron.allow`/`at.allow`, `cron.deny`/`at.deny` removed). Existing user crontabs keep *running* — the allow-list gates the `crontab(1)` command, not the daemon — so nothing already deployed breaks; unprivileged users just can't schedule anew. An admin-curated `cron.allow` is respected (root is ensured, other entries kept). |
| **Password policy** | CIS 5.3/5.4: the aging step decides *when* a password must change; this one decides *what it may be* and *how it is stored*. `libpam-pwquality` gates every PAM password change — `minlen 14`, all four character classes (`minclass 4`), `maxrepeat 3`, dictionary words rejected — and `enforce_for_root` closes the classic hole where root "fixing" an account types `temp123` straight past the policy. The hashing side: Debian already defaults to yescrypt through PAM, but `chpasswd`/`newusers` read `ENCRYPT_METHOD` from `login.defs` — pinned to `YESCRYPT` so no path quietly falls back to a weaker crypt. |
| **File integrity** | CIS 1.4: every other step hardens a file; this one notices when someone *changes* it afterwards. AIDE fingerprints the system binaries (`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/boot`) and the whole of `/etc` — permissions, ownership, size, mtime/ctime and SHA-256+512 — into a baseline database, and a `systemd` timer re-checks daily. A backdoored `sudo`, an edited `/etc/passwd` or a new SUID binary shows up as drift instead of staying invisible. Own config (`/etc/aide/hardening.conf`) and DB (`/var/lib/aide/hardening.db`) scoped to what matters after a compromise, so the baseline builds fast enough to check daily. On a real box, copy the baseline somewhere the attacker can't reach — otherwise they can just regenerate it. |
| **Rootkit detection** | rkhunter scans for known rootkits, backdoors and local exploits, plus suspicious file properties and hidden files — a second detection layer alongside AIDE (AIDE = generic file integrity, rkhunter = known-threat signatures). A property baseline is taken at hardening time and re-checked daily by a `systemd` timer; Debian's own `cron.daily` job and its network signature auto-update are turned off so the check runs once, from the timer, offline. Installed without recommends so it doesn't drag in a mail-transport agent. |
| **Module blacklist** | CIS 1.1.1 / 3.4: rarely-used filesystems (`cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `udf`) and network protocols (`dccp`, `sctp`, `rds`, `tipc`) made unloadable in `modprobe.d` — every one is kernel code reachable from userspace (a `mount(2)` or `socket(2)` away), and several have carried privilege-escalation CVEs. Two directives per module because they close different doors: `install <m> /bin/false` defeats an explicit `modprobe`, `blacklist <m>` stops the alias auto-load path. Already-loaded modules get a best-effort unload. `usb-storage` is deliberately spared (site-dependent per CIS — it bites the restore-from-USB path), as are `squashfs`/`overlayfs` (snaps, container runtimes). |
| **Account lockout** | CIS 5.3.2: `pam_faillock` locks an account after **5 failed password attempts** for **15 minutes** (`deny=5`, `unlock_time=900`, `audit`). The password-quality step makes each guess expensive and Fail2Ban blocks the SSH *source*; this closes the third face — the *account* itself, so brute force over any PAM path (su, console login, keyboard-interactive SSH) hits a wall. Wired the Debian way via two `pam-auth-update` profiles (a high-priority `preauth` gate above `pam_unix`, an `authfail` tally below it) so the generated `common-auth` stays deterministic and the tool never clobbers a hand-edit. **Key-only SSH never touches the PAM auth stack**, so the admin user this script creates (locked password, key login) can't be locked out by it — the lockout only bites password authentication. |
| **File permissions** | CIS 6.1: exact owner/group/mode on the account database — `passwd`/`group` 644 root:root, `shadow`/`gshadow` 640 root:shadow, **including the `-` backups** the shadow suite writes (same secrets, routinely forgotten) — plus three sweeps over the root filesystem: the world-writable bit cleared on files (any local user could rewrite them), orphan files adopted by root:root (a recycled UID would silently inherit them), and the sticky bit added to world-writable directories (without it anyone can delete anyone's files). SUID/SGID binaries are **inventoried, never stripped** — site-dependent per CIS, and blindly removing bits breaks `sudo`/`passwd`/`ping`. Scratch dirs (`/tmp`, `/var/tmp`) are excluded from the file sweeps: transient by design and already guarded by the sticky bit. |
| **SSH access control** | CIS 5.2: only members of a dedicated `ssh-users` group may log in over SSH (`AllowGroups ssh-users`) — sshd rejects anyone else *before* the auth stack runs, so a service account or a stale login can't be brute-forced over SSH if it can't reach SSH at all. **The lockout guard**: the admin user is added to the group first, and if there is no `--admin-user` the step is **skipped entirely** — an `AllowGroups` that no live account satisfies would lock everyone out. Own drop-in (`96-hardening-access.conf`), validated with `sshd -t` and reverted on failure, like every other sshd change here. |
| **Service sandboxing** | A systemd hardening drop-in for the `fail2ban` unit — `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=full`, `ProtectHome`, `ProtectKernelTunables`, `ProtectControlGroups`, `RestrictSUIDSGID`. A network daemon that shells out to `ufw` is a juicy foothold if it's ever exploited; systemd boxes it in for free. The set is **conservative on purpose** — fail2ban still needs the network and to run `ufw`, so no `PrivateNetwork` / `ProtectSystem=strict` / kernel-module lockout that would break it. If the unit won't start with the drop-in it's reverted (`systemctl daemon-reload` + restart, then a start check) — a hardening step must never leave the intrusion-prevention service down. |
| **Journald persistence** | CIS 4.2.2: a `journald.conf.d` drop-in makes `systemd-journald` keep logs on disk (`Storage=persistent`) so they survive a reboot — the volatile default keeps them in a `/run` tmpfs and loses everything on restart, so the one event you most want after an incident (the compromise that forced the reboot) is gone. Plus `Compress=yes` and `SystemMaxUse=200M` so the persistent journal can't fill the disk. `/var/log/journal` is created up front so the very next boot is already persistent instead of one reboot behind. |
| **Su restriction** | CIS 5.7: `su` hands out a whole root shell against a shared password; `sudo` logs every command and is revocable per user. A `pam_wheel` line in `/etc/pam.d/su` gates `su` on membership of a dedicated group, checked by **real uid** (`use_uid` — `getlogin()` can be spoofed through utmp), so a stolen root password alone no longer buys a shell. The group is created **empty on purpose** (as CIS suggests): sudo is the sanctioned path, and any member is a deliberate, auditable exception. Root keeps its own `su` — `pam_rootok` sits above the check. |
| **System accounts** | CIS 5.4.2 / 6.2.9: a service account with a real shell is a login waiting to happen — a valid `su` target, a valid SSH target while password auth lives, and the landing spot of choice once the daemon running as it is compromised. Every account with `uid <= 999` gets **two independent gates**: a `/usr/sbin/nologin` shell and a locked password. Either alone leaks — a locked password still lets in anything that skips PAM's auth stage (an SSH key dropped in `~/.ssh`, `su -` from root, a cron entry), and a nologin shell still lets a password-only check "succeed" for services that authenticate without spawning a shell. Together the account can own files and run daemons, but nobody can *be* it interactively. **Never touched**: root (locking it bricks single-user recovery), the `--admin-user`, anything with `uid >= 1000` (humans), and the `sync`/`shutdown`/`halt` trio whose whole purpose is a login shell — the exceptions CIS itself carves out. Reversible per account with `passwd -u`. |
| **Log file permissions** | CIS 4.2.3: logs are the forensic record *and* a reconnaissance goldmine — `auth.log` says who logs in from where and which attempts fail, `dpkg.log` lists the exact package versions to shop CVEs for (and ships world-readable on stock Debian). Everything under `/var/log` loses group-write and **all world access** (`g-wx,o-rwx`), keeping owner bits and ownership so services keep writing their own logs. The deliberate exceptions are the **utmp family**, world-readable *by design* so `who`/`last` work for non-root users: `wtmp`/`lastlog` stay `664 root:utmp`, `btmp` gets `660` — failed logins famously record usernames typed into the password prompt. Second half: an `rsyslog.d` drop-in pins `FileCreateMode 0640` so **tomorrow's** files are born restricted too (loaded after `rsyslog.conf`, it wins over a drifted mode there — a sweep without it rots on the next logrotate cycle). Skipped gracefully on journald-only boxes, whose journal files are `0640` by design. |
| **Logrotate permissions** | CIS 4.4: rotation is the **third way a log is born** (after the service and rsyslog, both covered above) — logrotate's `create` directive decides the mode of every file it re-creates, and stock Debian offends on its own: the global `create` is **bare** (it *clones* the rotated file's mode, drift included) and the `dpkg`/`alternatives` snippets say `create 644 root root`, so the very `dpkg.log` the sweep just tightened comes back world-readable on the next monthly cycle. The step pins the global to `create 0640` (**mode only** — owner/group keep coming from each file, so services keep writing their own logs) and strips `g-wx,o-rwx` from every loose `create` in `logrotate.d`, keeping owner/group arguments untouched. The `wtmp`/`btmp` snippets keep their by-design utmp split (`664`/`660 root:utmp`) — the same exception the sweep makes. Edits are validated with logrotate's own parser and restored if it rejects them; verify **forces a real rotation** and proves the re-created files are born `0640`. Skipped gracefully when logrotate isn't installed. |
| **Audit daemon** | CIS 4.1: the logging chapter's last piece — journald keeps the logs, the sweep guards them, logrotate re-creates them right; **auditd records WHO touched the crown jewels**, at the kernel, as it happens (AIDE notices a change by the next daily check; the audit trail names the process, uid and syscall the moment it happened). A staged ruleset (`/etc/audit/rules.d/hardening.rules`, `0640 root:root`) watches the account database (`-k identity`), sudoers (`-k scope`), sshd config including this repo's own drop-ins (`-k sshd`), time manipulation — log-forgery 101 — on both syscall arches plus `/etc/localtime` (`-k time-change`), kernel module syscalls (`-k modules`), and the audit config and logs themselves. `auditd.conf` keeps history instead of rotating it away (`max_log_file_action = keep_logs`) and shouts to syslog when disk runs low. The split that keeps it honest: the **promise is configuration** — package installed, rules staged, service enabled at boot — because the audit netlink is **not namespaced**: a container (this repo's CI node, WSL) gets `EPERM` by construction, while any real server compiles and loads the staged rules on its next boot. So verify runs the **real toolchain** instead of pretending: `augenrules` must land every key in the merged `audit.rules`. No `-e 2` immutable flag on purpose — the script stays re-runnable; flip it yourself once the ruleset is final. |
| **Home directory permissions** | CIS 6.2: a 755 home — still the default on many distros — hands **every local account** a reading pass over `~/.ssh`, `~/.aws`, `~/.kube` and the shell history with the password someone typed at the wrong prompt; group-write is worse, because a writable `~/.bashrc` is code execution as that user at the next login. Every interactive home (uid ≥ 1000 with a real shell, plus root) is trimmed to **750 or tighter** — mode only, ownership untouched: adopting a home to root would break the login it exists for; a home already at 700/750 isn't touched at all. And the legacy dotfiles that grant access with **no password** are removed: `.netrc` (cleartext logins that ftp/curl happily read), `.rhosts`/`.shosts` (rlogin-era trust files), `.forward` (silently reroutes a user's mail). All four are relics; none has a legitimate place on a hardened server. |
| **Process isolation** | Your neighbour's process is private — two doors, because each one alone leaks. **`/proc` with `hidepid`**: on a stock box `ps aux` hands every local account a full inventory of what runs and as whom, plus any secret sitting in someone else's command line (`mysql -pSecret`, a curl with a token in the URL, a backup script's `--password=`). hidepid=2 shows a user only their own processes; root — and an optional monitoring group via `PROCESS_HIDEPID_GID` — still sees everything. Pinned in `/etc/fstab` (Debian ships **no** `/proc` line, so without the pin the hardening dies at the next reboot) and remounted live only when the option isn't already in effect; an admin who chose `hidepid=1` keeps that choice instead of getting a contradictory second copy of the key. **`kernel.yama.ptrace_scope=1`**: hidepid hides the process *list*, ptrace_scope stops reading a process's *memory* — with the default `0`, anything running as you can attach to your browser and lift its session cookies, or to `ssh-agent`/`gpg-agent` and lift the keys, **with no root at all**; `1` allows only a direct parent, which is all a debugger launched from your shell needs. Its own drop-in (`/etc/sysctl.d/99-hardening-process.conf`), not the step-6 sysctl file, so `--no-process-isolation` and `--no-sysctl` stay independent. Both halves warn instead of failing where the kernel won't allow them (a `/proc` that can't be remounted, a kernel built without Yama). |

### Lockout guard

The script **will not disable SSH password authentication** unless it finds an
`authorized_keys` for the target user (or root) — so a typo can't lock you out.
Pass `--pubkey` to install a key first, or `--force-no-password` if you have
console access and know what you're doing.

## What this demonstrates

- **Automation & idempotency** — every step checks state before acting; safe to
  re-run. Honours a real `--dry-run`.
- **Linux security baseline** — SSH hardening, host firewall, brute-force
  protection and patch automation, the way you'd actually set up a server.
- **Defensive scripting** — `set -euo pipefail`, root/OS preflight checks,
  config validation (`sshd -t`) before reload, and a lockout safeguard.

## Usage

```bash
git clone https://github.com/DannyRuizB/debian-hardening.git
cd debian-hardening
chmod +x harden.sh

# See exactly what would change — touches nothing:
sudo ./harden.sh --dry-run

# Typical run: create an admin user with your key, harden everything,
# open ports 80/443 for a web server:
sudo ./harden.sh \
  --admin-user danny \
  --pubkey "$(cat ~/.ssh/id_ed25519.pub)" \
  --allow-port 80/tcp --allow-port 443/tcp
```

### Options

```
--ssh-port N           SSH port to allow/protect (default: 22)
--admin-user NAME      create/ensure this sudo user before locking SSH
--pubkey "ssh-... "    public key to install for --admin-user
--allow-port N[/proto] extra port to open in UFW (repeatable)
--no-<step>            skip any single step — one flag per table row above,
                       e.g. --no-ssh, --no-aide, --no-module-blacklist
                       (the full list: ./harden.sh -h)
--no-passwordless-sudo don't grant --admin-user passwordless sudo
--force-no-password    disable password auth even with no key (DANGEROUS)
--dry-run              print what would change, do nothing
-y, --yes              don't ask for confirmation
-h, --help             show help
```

## Verify after running

```bash
sshd -T | grep -Ei 'passwordauth|permitroot|^port'
sudo ufw status verbose
sudo fail2ban-client status sshd
```

## Targets

Written for Debian 12 (Bookworm) and Debian 13 (Trixie), and should work on
Debian-based distros that ship `ufw`, `fail2ban` and `unattended-upgrades`. The
script is checked in CI (`bash -n`, ShellCheck and a bats unit suite); always
run it with `--dry-run` first against a host you can reach by console.

## Tests

A [bats](https://github.com/bats-core/bats-core) suite covers the script's
parsing and helpers without touching the host. `main` is guarded behind a
`BASH_SOURCE` check, so the tests `source` the script to exercise `parse_args`
(flags, defaults, `--allow-port` accumulation, `--no-*` toggles) and
`has_authorized_key` (the lockout guard's key check, with `getent` stubbed to a
temp home), plus the CLI surface (`--help`, unknown options, the root check).

```bash
bats test/          # needs bats-core (apt install bats, or brew install bats-core)
```

### End-to-end (it actually hardens a box)

Linting proves the script *parses*; the [`e2e` workflow](.github/workflows/e2e.yml)
proves it *hardens*. On every push it boots a disposable Debian 13 systemd
container, runs `harden.sh` inside it for real, runs it again to prove
idempotence (the config files' hashes must not change), and then attacks the
result from the outside with [`test/verify.sh`](test/verify.sh): root login
refused, password auth not offered, UFW active, and a live brute-force burst
that must end with the attacker **banned by Fail2Ban**. Reproduce it locally:

```bash
cd test
./node.sh up && ./node.sh wait
docker exec db-harden-node bash /root/harden.sh --admin-user opsadmin \
  --pubkey "$(cat .ssh_ci/id_ci.pub)" -y
./verify.sh
./node.sh down
```

> This e2e caught a real bug: on OpenSSH ≥ 9.8 the auth work moved to an
> `sshd-session` process, so Fail2Ban's stock `_COMM=sshd` journal match missed
> every failure and never banned. The jail now matches on the ssh unit instead.

The same run also covers **flag behaviour** with
[`test/scenarios.sh`](test/scenarios.sh) — the lockout guard (no key → password
auth stays on; `--force-no-password` overrides it), a custom `--ssh-port` (sshd
and UFW stay in sync), `--allow-port`, and `--no-fail2ban`.

### Security lab

Beyond the CI checks, `test/` is a small hands-on security lab against the
hardened node — each script self-contained and local:

| Script | What it does |
|---|---|
| [`redteam.sh`](test/redteam.sh) | *Attacks* the node with a valid key **and** the correct passwords — 7 attacks repelled, 0 leaks ([REDTEAM.md](test/REDTEAM.md)) |
| [`forensics.sh`](test/forensics.sh) | Blue-team: stages an attack and reconstructs it from the node's logs — who, which accounts, how Fail2Ban responded ([FORENSICS.md](test/FORENSICS.md)) |
| [`before_after.sh`](test/before_after.sh) | Same attack against a stock Debian node vs the hardened one, side by side ([BEFORE_AFTER.md](test/BEFORE_AFTER.md)) |
| [`attacks.sh`](test/attacks.sh) | Catalogue of recon/login techniques — banner grab, port scan, user enumeration, dictionary — each bouncing off its control ([ATTACKS.md](test/ATTACKS.md)) |
| [`audit.sh`](test/audit.sh) | Grades the node against a CIS-style checklist and scores it — drove the SSH drop-in's extra hardening (now 100%) ([AUDIT.md](test/AUDIT.md)) |
| [`scenarios.sh`](test/scenarios.sh) | Asserts the flags behave (lockout guard, custom port, extra ports, skips) ([SCENARIOS.md](test/SCENARIOS.md)) |

> ⚠️ Always run with `--dry-run` first on a host you can reach by console
> (e.g. the Proxmox/hypervisor shell) the first time, in case of a custom SSH
> setup.

## About

Built by **[Danny Ruiz](https://github.com/DannyRuizB)** — systems & network
administrator (ASIR, *Administración de Sistemas Informáticos en Red*).
[More projects →](https://github.com/DannyRuizB?tab=repositories)

## License

MIT — see [LICENSE](LICENSE).
