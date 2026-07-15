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
--no-ssh | --no-ufw | --no-fail2ban | --no-autoupdates | --no-sysctl | --no-account-policies | --no-mount-options   skip a step
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
