# Compliance audit — grading the node against a CIS-style checklist

[`audit.sh`](audit.sh) scores the hardened node against a broader checklist than
`verify.sh` uses. `verify.sh` confirms *the baseline was applied*; this grades a
wider set of best practices — deliberately including ones the baseline may not
cover — so the score is honest and any failures read as a to-do list.

## Run it

```bash
cd tests
./node.sh up && ./node.sh wait

docker exec db-harden-node bash /root/harden.sh --admin-user opsadmin --pubkey "$(cat .ssh_ci/id_ci.pub)" -y
./audit.sh
```

## Grading

Each check is `PASS` (control in place), `WARN` (a CIS hardening not applied —
improvable) or `FAIL` (a core control missing — serious). The score weights
`WARN` as a half-point:

```
Score = (PASS + 0.5*WARN) / total * 100
```

Categories: SSH authentication (core), SSH hardening extras (CIS), firewall,
intrusion prevention, patch management, kernel parameters (CIS network),
account policies (CIS), filesystem mount options (CIS), warning banners (CIS),
sudo hardening (CIS), and accounts & files.

## What it caught — and the fix

On first run the baseline scored **89% (14 PASS, 4 WARN, 0 FAIL)**. Zero core
failures, but four CIS extras that the SSH drop-in didn't set:

| WARN | Was | CIS wants |
|---|---|---|
| `MaxAuthTries` | 6 | ≤ 4 |
| `X11Forwarding` | yes | no |
| `LoginGraceTime` | 120 | ≤ 60 |
| `ClientAliveInterval` | 0 (no idle timeout) | 300 |

So the audit became a to-do list, and `harden.sh`'s SSH drop-in now sets all
four (`MaxAuthTries 4`, `X11Forwarding no`, `LoginGraceTime 60`,
`ClientAliveInterval 300` + `ClientAliveCountMax 3`). Re-hardening and
re-auditing:

```
 Score: 18 PASS, 0 WARN, 0 FAIL  ->  100% compliant
```

Idempotence held (the drop-in's hash is unchanged on a second run) and the e2e
`verify.sh` still passes — the extra directives tighten the config without
changing key-only behaviour. That's the whole loop:
**audit → find gaps → remediate → re-audit.**

When the baseline later gained step 6 (kernel hardening via sysctl), the audit
grew with it: a **Kernel parameters (CIS network)** section now grades seven of
the keys the drop-in promises (ICMP redirects, source routing, rp_filter, SYN
cookies, `dmesg_restrict`, `suid_dumpable`). Step 7 (account policies) added an
**Account policies (CIS)** section with four more: password max/min age, expiry
warning, and the inactivity lock for new accounts. Step 8 (mount options) added
a **Filesystem mount options (CIS)** section with four more: `/dev/shm` mounted
`nodev` / `nosuid` / `noexec`, plus the fstab pin that makes the options survive
a reboot. Step 9 (warning banners) added a **Warning banners (CIS 1.7)** section
with four more: sshd presents a pre-auth banner, `/etc/issue` and
`/etc/issue.net` leak no OS/kernel info, and the banner file permissions are
sane. Step 10 (sudo hardening) added a **Sudo hardening (CIS 5.3)** section
with four more: sudo installed, `use_pty`, the dedicated logfile, and the
drop-in's permissions. Step 11 (SSH session policies) added an **SSH: session
policies (CIS 5.2)** section with eight more: TCP and agent forwarding off,
`MaxSessions` / `MaxStartups` caps, `LogLevel VERBOSE`, no user environment,
no host-based auth, rhosts ignored. Step 12 (core dump limits) added a
**Core dumps (CIS 1.5)** section with four more: `* hard core 0` and root's
own `hard core 0` line (`*` never matches root), plus systemd-coredump capped
off (`Storage=none`, `ProcessSizeMax=0`). Step 13 (umask & shell timeout)
added an **Umask & shell timeout (CIS 5.4)** section with four more:
`UMASK 027` in login.defs, the profile.d umask drop-in, a readonly
`TMOUT` at or under 900 seconds, and its export. Step 14 (cron restrictions)
added a **Cron restrictions (CIS 5.1)** section with four more: `/etc/crontab`
at `600 root:root`, the `cron.*` drop-in dirs uniformly `700 root:root`, a
root-only `cron.allow`, and `cron.deny` gone (allow-list model). Current
score on a freshly hardened node:

```
 Score: 61 PASS, 0 WARN, 0 FAIL  ->  100% compliant
```

## Honesty

This is a lightweight, SSH-and-service-focused checklist, not a full CIS
Benchmark or a Lynis run. 100% here means "compliant with *these* checks" — it
doesn't cover auditd, AppArmor,
or the dozens of other items a full benchmark grades. It's a useful, honest
scorecard for the controls this baseline is actually responsible for.
