# Scenario tests — the flags actually behave

`verify.sh` proves a default `harden.sh` run hardens a box. But the script has a
dozen flags, and the most important one — the **lockout guard** — is a promise
you don't want to find out is broken from a locked-out console. [`scenarios.sh`](scenarios.sh)
hardens a fresh throwaway container per scenario with a different flag set and
asserts the effective state from inside.

## Run it

```bash
cd test
./node.sh up            # builds the image once
./scenarios.sh
```

## The scenarios

| # | Flags | Asserts |
|---|-------|---------|
| 1 | *(none, no key)* | **lockout guard**: no usable key → `PasswordAuthentication` stays `yes` (you're not locked out) |
| 2 | `--force-no-password` | override: password auth forced `no` even without a key |
| 3 | `--admin-user … --pubkey …` | a key present → `PasswordAuthentication no` (key-only) |
| 4 | `--ssh-port 2244` | `sshd` listens on 2244 **and** UFW allows 2244 (they stay in sync) |
| 5 | `--allow-port 80/tcp` | UFW opens the extra port |
| 6 | `--no-fail2ban` | Fail2Ban is skipped, but the rest of the baseline still applies |
| 7 | `--no-ssh-policies` | session policies skipped (TCP forwarding stays at its default), the rest still applies |
| 8 | `--no-coredump-limits` | core dump limits skipped (no limits.d drop-in), the rest still applies |
| 9 | `--no-umask-tmout` | umask / TMOUT drop-ins skipped, the rest still applies |
| 10 | `--no-cron-restrictions` | no `cron.allow` / spool changes, the rest still applies |
| 11 | `--no-password-policy` | `pwquality.conf` untouched (no `minlen = 14`), the rest still applies |
| 12 | `--no-aide` | no AIDE config / baseline written, the rest still applies |
| 13 | `--no-rkhunter` | no rkhunter baseline / timer written, the rest still applies |
| 14 | `--no-ssh-access` | no `AllowGroups` drop-in written, the rest still applies |
| 15 | (no `--admin-user`) | the `AllowGroups` step refuses to run — an allow-list nobody satisfies would lock everyone out |
| 16 | `--no-service-sandboxing` | no systemd drop-in for fail2ban, the rest still applies |
| 17 | `--no-journald` | no journald drop-in written, the rest still applies |
| 18 | `--no-su-restriction` | no `sugroup` group and `pam_wheel` stays inactive in `pam.d/su`, the rest still applies |
| 19 | `--no-log-permissions` | a planted world-readable log keeps its world-read bit (the file-permissions sweep only strips `o+w`) and no rsyslog drop-in is written, the rest still applies |
| 20 | `--no-logrotate-perms` | stock Debian is its own offender: the bare global `create` and dpkg's `create 644 root root` must stay exactly as the distro shipped them, the rest still applies |
| 21 | `--no-home-permissions` | a planted 755 home and its `.netrc` credential relic both survive untouched (no other step looks at homes), the rest still applies |
| 22 | `--no-process-isolation` | a planted open `/proc` (no hidepid) and `ptrace_scope=0` both survive, and no ptrace drop-in is written, the rest still applies |
| 23 | `--no-guess-cost` | planted weak values (`YESCRYPT_COST_FACTOR 5`, `FAIL_DELAY 0`) survive untouched and `pam_faildelay` stays out of `common-auth` — while the password-policy step still pins `ENCRYPT_METHOD`, proving the two login.defs steps are independent |
| 24 | `--no-root-path` | planted PATH offenders (a world-writable directory, an empty entry) survive untouched in `login.defs` and `/etc/profile`, and the loose directory keeps its mode — no other step looks at PATH, the rest still applies |
| 25 | `--no-apt-sandboxing` | no sandbox drop-in is written and the `apt-daily-upgrade` unit keeps its stock (unconfined) `NoNewPrivileges=no` — the rest still applies |
| 26 | `--no-pw-history` | no `pam_pwhistory` profile is written and `common-password` keeps its stock stack (old passwords stay reusable), the rest still applies |
| 27 | `--no-ssh-crypto` | no crypto drop-in is written and `sshd` still *offers* `hmac-sha1` (the stock negotiation lists survive), the rest still applies |
| 28 | `--no-legacy-protocols` | a planted `telnet` client survives the run untouched (no other step purges packages), the rest still applies |
| 29 | `--no-fs-protected` | planted `fs.protected_*=0` values survive and no `99-hardening-fs.conf` drop-in is written (no other step touches them), the rest still applies |
| 30 | `--no-account-hygiene` | the planted NIS `+` entry, the hash sitting in `/etc/passwd` and the empty password all survive — pressing Enter still authenticates (behavioral, `nullok`) — while the rest still applies |
| 31 | `--no-exploit-mitigations` | the planted `randomize_va_space=0` survives and no `99-hardening-exploit.conf` drop-in is written, the rest still applies (the scenario restores full ASLR itself: these sysctls are host-global) |

**Result: 76/76 checks pass.**

## Why the lockout guard scenario matters most

The headline promise of this script is "won't lock you out". Scenario 1 is the
proof: run with no SSH key anywhere, and instead of blindly disabling password
auth (which would strand you if the key was missing or mistyped), the script
keeps `PasswordAuthentication yes` and warns you. Scenario 2 shows the escape
hatch — `--force-no-password` — for when you *do* have console access and want
key-only regardless. Getting these two wrong is how a hardening script turns
into a lockout, so they're tested explicitly.

## Honesty

Each scenario checks the *effective configuration* the flag produces (via
`sshd -T`, `ufw status`, `systemctl`), not a live login for every case — the
end-to-end login path is already covered by `verify.sh`. Scenarios run their
containers without publishing ports; they inspect state with `docker exec`.
