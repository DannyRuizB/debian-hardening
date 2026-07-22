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

**Result: 18/18 checks pass.**

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
