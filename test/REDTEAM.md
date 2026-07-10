# Red-team report — attacking the hardened node

The adversarial companion to `verify.sh`. Where that one *asserts* the config,
[`redteam.sh`](redteam.sh) **attacks** a freshly hardened node from the outside
and records what the server does. Everything runs locally: the target is the
throwaway systemd container from [`node.sh`](node.sh) on `127.0.0.1:2222`,
attacked from the same machine.

To make it a fair fight, the attacker is handed the strongest possible
position: an SSH key of their own **and** the correct account passwords
(`opsadmin:SuperSecret123`, `root:ToorRoot456`). The hardening still has to
turn every attempt away.

## Run it

```bash
cd test
./node.sh up && ./node.sh wait
docker exec db-harden-node bash /root/harden.sh --admin-user opsadmin \
  --pubkey "$(cat .ssh_ci/id_ci.pub)" -y
./redteam.sh
./node.sh down
```

## What gets attacked, and the result

| # | Attack | What the server did | Verdict |
|---|--------|--------------------|---------|
| Control | Legit admin logs in with their key | In, with working sudo | ✅ access preserved |
| 1 | `root` with a **valid** authorized key | denied — `PermitRootLogin no` overrides the key | 🛡️ blocked |
| 2 | `opsadmin` with an **unauthorized** key | `Permission denied (publickey)` | 🛡️ blocked |
| 3 | `root` with an unauthorized key | `Permission denied (publickey)` | 🛡️ blocked |
| 4 | Login as a non-existent user `hacker` | `Permission denied (publickey)` | 🛡️ blocked |
| 5 | Password auth with the **correct** password | server offers only `publickey` — never prompts | 🛡️ blocked |
| 6 | Brute force: waves of failed logins | Fail2Ban bans the source IP after 5 tries | 🛡️ blocked |
| 7 | Banned IP retries with a **valid** key | rejected at the firewall before SSH is reached | 🛡️ blocked |
| Recovery | Admin unbans + restarts Fail2Ban | Access restored | ✅ reversible |

**Result: 7 attacks repelled, 0 leaks.**

## Things worth remembering

- **A valid key is not enough for root** — in attack #1 the key *is* in
  `/root/.ssh/authorized_keys`, yet `PermitRootLogin no` refuses it first.
- **Knowing the password buys nothing** — the server advertises only
  `publickey`, so #5 never even reaches a password prompt.
- **A ban outlives a plain unban** — the bantime is still running and recent
  failures sit inside `findtime`, so Fail2Ban re-bans on the next tick. Real
  recovery is *unban + restart the service*, which the Recovery step does.

## Honesty

This proves the *configuration* resists these attacks. It is not a full
penetration test (no kernel/service CVEs, no local privilege escalation once
inside, single-origin brute force rather than distributed).
