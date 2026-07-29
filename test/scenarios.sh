#!/usr/bin/env bash
# =============================================================================
# Scenario tests for harden.sh's flags. verify.sh proves the default run
# hardens a box; this proves the OPTIONS behave — the lockout guard, a custom
# SSH port, extra open ports, and skipping a step. Each scenario hardens a
# fresh throwaway container with a different flag set and asserts the effective
# state from inside (sshd -T, ufw status, systemctl).
#
# Needs the node image built once (./node.sh up), then:
#   ./scenarios.sh
#
# All local and disposable; every scenario cleans up its own container.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"

IMAGE="db-harden-node"
KEY=".ssh_ci/id_ci"
pass=0; fail=0
P() { printf "    \033[32mPASS\033[0m %s\n" "$1"; pass=$((pass+1)); }
F() { printf "    \033[31mFAIL\033[0m %s (got: %s)\n" "$1" "$2"; fail=$((fail+1)); }

# A key to hand to --pubkey when a scenario needs one.
[ -f "$KEY" ] || { mkdir -p .ssh_ci; chmod 700 .ssh_ci
  ssh-keygen -t ed25519 -f "$KEY" -N "" -C scenarios >/dev/null 2>&1; }
PUBKEY=$(cat "$KEY.pub")

# Ensure the node image exists (built by node.sh up); build it if not.
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker build -t "$IMAGE" . >/dev/null

# fresh_node NAME — boot a clean systemd container with harden.sh inside.
fresh_node() {
  local name="$1"
  docker rm -f "$name" >/dev/null 2>&1
  docker run -d --name "$name" --hostname "$name" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw "$IMAGE" >/dev/null
  sleep 4
  docker cp ../harden.sh "$name:/root/harden.sh"
}
# val NAME KEY — effective sshd config value
val() { docker exec "$1" sshd -T 2>/dev/null | awk -v k="$2" 'tolower($1)==k{print $2; exit}'; }

echo "============================================================="
echo " SCENARIO TESTS — harden.sh flag behaviour"
echo "============================================================="

echo "-- 1. Lockout guard: no key -> password auth STAYS on ------"
fresh_node s1 >/dev/null
docker exec s1 bash /root/harden.sh -y >/dev/null 2>&1
got=$(val s1 passwordauthentication)
[ "$got" = yes ] && P "no key found -> PasswordAuthentication stays 'yes'" \
                 || F "PasswordAuthentication should stay yes without a key" "$got"
docker rm -f s1 >/dev/null 2>&1

echo "-- 2. Lockout guard override: --force-no-password ----------"
fresh_node s2 >/dev/null
docker exec s2 bash /root/harden.sh --force-no-password -y >/dev/null 2>&1
got=$(val s2 passwordauthentication)
[ "$got" = no ] && P "--force-no-password -> PasswordAuthentication 'no' even without a key" \
                || F "--force-no-password should force 'no'" "$got"
docker rm -f s2 >/dev/null 2>&1

echo "-- 3. With a key -> password auth is disabled --------------"
fresh_node s3 >/dev/null
docker exec s3 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" -y >/dev/null 2>&1
got=$(val s3 passwordauthentication)
[ "$got" = no ] && P "key installed -> PasswordAuthentication 'no'" \
                || F "with a key it should be 'no'" "$got"
docker rm -f s3 >/dev/null 2>&1

echo "-- 4. Custom SSH port: --ssh-port 2244 ---------------------"
fresh_node s4 >/dev/null
docker exec s4 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --ssh-port 2244 -y >/dev/null 2>&1
got=$(val s4 port)
[ "$got" = 2244 ] && P "sshd listens on the custom port (Port 2244)" \
                  || F "sshd Port should be 2244" "$got"
if docker exec s4 ufw status 2>/dev/null | grep -qE "^2244/tcp +ALLOW"; then
  P "UFW allows the custom port 2244"; else
  F "UFW should allow 2244/tcp" "$(docker exec s4 ufw status 2>/dev/null | grep -i 2244 || echo none)"; fi
docker rm -f s4 >/dev/null 2>&1

echo "-- 5. Extra port: --allow-port 80/tcp ----------------------"
fresh_node s5 >/dev/null
docker exec s5 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --allow-port 80/tcp -y >/dev/null 2>&1
if docker exec s5 ufw status 2>/dev/null | grep -qE "^80/tcp +ALLOW"; then
  P "UFW opens the extra port 80/tcp"; else
  F "UFW should allow 80/tcp" "$(docker exec s5 ufw status 2>/dev/null | grep -i '80/tcp' || echo none)"; fi
docker rm -f s5 >/dev/null 2>&1

echo "-- 6. Skip a step: --no-fail2ban ---------------------------"
fresh_node s6 >/dev/null
docker exec s6 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-fail2ban -y >/dev/null 2>&1
if docker exec s6 systemctl is-active fail2ban 2>/dev/null | grep -qx active; then
  F "--no-fail2ban should not run fail2ban" "active"; else
  P "--no-fail2ban -> fail2ban not running"; fi
# ...but the rest of the baseline still applied:
got=$(val s6 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s6 >/dev/null 2>&1

echo "-- 7. Skip a step: --no-ssh-policies -----------------------"
fresh_node s7 >/dev/null
docker exec s7 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-ssh-policies -y >/dev/null 2>&1
got=$(val s7 allowtcpforwarding)
[ "$got" = yes ] && P "--no-ssh-policies -> TCP forwarding left at its default (yes)" \
                 || F "--no-ssh-policies should leave forwarding alone" "$got"
# ...and the default run does lock it down:
got=$(val s7 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s7 >/dev/null 2>&1

echo "-- 8. Skip a step: --no-coredump-limits --------------------"
fresh_node s8 >/dev/null
docker exec s8 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-coredump-limits -y >/dev/null 2>&1
if docker exec s8 test -f /etc/security/limits.d/99-hardening-coredumps.conf 2>/dev/null; then
  F "--no-coredump-limits should not write the limits drop-in" "file exists"; else
  P "--no-coredump-limits -> no core-dump limits drop-in"; fi
# ...but the rest of the baseline still applied:
got=$(val s8 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s8 >/dev/null 2>&1

echo "-- 9. Skip a step: --no-umask-tmout ------------------------"
fresh_node s9 >/dev/null
docker exec s9 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-umask-tmout -y >/dev/null 2>&1
if docker exec s9 test -f /etc/profile.d/99-hardening-tmout.sh 2>/dev/null; then
  F "--no-umask-tmout should not write the TMOUT drop-in" "file exists"; else
  P "--no-umask-tmout -> no umask/TMOUT drop-ins"; fi
# ...but the rest of the baseline still applied:
got=$(val s9 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s9 >/dev/null 2>&1

echo "-- 10. Skip a step: --no-cron-restrictions -----------------"
fresh_node s10 >/dev/null
docker exec s10 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-cron-restrictions -y >/dev/null 2>&1
if docker exec s10 test -f /etc/cron.allow 2>/dev/null; then
  F "--no-cron-restrictions should not write cron.allow" "file exists"; else
  P "--no-cron-restrictions -> no cron.allow / spool changes"; fi
# ...but the rest of the baseline still applied:
got=$(val s10 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s10 >/dev/null 2>&1

echo "-- 11. Skip a step: --no-password-policy -------------------"
fresh_node s11 >/dev/null
docker exec s11 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-password-policy -y >/dev/null 2>&1
if docker exec s11 grep -qE '^minlen = 14' /etc/security/pwquality.conf 2>/dev/null; then
  F "--no-password-policy should not touch pwquality.conf" "minlen = 14 present"; else
  P "--no-password-policy -> pwquality.conf untouched"; fi
# ...but the rest of the baseline still applied:
got=$(val s11 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s11 >/dev/null 2>&1

echo "-- 12. Skip a step: --no-aide ------------------------------"
fresh_node s12 >/dev/null
docker exec s12 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-aide -y >/dev/null 2>&1
if docker exec s12 test -f /etc/aide/hardening.conf 2>/dev/null; then
  F "--no-aide should not write the AIDE config" "file exists"; else
  P "--no-aide -> no AIDE config / baseline"; fi
# ...but the rest of the baseline still applied:
got=$(val s12 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s12 >/dev/null 2>&1

echo "-- 13. Skip a step: --no-rkhunter --------------------------"
fresh_node s13 >/dev/null
docker exec s13 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-rkhunter -y >/dev/null 2>&1
if docker exec s13 test -f /etc/systemd/system/rkhunter-check.timer 2>/dev/null; then
  F "--no-rkhunter should not write the rkhunter timer" "file exists"; else
  P "--no-rkhunter -> no rkhunter baseline / timer"; fi
# ...but the rest of the baseline still applied:
got=$(val s13 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s13 >/dev/null 2>&1

echo "-- 14. Skip a step: --no-ssh-access ------------------------"
fresh_node s14 >/dev/null
docker exec s14 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-ssh-access -y >/dev/null 2>&1
if docker exec s14 test -f /etc/ssh/sshd_config.d/96-hardening-access.conf 2>/dev/null; then
  F "--no-ssh-access should not write the AllowGroups drop-in" "file exists"; else
  P "--no-ssh-access -> no AllowGroups drop-in"; fi
# ...but the rest of the baseline still applied:
got=$(val s14 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s14 >/dev/null 2>&1

echo "-- 15. Guard: no --admin-user -> AllowGroups is NOT written -"
fresh_node s15 >/dev/null
# No --admin-user: the step must refuse (an AllowGroups nobody satisfies
# would lock everyone out) while the rest of the baseline still runs.
docker exec s15 bash /root/harden.sh -y >/dev/null 2>&1
if docker exec s15 test -f /etc/ssh/sshd_config.d/96-hardening-access.conf 2>/dev/null; then
  F "AllowGroups must not be written without an admin user" "file exists"; else
  P "no --admin-user -> AllowGroups skipped (lockout guard)"; fi
docker rm -f s15 >/dev/null 2>&1

echo "-- 16. Skip a step: --no-service-sandboxing ----------------"
fresh_node s16 >/dev/null
docker exec s16 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-service-sandboxing -y >/dev/null 2>&1
if docker exec s16 test -f /etc/systemd/system/fail2ban.service.d/99-hardening.conf 2>/dev/null; then
  F "--no-service-sandboxing should not write the fail2ban drop-in" "file exists"; else
  P "--no-service-sandboxing -> no fail2ban sandbox drop-in"; fi
# ...but the rest of the baseline still applied:
got=$(val s16 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s16 >/dev/null 2>&1

echo "-- 17. Skip a step: --no-journald --------------------------"
fresh_node s17 >/dev/null
docker exec s17 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-journald -y >/dev/null 2>&1
if docker exec s17 test -f /etc/systemd/journald.conf.d/99-hardening.conf 2>/dev/null; then
  F "--no-journald should not write the journald drop-in" "file exists"; else
  P "--no-journald -> no journald drop-in"; fi
# ...but the rest of the baseline still applied:
got=$(val s17 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s17 >/dev/null 2>&1

echo "-- 18. Skip a step: --no-su-restriction --------------------"
fresh_node s18 >/dev/null
docker exec s18 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-su-restriction -y >/dev/null 2>&1
if docker exec s18 getent group sugroup >/dev/null 2>&1; then
  F "--no-su-restriction should not create the sugroup group" "group exists"; else
  P "--no-su-restriction -> no sugroup group"; fi
# The pam.d/su hint must stay commented out, i.e. su stays open.
if docker exec s18 grep -Eq '^auth[[:space:]]+required[[:space:]]+pam_wheel' /etc/pam.d/su 2>/dev/null; then
  F "--no-su-restriction should leave pam.d/su untouched" "pam_wheel active"; else
  P "--no-su-restriction -> pam_wheel stays inactive"; fi
# ...but the rest of the baseline still applied:
got=$(val s18 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s18 >/dev/null 2>&1

echo "-- 19. Skip a step: --no-log-permissions -------------------"
fresh_node s19 >/dev/null
# Plant a world-readable log; with the step skipped it must KEEP its world-
# read bit. (The file-permissions sweep still strips the o+w bit — that one
# guards integrity everywhere; only the log step takes world-READ away.)
docker exec s19 bash -c "touch /var/log/dh-app.log && chmod 666 /var/log/dh-app.log"
docker exec s19 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-log-permissions -y >/dev/null 2>&1
got=$(docker exec s19 stat -c %a /var/log/dh-app.log 2>/dev/null)
case "$got" in
  *4) P "--no-log-permissions -> planted log keeps its world-read bit ($got)";;
  *)  F "--no-log-permissions should leave world-read on the planted log" "$got";;
esac
if docker exec s19 test -f /etc/rsyslog.d/99-hardening.conf 2>/dev/null; then
  F "--no-log-permissions should not write the rsyslog drop-in" "file exists"; else
  P "--no-log-permissions -> no rsyslog drop-in"; fi
# ...but the rest of the baseline still applied:
got=$(val s19 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s19 >/dev/null 2>&1

echo "============================================================="
total=$((pass + fail))
echo " $pass/$total scenario checks passed"
[ "$fail" -eq 0 ] && echo " All flag scenarios behaved as documented." \
                  || { echo " Some scenarios FAILED — see above."; exit 1; }
echo "============================================================="
