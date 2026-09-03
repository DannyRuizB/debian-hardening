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

echo "-- 20. Skip a step: --no-logrotate-perms --------------------"
fresh_node s20 >/dev/null
# Stock Debian is its own offender here: the global create is bare and the
# dpkg snippet says `create 644 root root`. With the step skipped, both must
# stay exactly as the distro shipped them.
docker exec s20 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-logrotate-perms -y >/dev/null 2>&1
if docker exec s20 grep -Eqs '^[[:space:]]*create[[:space:]]*$' /etc/logrotate.conf; then
  P "--no-logrotate-perms -> global create stays bare (stock)"; else
  F "--no-logrotate-perms should leave the bare global create alone" "$(docker exec s20 grep -E '^[[:space:]]*create' /etc/logrotate.conf 2>/dev/null)"; fi
if docker exec s20 grep -qs 'create 644 root root' /etc/logrotate.d/dpkg 2>/dev/null; then
  P "--no-logrotate-perms -> dpkg snippet keeps its stock create 644"; else
  F "--no-logrotate-perms should leave the dpkg create mode alone" "$(docker exec s20 grep create /etc/logrotate.d/dpkg 2>/dev/null)"; fi
# ...but the rest of the baseline still applied:
got=$(val s20 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s20 >/dev/null 2>&1

echo "-- 21. Skip a step: --no-home-permissions -------------------"
fresh_node s21 >/dev/null
# Plant a loose interactive home with a credential relic; with the step
# skipped both must survive untouched (no other step looks at homes — the
# file-permissions sweep only strips o+w, and 755 has no o+w to strip).
docker exec s21 bash -c "useradd --create-home --shell /bin/bash dhhome &&
  chmod 755 /home/dhhome &&
  printf 'machine example.com login dh password hunter2\n' > /home/dhhome/.netrc &&
  chown dhhome:dhhome /home/dhhome/.netrc"
docker exec s21 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-home-permissions -y >/dev/null 2>&1
got=$(docker exec s21 stat -c %a /home/dhhome 2>/dev/null)
[ "$got" = 755 ] && P "--no-home-permissions -> planted home keeps its 755" \
                 || F "--no-home-permissions should leave the 755 home alone" "$got"
if docker exec s21 test -e /home/dhhome/.netrc 2>/dev/null; then
  P "--no-home-permissions -> the .netrc relic survives"; else
  F "--no-home-permissions should not remove .netrc" "file gone"; fi
# ...but the rest of the baseline still applied:
got=$(val s21 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s21 >/dev/null 2>&1

echo "-- 22. Skip a step: --no-process-isolation ------------------"
fresh_node s22 >/dev/null
# Plant the offending state: /proc without hidepid and ptrace_scope at 0.
# With the step skipped both must stay exactly as planted — no other step
# touches /proc or yama (the step-6 sysctl drop-in doesn't carry ptrace).
docker exec s22 bash -c "mount -o remount,hidepid=0 /proc; sysctl -qw kernel.yama.ptrace_scope=0" >/dev/null 2>&1
docker exec s22 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-process-isolation -y >/dev/null 2>&1
if docker exec s22 findmnt -no OPTIONS /proc | grep -q hidepid=; then
  F "--no-process-isolation should leave /proc without hidepid" "$(docker exec s22 findmnt -no OPTIONS /proc)"; else
  P "--no-process-isolation -> /proc keeps showing every process"; fi
got=$(docker exec s22 sysctl -n kernel.yama.ptrace_scope 2>/dev/null)
[ "$got" = 0 ] && P "--no-process-isolation -> ptrace_scope stays at the planted 0" \
              || F "--no-process-isolation should leave ptrace_scope alone" "$got"
if docker exec s22 test -f /etc/sysctl.d/99-hardening-process.conf 2>/dev/null; then
  F "--no-process-isolation should not write the ptrace drop-in" "file exists"; else
  P "--no-process-isolation -> no ptrace drop-in"; fi
# ...but the rest of the baseline still applied:
got=$(val s22 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s22 >/dev/null 2>&1

echo "-- 23. Skip a step: --no-guess-cost -------------------------"
fresh_node s23 >/dev/null
# Plant the WEAK values explicitly (the stock file carries neither key).
# With the step skipped both must stay exactly as planted — and the
# password-policy step must still pin ENCRYPT_METHOD, proving the two
# login.defs steps are independent.
docker exec s23 bash -c "printf 'YESCRYPT_COST_FACTOR\t5\nFAIL_DELAY\t0\n' >> /etc/login.defs"
docker exec s23 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-guess-cost -y >/dev/null 2>&1
got=$(docker exec s23 awk '$1=="YESCRYPT_COST_FACTOR"{print $2}' /etc/login.defs 2>/dev/null)
[ "$got" = 5 ] && P "--no-guess-cost -> the planted cost factor 5 survives" \
              || F "--no-guess-cost should leave YESCRYPT_COST_FACTOR alone" "$got"
got=$(docker exec s23 awk '$1=="FAIL_DELAY"{print $2}' /etc/login.defs 2>/dev/null)
[ "$got" = 0 ] && P "--no-guess-cost -> the planted FAIL_DELAY 0 survives" \
              || F "--no-guess-cost should leave FAIL_DELAY alone" "$got"
if docker exec s23 grep -q pam_faildelay /etc/pam.d/common-auth 2>/dev/null; then
  F "--no-guess-cost should not wire pam_faildelay" "$(docker exec s23 grep pam_faildelay /etc/pam.d/common-auth)"; else
  P "--no-guess-cost -> pam_faildelay stays out of common-auth"; fi
got=$(docker exec s23 awk '$1=="ENCRYPT_METHOD"{print $2}' /etc/login.defs 2>/dev/null)
[ "$got" = YESCRYPT ] && P "the password-policy step still pinned ENCRYPT_METHOD (independent)" \
                      || F "password policy should still pin ENCRYPT_METHOD" "$got"
# ...but the rest of the baseline still applied:
got=$(val s23 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s23 >/dev/null 2>&1

echo "-- 24. Skip a step: --no-root-path --------------------------"
fresh_node s24 >/dev/null
# Plant the trap in all three PATH sources plus an empty entry. With the step
# skipped, the PATH sources must survive exactly as planted. The trap dir's
# WRITE bits must survive too — but not its exact mode: the file-permissions
# sweep still runs and adds the sticky bit to any world-writable dir it finds
# (its documented job), so 777 legitimately becomes 1777 here.
docker exec s24 bash -c "install -d -m 777 /opt/dh-path-loose &&
  sed -i 's|^ENV_SUPATH.*|ENV_SUPATH\tPATH=/opt/dh-path-loose:/usr/local/sbin::/usr/local/bin:/usr/sbin:/usr/bin|' /etc/login.defs &&
  sed -i '5s|PATH=\"[^\"]*\"|PATH=\"/opt/dh-path-loose:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\"|' /etc/profile"
docker exec s24 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-root-path -y >/dev/null 2>&1
if docker exec s24 grep -q "::" /etc/login.defs 2>/dev/null; then
  P "--no-root-path -> the planted empty entry survives in ENV_SUPATH"; else
  F "--no-root-path should leave ENV_SUPATH alone" "empty entry gone"; fi
if docker exec s24 grep -q dh-path-loose /etc/profile 2>/dev/null; then
  P "--no-root-path -> the planted entry survives in /etc/profile"; else
  F "--no-root-path should leave /etc/profile alone" "trap gone"; fi
got=$(docker exec s24 stat -Lc %a /opt/dh-path-loose 2>/dev/null)
case "$got" in
  777|1777) P "--no-root-path -> the trap dir keeps its write bits (mode $got)" ;;
  *)        F "--no-root-path should not strip the trap dir's write bits" "$got" ;;
esac
# ...but the rest of the baseline still applied:
got=$(val s24 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s24 >/dev/null 2>&1

echo "-- 25. Skip a step: --no-apt-sandboxing ---------------------"
fresh_node s25
docker exec s25 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-apt-sandboxing -y >/dev/null 2>&1
if docker exec s25 test -f /etc/systemd/system/apt-daily-upgrade.service.d/99-hardening.conf 2>/dev/null; then
  F "--no-apt-sandboxing should not write the apt sandbox drop-in" "file exists"; else
  P "--no-apt-sandboxing -> no apt sandbox drop-in"; fi
got=$(docker exec s25 systemctl show apt-daily-upgrade.service -p NoNewPrivileges --value 2>/dev/null)
[ "$got" = no ] && P "--no-apt-sandboxing -> apt updater keeps its stock (unconfined) unit" \
                || F "--no-apt-sandboxing should leave the apt unit unconfined" "$got"
# ...but the rest of the baseline still applied:
got=$(val s25 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s25 >/dev/null 2>&1

echo "-- 26. Skip a step: --no-pw-history -------------------------"
fresh_node s26
docker exec s26 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-pw-history -y >/dev/null 2>&1
if docker exec s26 test -f /usr/share/pam-configs/hardening-pwhistory 2>/dev/null; then
  F "--no-pw-history should not write the pwhistory profile" "file exists"; else
  P "--no-pw-history -> no pwhistory profile"; fi
if docker exec s26 bash -c "grep -v '^#' /etc/pam.d/common-password | grep -q pam_pwhistory" 2>/dev/null; then
  F "--no-pw-history should leave common-password without pam_pwhistory" "line present"; else
  P "--no-pw-history -> common-password keeps its stock stack (no history)"; fi
# ...but the rest of the baseline still applied:
got=$(val s26 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s26 >/dev/null 2>&1

echo "-- 27. Skip a step: --no-ssh-crypto --------------------------"
fresh_node s27
docker exec s27 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-ssh-crypto -y >/dev/null 2>&1
if docker exec s27 test -f /etc/ssh/sshd_config.d/95-hardening-crypto.conf 2>/dev/null; then
  F "--no-ssh-crypto should not write the crypto drop-in" "file exists"; else
  P "--no-ssh-crypto -> no crypto drop-in"; fi
# The stock negotiation lists survive: hmac-sha1 is still on offer (the
# natural offender this step exists to retire).
got=$(val s27 macs)
case "$got" in
  *hmac-sha1*) P "--no-ssh-crypto -> sshd still offers hmac-sha1 (stock lists intact)" ;;
  *)           F "--no-ssh-crypto should leave the stock MAC list" "$got" ;;
esac
# ...but the rest of the baseline still applied:
got=$(val s27 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s27 >/dev/null 2>&1

echo "-- 28. Skip a step: --no-legacy-protocols ------------------"
fresh_node s28
# Plant the natural offender the step exists to purge, then skip the step:
# the planted client must survive while the rest of the baseline applies.
docker exec s28 apt-get install -y --no-install-recommends telnet >/dev/null 2>&1
docker exec s28 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-legacy-protocols -y >/dev/null 2>&1
if docker exec s28 sh -c 'command -v telnet' >/dev/null 2>&1; then
  P "--no-legacy-protocols -> the planted telnet client survives"; else
  F "--no-legacy-protocols should leave telnet installed" "gone"; fi
got=$(val s28 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s28 >/dev/null 2>&1

echo "-- 29. Skip a step: --no-fs-protected ----------------------"
fresh_node s29
# Plant all four fs.protected_* weak, then skip the step: they must stay 0
# (no other step touches them) while the rest of the baseline applies.
docker exec s29 bash -c 'for f in symlinks hardlinks fifos regular; do echo 0 > /proc/sys/fs/protected_$f; done' >/dev/null 2>&1
docker exec s29 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-fs-protected -y >/dev/null 2>&1
got=$(docker exec s29 cat /proc/sys/fs/protected_symlinks 2>/dev/null)
[ "$got" = 0 ] && P "--no-fs-protected -> the planted fs.protected_symlinks=0 survives" \
               || F "--no-fs-protected should leave fs.protected_symlinks alone" "$got"
if docker exec s29 test -f /etc/sysctl.d/99-hardening-fs.conf 2>/dev/null; then
  F "--no-fs-protected should not write the drop-in" "file exists"; else
  P "--no-fs-protected -> no fs-protection drop-in written"; fi
got=$(val s29 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s29 >/dev/null 2>&1

echo "-- 30. Skip a step: --no-account-hygiene --------------------"
fresh_node s30
# Plant the three data-level logins, then skip the step: the NIS '+' entry,
# the passwd-file hash and the empty password must all survive (no other
# step touches account-database CONTENT) while the rest of the baseline
# applies. The empty-password check is behavioral: pressing Enter must
# still authenticate, nullok and all.
docker exec s30 bash -c '
  useradd --create-home --shell /bin/bash dhnopw && passwd -d dhnopw &&
  useradd --create-home --shell /bin/bash dhlegacy &&
  echo "dhlegacy:Sh4dow-Migr8-OK!9" | chpasswd &&
  h=$(grep "^dhlegacy:" /etc/shadow | cut -d: -f2) &&
  sed -i "s|^dhlegacy:x:|dhlegacy:$h:|" /etc/passwd &&
  sed -i "s|^dhlegacy:[^:]*:|dhlegacy:*:|" /etc/shadow &&
  printf "+::0:0:::\n" >> /etc/passwd' >/dev/null 2>&1
docker exec s30 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-account-hygiene -y >/dev/null 2>&1
if docker exec s30 grep -q '^+' /etc/passwd 2>/dev/null; then
  P "--no-account-hygiene -> the planted NIS '+' entry survives"; else
  F "--no-account-hygiene should leave the '+' entry alone" "gone"; fi
got=$(docker exec s30 bash -c 'grep "^dhlegacy:" /etc/passwd | cut -d: -f2 | cut -c1' 2>/dev/null)
[ "$got" = '$' ] && P "--no-account-hygiene -> the passwd-file hash stays unshadowed" \
                 || F "--no-account-hygiene should leave the passwd-file hash" "field starts with '$got'"
if docker exec s30 bash -c 'printf "\n" | pamtester login dhnopw authenticate' >/dev/null 2>&1; then
  P "--no-account-hygiene -> pressing Enter still authenticates (nullok, empty password)"; else
  F "--no-account-hygiene should leave the empty password usable" "auth refused"; fi
got=$(val s30 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s30 >/dev/null 2>&1

echo "-- 31. Skip a step: --no-exploit-mitigations ----------------"
fresh_node s31
# Plant ASLR off, then skip the step: it must stay 0 (no other step touches
# it) while the rest applies. These sysctls are HOST-GLOBAL in a privileged
# container, so the scenario restores full ASLR itself at the end — leaving
# a lab host without ASLR would be worse than the thing being tested.
docker exec s31 bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space' >/dev/null 2>&1
docker exec s31 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-exploit-mitigations -y >/dev/null 2>&1
got=$(docker exec s31 cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
[ "$got" = 0 ] && P "--no-exploit-mitigations -> the planted randomize_va_space=0 survives" \
               || F "--no-exploit-mitigations should leave ASLR alone" "$got"
if docker exec s31 test -f /etc/sysctl.d/99-hardening-exploit.conf 2>/dev/null; then
  F "--no-exploit-mitigations should not write the drop-in" "file exists"; else
  P "--no-exploit-mitigations -> no exploit-mitigation drop-in written"; fi
got=$(val s31 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker exec s31 bash -c 'echo 2 > /proc/sys/kernel/randomize_va_space' >/dev/null 2>&1
docker rm -f s31 >/dev/null 2>&1

echo "-- 32. Skip a step: --no-tmp-confinement --------------------"
fresh_node s32
docker exec s32 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-tmp-confinement -y >/dev/null 2>&1
# The dropper's move must still WORK with the step skipped: stage in /tmp, run.
if docker exec s32 bash -c 'cp /bin/true /tmp/dh-probe && /tmp/dh-probe' >/dev/null 2>&1; then
  P "--no-tmp-confinement -> a binary in /tmp still executes (step skipped)"; else
  F "--no-tmp-confinement should leave /tmp executable" "exec refused"; fi
if docker exec s32 grep -qE '^[^#].*[[:space:]]/tmp[[:space:]]' /etc/fstab 2>/dev/null; then
  F "--no-tmp-confinement should not pin /tmp in fstab" "entry exists"; else
  P "--no-tmp-confinement -> no /tmp entry written to fstab"; fi
got=$(val s32 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s32 >/dev/null 2>&1

echo "-- 33. Skip a step: --no-time-sync --------------------------"
fresh_node s33
# The fresh node image has no time-sync daemon (measured) — absence IS the
# offender, so the skip just has to leave it absent.
docker exec s33 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-time-sync -y >/dev/null 2>&1
if docker exec s33 dpkg -s systemd-timesyncd >/dev/null 2>&1; then
  F "--no-time-sync should not install systemd-timesyncd" "package present"; else
  P "--no-time-sync -> systemd-timesyncd stays uninstalled"; fi
if docker exec s33 test -f /etc/systemd/timesyncd.conf.d/99-hardening.conf 2>/dev/null; then
  F "--no-time-sync should not write the drop-in" "file exists"; else
  P "--no-time-sync -> no timesyncd drop-in written"; fi
got=$(val s33 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s33 >/dev/null 2>&1

echo "-- 34. Skip a step: --no-apt-trust --------------------------"
fresh_node s34
# Plant the broken-mirror workaround: with the step skipped it must stay the
# EFFECTIVE config (apt-config dump is apt's merged view), and no pin lands.
docker exec s34 bash -c 'printf "APT::Get::AllowUnauthenticated \"true\";\n" > /etc/apt/apt.conf.d/90-weak'
docker exec s34 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-apt-trust -y >/dev/null 2>&1
if docker exec s34 test -f /etc/apt/apt.conf.d/99-hardening-apt-trust 2>/dev/null; then
  F "--no-apt-trust should not write the trust drop-in" "file exists"; else
  P "--no-apt-trust -> no apt trust drop-in written"; fi
got=$(docker exec s34 apt-config dump 2>/dev/null | awk '$1=="APT::Get::AllowUnauthenticated"{gsub(/[";]/,"",$2); print $2; exit}')
[ "$got" = "true" ] && P "--no-apt-trust -> the planted AllowUnauthenticated=true stays effective (step skipped)" \
                    || F "--no-apt-trust should leave the planted loosening effective" "got '$got'"
got=$(val s34 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s34 >/dev/null 2>&1

echo "-- 35. Skip a step: --no-var-tmp-confinement ----------------"
fresh_node s35
# The fresh node has /var/tmp as a plain directory (measured) — absence of
# the bind IS the offender, so the skip just has to leave it plain.
docker exec s35 bash /root/harden.sh --admin-user opsadmin --pubkey "$PUBKEY" --no-var-tmp-confinement -y >/dev/null 2>&1
if docker exec s35 mountpoint -q /var/tmp 2>/dev/null; then
  F "--no-var-tmp-confinement should leave /var/tmp a plain directory" "it is a mountpoint"; else
  P "--no-var-tmp-confinement -> /var/tmp stays a plain directory (no bind)"; fi
if docker exec s35 bash -c 'cp /bin/true /var/tmp/s35 && /var/tmp/s35' >/dev/null 2>&1; then
  P "--no-var-tmp-confinement -> a binary in /var/tmp still executes (step skipped)"; else
  F "--no-var-tmp-confinement should leave /var/tmp executable" "exec refused"; fi
got=$(val s35 permitrootlogin)
[ "$got" = no ] && P "the other steps still ran (PermitRootLogin no)" \
                || F "SSH hardening should still apply" "$got"
docker rm -f s35 >/dev/null 2>&1

echo "============================================================="
total=$((pass + fail))
echo " $pass/$total scenario checks passed"
[ "$fail" -eq 0 ] && echo " All flag scenarios behaved as documented." \
                  || { echo " Some scenarios FAILED — see above."; exit 1; }
echo "============================================================="
