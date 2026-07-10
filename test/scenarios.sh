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

echo "============================================================="
total=$((pass + fail))
echo " $pass/$total scenario checks passed"
[ "$fail" -eq 0 ] && echo " All flag scenarios behaved as documented." \
                  || { echo " Some scenarios FAILED — see above."; exit 1; }
echo "============================================================="
