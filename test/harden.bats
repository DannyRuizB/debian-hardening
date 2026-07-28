#!/usr/bin/env bats
#
# Unit tests for harden.sh. The script guards `main` behind a BASH_SOURCE check,
# so sourcing it loads the functions and default flags without touching the
# host. The parse_args / has_authorized_key checks run in an isolated `bash -c`
# subshell so the script's `set -euo pipefail` can't leak into the test shell.

SCRIPT="${BATS_TEST_DIRNAME}/../harden.sh"

# ---- CLI surface (script run as a subprocess) -----------------------------

@test "--help lists the options and exits 0" {
  run "$SCRIPT" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"--ssh-port"* ]]
  [[ "$output" == *"--no-passwordless-sudo"* ]]
  # The help is a sed range over the header — these catch it going stale
  # when options are added (the range cut off the tail once already).
  [[ "$output" == *"--no-ssh-policies"* ]]
  [[ "$output" == *"--no-coredump-limits"* ]]
  [[ "$output" == *"--no-umask-tmout"* ]]
  [[ "$output" == *"--no-cron-restrictions"* ]]
  [[ "$output" == *"--no-password-policy"* ]]
  [[ "$output" == *"--no-aide"* ]]
  [[ "$output" == *"--no-rkhunter"* ]]
  [[ "$output" == *"--no-module-blacklist"* ]]
  [[ "$output" == *"--no-faillock"* ]]
  [[ "$output" == *"--no-file-permissions"* ]]
  [[ "$output" == *"--no-ssh-access"* ]]
  [[ "$output" == *"--no-service-sandboxing"* ]]
  [[ "$output" == *"--no-journald"* ]]
  [[ "$output" == *"--no-su-restriction"* ]]
  [[ "$output" == *"--no-system-accounts"* ]]
  [[ "$output" == *"-h, --help"* ]]
}

@test "an unknown option is rejected with a message and non-zero exit" {
  run "$SCRIPT" --nope
  [ "$status" -ne 0 ]
  [[ "$output" == *"Unknown option"* ]]
}

@test "running without root is refused" {
  [ "$(id -u)" -eq 0 ] && skip "test assumes a non-root user"
  run "$SCRIPT" --dry-run --yes
  [ "$status" -ne 0 ]
  [[ "$output" == *"Run as root"* ]]
}

# ---- parse_args (source the script, inspect the globals) ------------------

@test "defaults are sane before any flags" {
  run bash -c "source '$SCRIPT'; echo \"\$SSH_PORT \$PASSWORDLESS_SUDO \$DO_SSH \$DRY_RUN\""
  [ "$status" -eq 0 ]
  [ "$output" = "22 1 1 0" ]
}

@test "parse_args reads --ssh-port / --admin-user / --pubkey" {
  run bash -c "source '$SCRIPT'; parse_args --ssh-port 2222 --admin-user bob --pubkey 'ssh-ed25519 KEY'; echo \"\$SSH_PORT|\$ADMIN_USER|\$ADMIN_PUBKEY\""
  [ "$status" -eq 0 ]
  [ "$output" = "2222|bob|ssh-ed25519 KEY" ]
}

@test "--no-passwordless-sudo flips the flag off" {
  run bash -c "source '$SCRIPT'; parse_args --no-passwordless-sudo; echo \"\$PASSWORDLESS_SUDO\""
  [ "$output" = "0" ]
}

@test "the per-step --no-* flags each set their toggle to 0" {
  run bash -c "source '$SCRIPT'; parse_args --no-ssh --no-ufw --no-fail2ban --no-autoupdates --no-sysctl --no-account-policies --no-mount-options --no-banners --no-sudo-hardening --no-ssh-policies --no-coredump-limits --no-umask-tmout --no-cron-restrictions --no-password-policy --no-aide --no-rkhunter --no-module-blacklist --no-faillock --no-file-permissions --no-ssh-access --no-service-sandboxing --no-journald --no-su-restriction --no-system-accounts; echo \"\$DO_SSH \$DO_UFW \$DO_FAIL2BAN \$DO_AUTOUPDATES \$DO_SYSCTL \$DO_ACCOUNT_POLICIES \$DO_MOUNT_OPTIONS \$DO_BANNERS \$DO_SUDO_HARDENING \$DO_SSH_POLICIES \$DO_COREDUMP_LIMITS \$DO_UMASK_TMOUT \$DO_CRON_RESTRICTIONS \$DO_PASSWORD_POLICY \$DO_AIDE \$DO_RKHUNTER \$DO_MODULE_BLACKLIST \$DO_FAILLOCK \$DO_FILE_PERMISSIONS \$DO_SSH_ACCESS \$DO_SERVICE_SANDBOXING \$DO_JOURNALD \$DO_SU_RESTRICTION \$DO_SYSTEM_ACCOUNTS\""
  [ "$output" = "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0" ]
}

@test "--allow-port accumulates into EXTRA_PORTS" {
  run bash -c "source '$SCRIPT'; parse_args --allow-port 80/tcp --allow-port 443/tcp; echo \"\${EXTRA_PORTS[*]}\""
  [ "$output" = "80/tcp 443/tcp" ]
}

# ---- has_authorized_key (override getent to point at a temp home) ---------

@test "has_authorized_key succeeds for a non-empty authorized_keys" {
  home="$BATS_TEST_TMPDIR/withkey"
  mkdir -p "$home/.ssh"
  echo "ssh-ed25519 AAAA test@host" > "$home/.ssh/authorized_keys"
  run bash -c "source '$SCRIPT'; getent() { printf 'u:x:0:0::%s:/bin/bash\n' '$home'; }; has_authorized_key u && echo YES || echo NO"
  [ "$output" = "YES" ]
}

@test "has_authorized_key fails when there is no key file" {
  home="$BATS_TEST_TMPDIR/nokey"
  mkdir -p "$home"
  run bash -c "source '$SCRIPT'; getent() { printf 'u:x:0:0::%s:/bin/bash\n' '$home'; }; has_authorized_key u && echo YES || echo NO"
  [ "$output" = "NO" ]
}
