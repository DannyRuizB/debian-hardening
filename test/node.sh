#!/usr/bin/env bash
# =============================================================================
# Test node for the e2e workflow: one privileged systemd container that plays a
# fresh Debian server, reachable at 127.0.0.1:2222. harden.sh is copied in and
# run there (as root) by the workflow; verify.sh then attacks it from outside.
#
#   ./node.sh up     -> generate the CI SSH key, build the image, boot the node,
#                       and copy ../harden.sh into it
#   ./node.sh wait   -> block until the node's sshd answers (max 60 s)
#   ./node.sh down   -> remove the node
#
# All local and disposable; "down" leaves nothing running.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="db-harden-node"
NAME="db-harden-node"
PORT=2222
KEY=".ssh_ci/id_ci"

case "${1:-}" in
  up)
    if [ ! -f "$KEY" ]; then
      mkdir -p .ssh_ci
      chmod 700 .ssh_ci
      ssh-keygen -t ed25519 -f "$KEY" -N "" -C "db-harden-ci" >/dev/null
      echo "CI key created at test/$KEY"
    fi

    docker build -t "$IMAGE" .

    docker rm -f "$NAME" >/dev/null 2>&1 || true
    # Privileged + host cgroups: systemd inside the container needs to manage
    # its own services (sshd, ufw, fail2ban, unattended-upgrades).
    docker run -d --name "$NAME" --hostname debian-node \
      --privileged --cgroupns=host \
      -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
      -p "127.0.0.1:$PORT:22" "$IMAGE" >/dev/null

    # Ship the script under test into the node.
    docker cp ../harden.sh "$NAME:/root/harden.sh"

    rm -f .ssh_ci/known_hosts
    echo "Node up (ssh on 127.0.0.1:$PORT), harden.sh copied to /root/harden.sh"
    ;;

  wait)
    # No CI key is installed yet (harden.sh runs later and installs it), so we
    # can't authenticate. Just confirm sshd is up by reading its banner.
    for i in $(seq 1 30); do
      if timeout 2 bash -c \
          "exec 3<>/dev/tcp/127.0.0.1/$PORT; read -r line <&3; case \$line in SSH-*) exit 0;; *) exit 1;; esac" \
          2>/dev/null; then
        echo "Node SSH ready"
        exit 0
      fi
      sleep 2
    done
    echo "ERROR: node SSH not answering after 60 s" >&2
    exit 1
    ;;

  down)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    echo "Node removed"
    ;;

  *)
    echo "Usage: $0 {up|wait|down}" >&2
    exit 1
    ;;
esac
