# Disposable "fresh Debian server" for the e2e test: systemd as PID 1 (so ufw,
# fail2ban and unattended-upgrades run as real services) plus sshd. harden.sh
# is run INSIDE this container as root (via docker exec), exactly as you'd run
# it on a real box — then the test attacks it over SSH from outside.
FROM debian:13

ENV container=docker

# Keep the apt lists (no rm -rf /var/lib/apt/lists): harden.sh installs ufw,
# fail2ban and unattended-upgrades, so the node needs to resolve packages.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       systemd systemd-sysv openssh-server sudo ca-certificates procps iproute2

EXPOSE 22

CMD ["/sbin/init"]
