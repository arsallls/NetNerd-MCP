#!/bin/sh
# Seed the running config from the read-only copy the compose file mounts.
# /etc/frr/frr.conf has to be a normal container-local file: `write memory`
# renames it before writing, which a bind-mounted file refuses. Copying means
# `save_config` works, changes die with the container, and the repo's seed
# config is never modified by a test.
cp /seed/frr.conf /etc/frr/frr.conf
chown frr:frr /etc/frr/frr.conf
chmod 640 /etc/frr/frr.conf

# Start sshd alongside FRR's own supervisor.
/usr/sbin/sshd
exec /sbin/tini -- /usr/lib/frr/docker-start
