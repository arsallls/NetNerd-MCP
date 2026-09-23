#!/bin/sh
# Seed the running config from the read-only copy the compose file mounts.
# /etc/frr/frr.conf has to be a normal container-local file: `write memory`
# renames it before writing, which a bind-mounted file refuses. Copying means
# `save_config` works, changes die with the container, and the repo's seed
# config is never modified by a test.
cp /seed/frr.conf /etc/frr/frr.conf
chown frr:frr /etc/frr/frr.conf
chmod 640 /etc/frr/frr.conf

# Keep sshd alive alongside FRR's own supervisor. A bare `sshd` here was
# enough until the test suite started opening a session per test: the listener
# would eventually die, and because its child sessions inherit the listening
# socket, port 22 stayed bound while nothing accepted connections. The
# container then looked healthy to every check while failing every SSH, and
# only a recreate fixed it. The retry loop waits for the orphans to be reaped
# (see ClientAliveInterval in the Dockerfile) and takes the port back.
while :; do
    /usr/sbin/sshd -D
    echo "entrypoint: sshd exited, restarting in 5s" >&2
    sleep 5
done &

exec /sbin/tini -- /usr/lib/frr/docker-start
