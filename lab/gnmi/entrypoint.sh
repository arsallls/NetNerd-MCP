#!/bin/sh
set -e

# gNMI is gRPC, which means TLS is not optional. Self-signed certs generated
# at boot rather than committed: a private key in a public repo is a habit
# worth not starting, even a throwaway one.
CERTS=/etc/gnmi/certs
if [ ! -f "$CERTS/server.crt" ]; then
    mkdir -p "$CERTS"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$CERTS/server.key" -out "$CERTS/server.crt" \
        -subj "/CN=gnmi1" \
        -addext "subjectAltName=DNS:gnmi1,DNS:localhost,IP:127.0.0.1,IP:172.30.0.5" \
        2>/dev/null
    cp "$CERTS/server.crt" "$CERTS/ca.crt"
fi

# -insecure keeps TLS on but makes a *client* certificate optional. The
# default is RequireAndVerifyClientCert, which would mean shipping a client
# key to whoever runs the tests. TLS itself stays in the path, so the
# transport's handshake handling is still exercised rather than bypassed --
# which -notls would do.
exec gnmi_target \
    -bind_address :57400 \
    -insecure \
    -config /etc/gnmi/model.json \
    -key "$CERTS/server.key" \
    -cert "$CERTS/server.crt" \
    -ca "$CERTS/ca.crt" \
    -username netnerd \
    -password netnerd123 \
    -alsologtostderr
