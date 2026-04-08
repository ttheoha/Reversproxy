#!/bin/bash
set -e

CERT_DIR="./certs"
mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/selfsigned.crt" ] && [ -f "$CERT_DIR/selfsigned.key" ]; then
    echo "Certificats SSL deja presents dans $CERT_DIR/, rien a faire."
    exit 0
fi

echo "Generation des certificats SSL auto-signes..."
openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/selfsigned.key" \
    -out "$CERT_DIR/selfsigned.crt" \
    -subj "/C=FR/ST=Local/L=Local/O=ReverseProxy/CN=localhost"

echo "Certificats generes dans $CERT_DIR/"
