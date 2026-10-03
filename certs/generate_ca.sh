#!/usr/bin/env bash
# ==============================================================================
# PasarGuard VPN Certificate Authority & Server Cert Generator
# Generates 4096-bit RSA Root CA and Server certificates for OpenVPN & strongSwan.
# ==============================================================================
set -euo pipefail

CERT_DIR="${1:-/opt/pasarguard-vpn/certs}"
mkdir -p "${CERT_DIR}"
cd "${CERT_DIR}"

echo "[VPN-Cert] Generating Certificate Authority in ${CERT_DIR}..."

# 1. Root CA Key and Certificate
if [[ ! -f "ca.key" || ! -f "ca.crt" ]]; then
  openssl genrsa -out ca.key 4096
  openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj "/C=IR/ST=Tehran/O=PasarGuard/CN=PasarGuard-VPN-CA"
  echo "[VPN-Cert] ✓ Root CA created (ca.crt, ca.key)"
else
  echo "[VPN-Cert] Root CA already exists."
fi

# 2. Server Key and CSR
if [[ ! -f "server.key" || ! -f "server.crt" ]]; then
  openssl genrsa -out server.key 2048
  openssl req -new -key server.key -out server.csr \
    -subj "/C=IR/ST=Tehran/O=PasarGuard/CN=server.vpn.pasarguard"

  # Sign Server Certificate with CA
  openssl x509 -req -days 1825 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt
  rm -f server.csr
  echo "[VPN-Cert] ✓ Server certificate created (server.crt, server.key)"
else
  echo "[VPN-Cert] Server certificate already exists."
fi

# 3. Diffie-Hellman Parameters (for OpenVPN)
if [[ ! -f "dh2048.pem" ]]; then
  openssl dhparam -out dh2048.pem 2048
  echo "[VPN-Cert] ✓ Diffie-Hellman parameters created (dh2048.pem)"
fi

chmod 600 ca.key server.key
chmod 644 ca.crt server.crt
echo "[VPN-Cert] Certificates successfully prepared."
