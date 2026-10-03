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

# 2. Server Key and CSR with X509v3 Extensions (critical for OpenVPN remote-cert-tls and strongSwan SAN)
if [[ ! -f "server.key" || ! -f "server.crt" || "${FORCE_REGEN_SERVER:-0}" == "1" ]]; then
  openssl genrsa -out server.key 2048
  openssl req -new -key server.key -out server.csr \
    -subj "/C=IR/ST=Tehran/O=PasarGuard/CN=server.vpn.pasarguard"

  cat << 'EOF' > server_ext.cnf
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "PasarGuard VPN Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, 1.3.6.1.5.5.7.3.1
subjectAltName = @alt_names

[alt_names]
DNS.1 = tur.mobx48.ir
DNS.2 = fin.mobx48.ir
DNS.3 = sub.mob48.ir
DNS.4 = server.vpn.pasarguard
IP.1 = 77.83.203.140
IP.2 = 65.109.217.93
IP.3 = 91.107.146.13
EOF

  # Sign Server Certificate with CA using X509v3 extensions
  openssl x509 -req -days 1825 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -extfile server_ext.cnf
  rm -f server.csr server_ext.cnf
  echo "[VPN-Cert] ✓ X509v3 Server certificate created (server.crt, server.key)"
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
