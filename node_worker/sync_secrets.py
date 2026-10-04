#!/usr/bin/env python3
"""
PasarGuard Node Worker Secrets Synchronizer
===========================================
Synchronizes authorized user credentials from PasarGuard Master
to local /etc/ppp/chap-secrets, /etc/ppp/pap-secrets, and /etc/ipsec.secrets.
Runs periodically via cron on VPN worker nodes.
"""
import json
import os
import ssl
import subprocess
import urllib.request

def _load_env_file():
    for env_path in ["/opt/pasarguard-vpn/config.env", "/etc/pasarguard-vpn/node.env"]:
        if os.path.exists(env_path):
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k = k.strip()
                            v = v.strip().strip("'\"")
                            if k not in os.environ:
                                os.environ[k] = v
            except Exception:
                pass

_load_env_file()
MASTER_URL = os.environ.get("PASARGUARD_MASTER_URL", "").rstrip("/")
API_TOKEN = os.environ.get("PASARGUARD_NODE_API_KEY", "")

if not MASTER_URL:
    print("PASARGUARD_MASTER_URL not configured")
    exit(1)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

req = urllib.request.Request(
    f"{MASTER_URL}/api/vpn/internal/users-secrets",
    headers={"Authorization": f"Bearer {API_TOKEN}", "User-Agent": "PasarGuard-Node-Sync/1.0"}
)

try:
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))
except Exception as e:
    print(f"Error fetching secrets from {MASTER_URL}: {e}")
    exit(1)

users = data.get("users", [])
if not users:
    print("No users received")
    exit(0)

# Build chap-secrets & pap-secrets
chap_lines = ["# PasarGuard Auto-Synced Secrets", "# client\tserver\tsecret\tIP"]
ipsec_secrets_lines = [
    ": RSA /etc/ipsec.d/private/server.key",
    ": PSK \"PasarGuardVPN123\""
]

for u in users:
    username = u.get("username", "").strip()
    if not username:
        continue
    pws = set()
    if u.get("password"):
        pws.add(u["password"])
    for p in u.get("valid_passwords", []):
        if p:
            pws.add(p)

    for pw in pws:
        clean_pw = pw.replace('"', '\\"')
        chap_lines.append(f'{username}\t*\t"{clean_pw}"\t*')
        chap_lines.append(f'{username}\tl2tpd\t"{clean_pw}"\t*')
        ipsec_secrets_lines.append(f'{username} : EAP "{clean_pw}"')

chap_content = "\n".join(chap_lines) + "\n"
with open("/etc/ppp/chap-secrets", "w", encoding="utf-8") as f:
    f.write(chap_content)
with open("/etc/ppp/pap-secrets", "w", encoding="utf-8") as f:
    f.write(chap_content)

ipsec_content = "\n".join(ipsec_secrets_lines) + "\n"
with open("/etc/ipsec.secrets", "w", encoding="utf-8") as f:
    f.write(ipsec_content)

# Reload strongSwan secrets
subprocess.run(["ipsec", "rereadsecrets"], check=False)
print(f"Successfully synced {len(users)} users to PPP & IPsec secrets!")
