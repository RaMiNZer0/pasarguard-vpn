#!/usr/bin/env bash
# ==============================================================================
# PasarGuard Unified VPN (OpenVPN, IKEv2, L2TP) - Automated Installer
# Supports:
#   1. Master Panel Mode (Default): Installs API routers and Web Dashboard UI
#   2. Node Worker Mode (`./install.sh --node`): Installs OpenVPN, strongSwan, and OS hooks
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}======================================================${NC}"
echo -e "${GREEN}  🛡️  PasarGuard Unified VPN Installer (OpenVPN/IKEv2) ${NC}"
echo -e "${BLUE}======================================================${NC}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo -e "${RED}Error: This installer must be run as root (sudo).${NC}" >&2
  exit 1
fi

INSTALL_DIR="/opt/pasarguard-vpn"
DATA_DIR="/var/lib/pasarguard/vpn"
PYTHON_DIR="/var/lib/pasarguard/vpn/python"
PASARGUARD_DIR="/opt/pasarguard"
RAW_BASE="https://raw.githubusercontent.com/RaMiNZer0/pasarguard-vpn/main"

fetch_file() {
  local rel_path="$1"
  local dest_path="$2"
  if [[ -n "${BASH_SOURCE[0]:-}" && -f "$(dirname "${BASH_SOURCE[0]}")/${rel_path}" ]]; then
    cp -f "$(dirname "${BASH_SOURCE[0]}")/${rel_path}" "${dest_path}"
  else
    curl -fsSL "${RAW_BASE}/${rel_path}" -o "${dest_path}"
  fi
}

MODE="${1:-panel}"

if [[ "${MODE}" == "--node" || "${MODE}" == "node" ]]; then
  echo -e "\n${YELLOW}[Node Mode] Installing VPN services and hooks on worker node...${NC}"
  apt-get update -y
  apt-get install -y openvpn strongswan strongswan-pki libcharon-extra-plugins xl2tpd ppp iptables

  # 1. Enable IPv4 forwarding
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  if [[ ! -f /etc/sysctl.d/99-vpn-forward.conf ]]; then
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-vpn-forward.conf
  fi

  # 2. Fetch worker scripts
  mkdir -p /opt/pasarguard-vpn/node_worker /opt/pasarguard-vpn/systemd
  fetch_file "node_worker/pg_vpn_hook.py" "/opt/pasarguard-vpn/node_worker/pg_vpn_hook.py"
  fetch_file "node_worker/vici_poller.py" "/opt/pasarguard-vpn/node_worker/vici_poller.py"
  fetch_file "node_worker/local_cache.py" "/opt/pasarguard-vpn/node_worker/local_cache.py"
  fetch_file "node_worker/circuit_breaker.py" "/opt/pasarguard-vpn/node_worker/circuit_breaker.py"
  fetch_file "node_worker/__init__.py" "/opt/pasarguard-vpn/node_worker/__init__.py"
  fetch_file "systemd/pg-vpn-vici-poller.service" "/etc/systemd/system/pg-vpn-vici-poller.service" 2>/dev/null || true
  chmod +x /opt/pasarguard-vpn/node_worker/*.py

  # 3. L2TP ppp ip-down accounting hook
  mkdir -p /etc/ppp
  if ! grep -q "pg_vpn_hook.py disconnect-l2tp" /etc/ppp/ip-down 2>/dev/null; then
    echo "/usr/bin/python3 /opt/pasarguard-vpn/node_worker/pg_vpn_hook.py disconnect-l2tp >/dev/null 2>&1 || true" >> /etc/ppp/ip-down
    chmod +x /etc/ppp/ip-down
  fi

  # 4. Enable strongSwan VICI Poller
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable --now pg-vpn-vici-poller.service 2>/dev/null || true
  fi

  echo -e "${GREEN}✓ Node worker hooks & VICI poller installed at /opt/pasarguard-vpn/node_worker/${NC}"
  exit 0
fi

# Default: Master Panel Mode
echo -e "\n${YELLOW}[1/4] Preparing directories on master panel...${NC}"
mkdir -p "${INSTALL_DIR}/backend" "${INSTALL_DIR}/plugin" "${INSTALL_DIR}/certs" "${DATA_DIR}" "${PYTHON_DIR}"

echo -e "${YELLOW}[2/4] Fetching extension files...${NC}"
fetch_file "backend/vpn_engine.py" "${INSTALL_DIR}/backend/vpn_engine.py"
fetch_file "backend/vpn_router.py" "${INSTALL_DIR}/backend/vpn_router.py"
fetch_file "backend/vpn_sub_injector.py" "${INSTALL_DIR}/backend/vpn_sub_injector.py"
fetch_file "backend/pg_db_reader.py" "${INSTALL_DIR}/backend/pg_db_reader.py"
fetch_file "backend/pg_user_sync.py" "${INSTALL_DIR}/backend/pg_user_sync.py"
fetch_file "backend/__init__.py" "${INSTALL_DIR}/backend/__init__.py"
fetch_file "plugin/vpn-panel.js" "${INSTALL_DIR}/plugin/vpn-panel.js"
fetch_file "plugin/vpn-sub.js" "${INSTALL_DIR}/plugin/vpn-sub.js"
fetch_file "plugin/integrate-dashboard.sh" "${INSTALL_DIR}/plugin/integrate-dashboard.sh"
chmod +x "${INSTALL_DIR}/plugin/integrate-dashboard.sh"
fetch_file "certs/generate_ca.sh" "${INSTALL_DIR}/certs/generate_ca.sh"
chmod +x "${INSTALL_DIR}/certs/generate_ca.sh"
fetch_file "config.env.example" "${INSTALL_DIR}/config.env.example"
fetch_file "uninstall.sh" "${INSTALL_DIR}/uninstall.sh"
chmod +x "${INSTALL_DIR}/uninstall.sh"
fetch_file "version.json" "${INSTALL_DIR}/version.json"

# Copy python modules
cp -rf "${INSTALL_DIR}/backend" "${PYTHON_DIR}/"

echo -e "${YELLOW}[3/4] Enabling router in sitecustomize.py and .env...${NC}"
SITECUSTOMIZE="${PYTHON_DIR}/sitecustomize.py"
cat << 'EOF' > "${SITECUSTOMIZE}"
import os
import sys
from pathlib import Path

# Prevent repeated bootstrap
if not getattr(sys, "_pasarguard_vpn_initialized", False):
    sys._pasarguard_vpn_initialized = True

    # 1. Chain CleanIP or any other sitecustomize if present
    cleanip_sc = "/var/lib/pasarguard/cleanip/python/sitecustomize.py"
    if os.path.exists(cleanip_sc) and os.path.abspath(cleanip_sc) != os.path.abspath(__file__):
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("cleanip_sitecustomize", cleanip_sc)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
        except Exception:
            pass

    # 2. Add custom vpn modules to path
    vpn_dir = "/var/lib/pasarguard/vpn/python"
    if vpn_dir not in sys.path:
        sys.path.insert(0, vpn_dir)

    # 3. Register VPN router into PasarGuard
    try:
        candidates = [Path.cwd(), Path("/code"), Path("/app"), Path("/opt/pasarguard")]
        for cand in candidates:
            if (cand / "main.py").is_file() and (cand / "app").is_dir():
                cand_str = str(cand.resolve())
                if cand_str not in sys.path:
                    sys.path.insert(0, cand_str)
                break

        from backend.vpn_router import router as vpn_router
        from app.routers import api_router

        if not any(getattr(r, "prefix", None) == "/api/vpn" for r in api_router.routes):
            api_router.include_router(vpn_router)
            sys.stderr.write("[VPN-Hub] Router successfully registered in PasarGuard API\n")
    except Exception as e:
        sys.stderr.write(f"[VPN-Hub] Bootstrap notice: {e}\n")
EOF

# Ensure PYTHONPATH is configured in /opt/pasarguard/.env
if [[ -f "/opt/pasarguard/.env" ]]; then
  if grep -q "^PYTHONPATH=" /opt/pasarguard/.env; then
    if ! grep -q "/var/lib/pasarguard/vpn/python" /opt/pasarguard/.env; then
      sed -i 's|^PYTHONPATH="\(.*\)"|PYTHONPATH="/var/lib/pasarguard/vpn/python:\1"|' /opt/pasarguard/.env
    fi
  else
    echo 'PYTHONPATH="/var/lib/pasarguard/vpn/python"' >> /opt/pasarguard/.env
  fi
fi

echo -e "${YELLOW}[4/4] Injecting Web UI to PasarGuard Dashboard and Client Subscription...${NC}"
bash "${INSTALL_DIR}/plugin/integrate-dashboard.sh" || {
  echo -e "${YELLOW}Warning: Automatic dashboard integration skipped, will fallback to manual injection if needed.${NC}"
}

# Inject vpn-sub.js into subscription template
SUB_TEMPLATE="/var/lib/pasarguard/templates/subscription/index.html"
if [[ -f "${SUB_TEMPLATE}" && -f "${INSTALL_DIR}/plugin/vpn-sub.js" ]]; then
  echo -e "${GREEN}Injecting/Updating 1-Click VPN download buttons to user subscription page...${NC}"
  python3 -c "
import re
with open('${SUB_TEMPLATE}', 'r', encoding='utf-8') as f:
    c = f.read()
with open('${INSTALL_DIR}/plugin/vpn-sub.js', 'r', encoding='utf-8') as f:
    js_code = f.read()
script_tag = f'\n<script id=\"pg-vpn-sub-initialized\">\n{js_code}\n</script>\n'
if 'id=\"pg-vpn-sub-initialized\"' in c:
    c = re.sub(r'<script id=\"pg-vpn-sub-initialized\">.*?</script>', script_tag.strip(), c, flags=re.DOTALL)
elif '</body>' in c:
    c = c.replace('</body>', script_tag + '</body>')
with open('${SUB_TEMPLATE}', 'w', encoding='utf-8') as f:
    f.write(c)
" || true
fi

echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}  ✓ PasarGuard Unified VPN installed successfully!   ${NC}"
echo -e "${GREEN}  Repository: https://github.com/RaMiNZer0/pasarguard-vpn ${NC}"
echo -e "${GREEN}======================================================${NC}"
echo -e "${YELLOW}To apply changes, restart PasarGuard:${NC}"
echo -e "  sudo systemctl restart pasarguard  (or: docker restart pasarguard)\n"
