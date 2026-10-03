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

  mkdir -p /opt/pasarguard-vpn/node_worker
  fetch_file "node_worker/pg_vpn_hook.py" "/opt/pasarguard-vpn/node_worker/pg_vpn_hook.py"
  chmod +x /opt/pasarguard-vpn/node_worker/pg_vpn_hook.py

  echo -e "${GREEN}✓ Node worker hooks installed at /opt/pasarguard-vpn/node_worker/pg_vpn_hook.py${NC}"
  exit 0
fi

# Default: Master Panel Mode
echo -e "\n${YELLOW}[1/4] Preparing directories on master panel...${NC}"
mkdir -p "${INSTALL_DIR}/backend" "${INSTALL_DIR}/plugin" "${DATA_DIR}" "${PYTHON_DIR}"

echo -e "${YELLOW}[2/4] Fetching extension files...${NC}"
fetch_file "backend/vpn_engine.py" "${INSTALL_DIR}/backend/vpn_engine.py"
fetch_file "backend/vpn_router.py" "${INSTALL_DIR}/backend/vpn_router.py"
fetch_file "backend/vpn_sub_injector.py" "${INSTALL_DIR}/backend/vpn_sub_injector.py"
fetch_file "backend/__init__.py" "${INSTALL_DIR}/backend/__init__.py"
fetch_file "plugin/vpn-panel.js" "${INSTALL_DIR}/plugin/vpn-panel.js"
fetch_file "plugin/integrate-dashboard.sh" "${INSTALL_DIR}/plugin/integrate-dashboard.sh"
chmod +x "${INSTALL_DIR}/plugin/integrate-dashboard.sh"
fetch_file "version.json" "${INSTALL_DIR}/version.json"

# Copy python modules
cp -rf "${INSTALL_DIR}/backend" "${PYTHON_DIR}/"

echo -e "${YELLOW}[3/4] Enabling router in sitecustomize.py...${NC}"
SITECUSTOMIZE="${PYTHON_DIR}/sitecustomize.py"
cat << 'EOF' > "${SITECUSTOMIZE}"
import os
import sys

# Add custom vpn modules to path
vpn_dir = "/var/lib/pasarguard/vpn/python"
if vpn_dir not in sys.path:
    sys.path.insert(0, vpn_dir)

try:
    from app.routers import api_router
    from backend.vpn_router import router as vpn_router
    api_router.include_router(vpn_router)
except Exception:
    pass
EOF

echo -e "${YELLOW}[4/4] Injecting Web UI to PasarGuard Dashboard (Host & Docker)...${NC}"
bash "${INSTALL_DIR}/plugin/integrate-dashboard.sh" || {
  echo -e "${YELLOW}Warning: Automatic dashboard integration skipped, will fallback to manual injection if needed.${NC}"
}

echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}  ✓ PasarGuard Unified VPN installed successfully!   ${NC}"
echo -e "${GREEN}  Repository: https://github.com/RaMiNZer0/pasarguard-vpn ${NC}"
echo -e "${GREEN}======================================================${NC}"
echo -e "${YELLOW}To apply changes, restart PasarGuard:${NC}"
echo -e "  sudo systemctl restart pasarguard  (or: docker restart pasarguard)\n"
