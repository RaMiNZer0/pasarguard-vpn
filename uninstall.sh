#!/usr/bin/env bash
# ==============================================================================
# PasarGuard Unified VPN Extension - Clean Uninstaller
# Safely removes all VPN extension files, dashboard injections, and node hooks
# WITHOUT touching PasarGuard core, database, or proxy configs.
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${YELLOW}Uninstalling PasarGuard Unified VPN Extension...${NC}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo -e "${RED}Error: This uninstaller must be run as root (sudo).${NC}" >&2
  exit 1
fi

# 1. Stop and remove node systemd service
if command -v systemctl >/dev/null 2>&1; then
  echo -e "${YELLOW}[1/4] Stopping VPN background services...${NC}"
  systemctl stop pg-vpn-vici-poller.service 2>/dev/null || true
  systemctl disable pg-vpn-vici-poller.service 2>/dev/null || true
  rm -f /etc/systemd/system/pg-vpn-vici-poller.service
  systemctl daemon-reload
fi

# 2. Revert Web UI Dashboard Injection
echo -e "${YELLOW}[2/4] Reverting Web UI dashboard patches...${NC}"
CANDIDATE_PATHS=(
  "/opt/pasarguard/dashboard/build/index.html"
  "/opt/pasarguard/panel/dashboard/build/index.html"
  "/var/lib/docker/volumes/pasarguard_dashboard/_data/build/index.html"
)

for html in "${CANDIDATE_PATHS[@]}"; do
  if [[ -f "${html}" ]]; then
    python3 - "${html}" << 'PY' || true
import sys, re
from pathlib import Path
p = Path(sys.argv[1])
content = p.read_text(encoding="utf-8")
cleaned = re.sub(r'\s*<script\s+id=["\']pg-vpn-loader["\'][^>]*></script>\s*', '\n', content, flags=re.I)
if cleaned != content:
    p.write_text(cleaned, encoding="utf-8")
    print(f"Reverted injection in {p}")
PY
  fi
done

# Docker container index.html revert
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -q "^pasarguard$"; then
  docker exec pasarguard python3 -c '
import re
from pathlib import Path
for p in [Path("/code/app/templates/index.html"), Path("/opt/pasarguard/dashboard/build/index.html")]:
    if p.exists():
        c = p.read_text()
        cleaned = re.sub(r"\s*<script\s+id=[\"'\']pg-vpn-loader[\"'\'][^>]*></script>\s*", "\n", c)
        if cleaned != c:
            p.write_text(cleaned)
' 2>/dev/null || true
fi

# 3. Remove backend hooks & sitecustomize
echo -e "${YELLOW}[3/4] Removing Python router extension...${NC}"
rm -rf /var/lib/pasarguard/vpn/python 2>/dev/null || true
rm -f /opt/pasarguard/dashboard/build/statics/vpn-panel.js 2>/dev/null || true

# Revert PYTHONPATH in .env
if [[ -f "/opt/pasarguard/.env" ]]; then
  sed -i 's|/var/lib/pasarguard/vpn/python:||g' /opt/pasarguard/.env
  sed -i 's|:/var/lib/pasarguard/vpn/python||g' /opt/pasarguard/.env
fi

# 4. Remove installation directory
echo -e "${YELLOW}[4/4] Cleaning up directory /opt/pasarguard-vpn...${NC}"
rm -rf /opt/pasarguard-vpn

echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}  ✓ PasarGuard Unified VPN uninstalled completely!    ${NC}"
echo -e "${GREEN}======================================================${NC}"
echo -e "${YELLOW}Please restart PasarGuard to apply clean state:${NC}"
echo -e "  sudo systemctl restart pasarguard  (or: docker restart pasarguard)\n"
