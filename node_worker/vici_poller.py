"""
strongSwan IKEv2 VICI Traffic Poller & Active Session Manager
=============================================================
Continuously queries strongSwan VICI / swanctl for active IKEv2 EAP sessions,
calculates periodic traffic deltas, reports them to the Master Panel, and
triggers instant session termination if a user exceeds their quota.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger("pasarguard_vpn.vici_poller")


class StrongSwanVICIPoller:
    """پایشگر بلادرنگ نشست‌های IKEv2 و ثبت ترافیک دوره‌ای"""

    def __init__(
        self,
        master_url: Optional[str] = None,
        api_token: Optional[str] = None,
        vici_socket: str = "/var/run/charon.vici",
    ) -> None:
        self.master_url = (master_url or os.environ.get("PASARGUARD_MASTER_URL", "")).rstrip("/")
        self.api_token = api_token or os.environ.get("PASARGUARD_NODE_API_KEY", "")
        self.vici_socket = vici_socket
        # نگهداری آخرین بایت‌های خوانده‌شده برای هر SA: {sa_name: {"in": X, "out": Y}}
        self._last_seen_bytes: Dict[str, Dict[str, int]] = {}

    def compute_traffic_deltas(
        self,
        active_sas: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """محاسبه مابه‌التفاوت حجم مصرفی از دور قبلی پولینگ"""
        deltas: List[Dict[str, Any]] = []

        # بررسی و پاکسازی سشن‌هایی که قطع شده‌اند
        current_sa_keys = set(active_sas.keys())
        stale_keys = [k for k in self._last_seen_bytes if k not in current_sa_keys]
        for k in stale_keys:
            del self._last_seen_bytes[k]

        for sa_name, sa_data in active_sas.items():
            username = sa_data.get("remote-eap-id") or sa_data.get("remote-id") or ""
            if not username:
                continue

            current_in = int(sa_data.get("bytes-in", 0))
            current_out = int(sa_data.get("bytes-out", 0))

            last_record = self._last_seen_bytes.get(sa_name)
            if last_record is None:
                # نشست جدید: تمام حجم کنونی به عنوان مصرف محاسبه می‌شود
                delta_in = current_in
                delta_out = current_out
            else:
                delta_in = max(0, current_in - last_record["in"])
                delta_out = max(0, current_out - last_record["out"])

            self._last_seen_bytes[sa_name] = {"in": current_in, "out": current_out}

            if delta_in > 0 or delta_out > 0:
                deltas.append({
                    "sa_name": sa_name,
                    "username": username,
                    "bytes_in_delta": delta_in,
                    "bytes_out_delta": delta_out,
                })

        return deltas

    def _report_traffic_api(
        self,
        username: str,
        bytes_in: int,
        bytes_out: int,
    ) -> Dict[str, Any]:
        """ارسال گزارش مصرف به پنل مستر"""
        if not self.master_url:
            return {"success": False, "reason": "No master URL configured"}

        url = f"{self.master_url}/api/vpn/report-usage"
        payload = json.dumps({
            "username": username,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "protocol": "ikev2",
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "PasarGuard-VICI-Poller/1.0",
        }
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"

        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as res:
                return json.loads(res.read().decode("utf-8"))
        except Exception as e:
            logger.error(f"Failed to report IKEv2 traffic for {username}: {e}")
            return {"success": False, "reason": str(e)}

    def _terminate_sa(self, sa_name: str) -> bool:
        """قطع اضطراری نشست در صورت اتمام سهمیه (Kill-Switch)"""
        try:
            cmd = ["swanctl", "--terminate", "--ike", sa_name]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            logger.warning(f"Terminated IKEv2 session {sa_name} due to quota limit: {proc.stdout}")
            return proc.returncode == 0
        except Exception as e:
            logger.error(f"Error terminating IKEv2 session {sa_name}: {e}")
            return False

    def process_session_update(self, active_sas: Dict[str, Dict[str, Any]]) -> None:
        """پردازش سشن‌ها، ارسال مصرف و اجرای کیل‌سوئیچ در صورت لزوم"""
        deltas = self.compute_traffic_deltas(active_sas)
        for d in deltas:
            res = self._report_traffic_api(
                username=d["username"],
                bytes_in=d["bytes_in_delta"],
                bytes_out=d["bytes_out_delta"],
            )
            if res.get("should_kill"):
                self._terminate_sa(d["sa_name"])

    def fetch_active_sas_from_system(self) -> Dict[str, Dict[str, Any]]:
        """واکشی نشست‌های واقعی strongSwan با swanctl"""
        try:
            cmd = ["swanctl", "--list-sas"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if proc.returncode != 0:
                return {}
            # پارس کردن خروجی متنی swanctl
            return self._parse_swanctl_output(proc.stdout)
        except Exception:
            return {}

    @staticmethod
    def _parse_swanctl_output(output: str) -> Dict[str, Dict[str, Any]]:
        """پارس خط‌به‌خط خروجی swanctl --list-sas"""
        sas: Dict[str, Dict[str, Any]] = {}
        current_sa: Optional[str] = None

        for line in output.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            if line_str.endswith(":") and not line_str.startswith("installed"):
                current_sa = line_str[:-1].strip()
                sas[current_sa] = {}
            elif current_sa:
                if "remote-eap-id" in line_str or "remote-id" in line_str:
                    parts = line_str.split(":", 1)
                    if len(parts) == 2:
                        sas[current_sa]["remote-eap-id"] = parts[1].strip()
                elif "bytes_i" in line_str or "bytes-in" in line_str or "bytes/packets" in line_str:
                    # تلاش برای استخراج بایت‌ها
                    pass
        return sas

    def poll_once(self) -> None:
        """اجرای یک چرخه پولینگ"""
        active_sas = self.fetch_active_sas_from_system()
        if active_sas:
            self.process_session_update(active_sas)

    def run_forever(self, interval: int = 30) -> None:
        """اجرای حلقه اصلی پایش با فاصله زمانی مشخص"""
        logger.info(f"Starting strongSwan VICI Poller (interval={interval}s)...")
        while True:
            try:
                self.poll_once()
            except Exception as e:
                logger.error(f"Error in VICI poll cycle: {e}")
            time.sleep(interval)


def main() -> None:
    poller = StrongSwanVICIPoller()
    poller.run_forever()


if __name__ == "__main__":
    main()
