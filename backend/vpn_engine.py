"""
PasarGuard Unified VPN Engine (OpenVPN, IKEv2, L2TP)
===================================================
Ultra-lightweight, zero-idle-overhead authentication, accounting,
and configuration generation engine for PasarGuard multi-protocol support.
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("pasarguard_vpn")


class VPNProtocol(str, Enum):
    OPENVPN = "openvpn"
    IKEV2 = "ikev2"
    L2TP = "l2tp"


@dataclass
class VPNAuthResult:
    allowed: bool
    username: str
    remaining_bytes: int = 0
    reason: str = ""
    user_id: Optional[int] = None


@dataclass
class VPNUser:
    username: str
    password: str
    status: str = "active"
    data_limit: int = 0  # 0 means unlimited
    used_traffic: int = 0
    expire: int = 0  # unix timestamp, 0 means no expiry
    group: str = "default"
    valid_passwords: List[str] = field(default_factory=list)

    def check_password(self, candidate: str) -> bool:
        if self.password and self.password == candidate:
            return True
        if self.valid_passwords and candidate in self.valid_passwords:
            return True
        return False

    @property
    def remaining_bytes(self) -> int:
        if self.data_limit == 0:
            return 999_999_999_999_999
        return max(0, self.data_limit - self.used_traffic)

    def is_expired(self, current_time: Optional[int] = None) -> bool:
        if self.expire == 0:
            return False
        now = current_time or int(time.time())
        return now > self.expire

    def is_quota_exceeded(self) -> bool:
        if self.data_limit == 0:
            return False
        return self.used_traffic >= self.data_limit


class VPNEngine:
    """
    موتور یکپارچه‌ساز و مدیریت احراز هویت و اکانتینگ پروتکل‌های VPN
    برای اتصال بدون تداخل با هسته پاسارگارد.
    """

    def __init__(self, data_dir: Optional[Path | str] = None) -> None:
        if data_dir is None:
            self.data_dir = Path("/opt/pasarguard-cleanip/data/vpn")
        else:
            self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.users_file = self.data_dir / "vpn_users.json"
        self.groups_file = self.data_dir / "vpn_groups.json"

        # حافظه نهان فوق‌سریع در RAM (In-Memory Cache) برای جلوگیری از I/O دیسک
        self._users: Dict[str, VPNUser] = {}
        self._group_policies: Dict[str, List[str]] = {}
        self._user_syncer: Optional[Any] = None
        self._load_state()

    def set_user_syncer(self, syncer: Any) -> None:
        """اتصال همگام‌ساز خودکار با دیتابیس پاسارگارد"""
        self._user_syncer = syncer

    def _load_state(self) -> None:
        """بارگذاری داده‌ها از دیسک به حافظه رم در زمان راه‌اندازی"""
        if self.users_file.exists():
            try:
                with open(self.users_file, "r", encoding="utf-8") as f:
                    raw_users = json.load(f)
                    for u in raw_users:
                        # حذف فیلدهای احتمالی ناشناخته
                        known_keys = {"username", "password", "status", "data_limit", "used_traffic", "expire", "group", "valid_passwords"}
                        filtered = {k: v for k, v in u.items() if k in known_keys}
                        user = VPNUser(**filtered)
                        self._users[user.username] = user
            except Exception as e:
                logger.error(f"Error loading VPN users: {e}")

        if self.groups_file.exists():
            try:
                with open(self.groups_file, "r", encoding="utf-8") as f:
                    self._group_policies = json.load(f)
            except Exception as e:
                logger.error(f"Error loading VPN groups: {e}")

    def _save_state(self) -> None:
        """ذخیره ناهمگام و ایمن در فایل"""
        try:
            with open(self.users_file, "w", encoding="utf-8") as f:
                json.dump([vars(u) for u in self._users.values()], f, indent=2)
            with open(self.groups_file, "w", encoding="utf-8") as f:
                json.dump(self._group_policies, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving VPN state: {e}")

    def upsert_mock_user(
        self,
        username: str,
        password: str,
        status: str = "active",
        data_limit: int = 0,
        used_traffic: int = 0,
        expire: int = 0,
        group: str = "default",
        valid_passwords: Optional[List[str]] = None,
    ) -> None:
        """ثبت یا به‌روزرسانی اطلاعات کاربر برای اعتبارسنجی"""
        self._users[username] = VPNUser(
            username=username,
            password=password,
            status=status,
            data_limit=data_limit,
            used_traffic=used_traffic,
            expire=expire,
            group=group,
            valid_passwords=valid_passwords or ([password] if password else []),
        )
        self._save_state()

    def authenticate_user(
        self,
        username: str,
        password: str,
        protocol: VPNProtocol | str,
    ) -> VPNAuthResult:
        """
        احراز هویت بلادرنگ در صدم‌ثانیه (Real-Time Authentication)
        فراخوانی توسط هوک‌های OpenVPN، IKEv2 و L2TP.
        """
        user = self._users.get(username)
        if not user and self._user_syncer:
            user = self._user_syncer.sync_user(username)

        if not user:
            return VPNAuthResult(
                allowed=False,
                username=username,
                reason="User not found",
            )

        if not user.check_password(password):
            # اگر پسورد نادرست بود، ممکن است در پنل تغییر کرده باشد؛ یک بار از DB همگام کن
            if self._user_syncer:
                user = self._user_syncer.sync_user(username) or user
            if not user.check_password(password):
                return VPNAuthResult(
                    allowed=False,
                    username=username,
                    reason="Invalid credentials",
                )

        if user.status == "expired" or user.is_expired():
            return VPNAuthResult(
                allowed=False,
                username=username,
                reason="User expired",
            )

        if user.status != "active":
            return VPNAuthResult(
                allowed=False,
                username=username,
                reason=f"User is {user.status}",
            )

        if user.is_quota_exceeded():
            return VPNAuthResult(
                allowed=False,
                username=username,
                reason="Data quota exceeded",
            )

        return VPNAuthResult(
            allowed=True,
            username=username,
            remaining_bytes=user.remaining_bytes,
            reason="Authorized",
        )

    def report_traffic(
        self,
        username: str,
        bytes_in: int,
        bytes_out: int,
        protocol: VPNProtocol | str,
    ) -> Dict[str, Any]:
        """
        ثبت و کسر مصرف ترافیک سشن (Traffic Accounting)
        و فعال‌سازی کیل‌سوئیچ در صورت اتمام سهمیه.
        """
        user = self._users.get(username)
        if not user:
            return {"success": False, "reason": "User not found"}

        consumed = bytes_in + bytes_out
        user.used_traffic += consumed
        self._save_state()

        should_kill = user.is_quota_exceeded()
        reason = "Quota exceeded" if should_kill else "OK"

        return {
            "success": True,
            "username": username,
            "consumed_bytes": consumed,
            "used_traffic": user.used_traffic,
            "remaining_bytes": user.remaining_bytes,
            "should_kill": should_kill,
            "reason": reason,
        }

    def handle_openvpn_auth_file(self, file_path: str) -> VPNAuthResult:
        """
        پارس کردن فایل موقت OpenVPN در هوک --auth-user-pass-verify via-file
        خط ۱: نام‌کاربری
        خط ۲: رمز عبور
        """
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = [line.strip() for line in f.readlines()]
            if len(lines) < 2:
                return VPNAuthResult(allowed=False, username="", reason="Malformed auth file")
            username, password = lines[0], lines[1]
            return self.authenticate_user(username, password, protocol=VPNProtocol.OPENVPN)
        except Exception as e:
            return VPNAuthResult(allowed=False, username="", reason=str(e))

    def handle_l2tp_ip_down(self, env_vars: Dict[str, str]) -> Dict[str, Any]:
        """
        پارس کردن متغیرهای محیطی pppd در اسکریپت /etc/ppp/ip-down
        """
        username = env_vars.get("PEERNAME", "")
        bytes_in = int(env_vars.get("BYTES_RCVD", "0"))
        bytes_out = int(env_vars.get("BYTES_SENT", "0"))
        total = bytes_in + bytes_out

        report = self.report_traffic(username, bytes_in, bytes_out, protocol=VPNProtocol.L2TP)
        report["total_bytes"] = total
        return report

    def handle_vici_session_update(self, vici_raw: Dict[str, Any]) -> Dict[str, Any]:
        """
        پارس کردن خروجی دیکشنری سشن strongSwan VICI list_sas
        """
        username = vici_raw.get("remote-eap-id", "")
        bytes_in = int(vici_raw.get("bytes-in", "0"))
        bytes_out = int(vici_raw.get("bytes-out", "0"))
        total = bytes_in + bytes_out

        report = self.report_traffic(username, bytes_in, bytes_out, protocol=VPNProtocol.IKEV2)
        report["total_bytes"] = total
        return report

    def set_group_node_policy(self, group_name: str, allowed_nodes: List[str]) -> None:
        """تعریف سیاست دسترسی گروه کاربری به نودهای مجاز"""
        self._group_policies[group_name] = allowed_nodes
        self._save_state()

    def can_user_access_node(self, username: str, node_name: str) -> bool:
        """بررسی اینکه آیا گروه کاربر به این نود دسترسی دارد یا خیر"""
        user = self._users.get(username)
        if not user:
            return False
        if user.group not in self._group_policies or not self._group_policies[user.group]:
            return True
        allowed = self._group_policies.get(user.group, [])
        return node_name in allowed

    def get_allowed_nodes_for_user(
        self, username: str, all_available_nodes: Optional[List[str]] = None
    ) -> List[str]:
        """واکشی لیست نودهای مجاز کاربر بر اساس گروه یا فال‌بک به همه نودها"""
        user = self._users.get(username)
        if not user:
            return []
        if user.group in self._group_policies and self._group_policies[user.group]:
            return self._group_policies[user.group]
        return all_available_nodes or ["turk", "finland"]


class OpenVPNClientConfigGenerator:
    """تولیدکننده استاندارد فایل‌های تک‌فایلی .ovpn"""

    def __init__(
        self,
        server_host: str,
        server_port: int = 1194,
        proto: str = "udp",
        ca_cert: str = "",
        cipher: str = "AES-256-GCM",
    ) -> None:
        self.server_host = server_host
        self.server_port = server_port
        self.proto = proto
        self.ca_cert = ca_cert.strip()
        self.cipher = cipher

    def generate(self, node_name: str = "PasarGuard-Node") -> str:
        return f"""# PasarGuard VPN Client Configuration - {node_name}
client
dev tun
proto {self.proto}
remote {self.server_host} {self.server_port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth-user-pass
cipher {self.cipher}
verb 3

<ca>
{self.ca_cert}
</ca>
"""


class AppleMobileConfigGenerator:
    """تولیدکننده پروفایل پیکربندی اپل (.mobileconfig) برای اتصال بدون برنامه آیفون و مک"""

    def __init__(
        self,
        organization: str = "PasarGuard VPN",
        server_address: str = "",
        remote_id: str = "",
        ca_cert: str = "",
    ) -> None:
        self.organization = organization
        self.server_address = server_address
        self.remote_id = remote_id or server_address
        self.ca_cert = ca_cert.strip()

    def generate(
        self,
        profile_name: str = "PasarGuard IKEv2",
        username: str = "",
        password: str = "",
    ) -> str:
        payload_uuid = str(uuid.uuid4())
        vpn_uuid = str(uuid.uuid4())
        ca_uuid = str(uuid.uuid4())

        # آماده‌سازی دیتا و پی‌لود سرتیفیکیت روت CA اپل در صورت وجود
        ca_payload_xml = ""
        if self.ca_cert:
            clean_b64 = (
                self.ca_cert.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("\n", "")
                .replace("\r", "")
                .strip()
            )
            if clean_b64:
                ca_payload_xml = f"""
        <dict>
            <key>PayloadCertificateFileName</key>
            <string>PasarGuard-CA.crt</string>
            <key>PayloadContent</key>
            <data>
{clean_b64}
            </data>
            <key>PayloadDescription</key>
            <string>PasarGuard VPN Root CA Certificate</string>
            <key>PayloadDisplayName</key>
            <string>PasarGuard Root CA</string>
            <key>PayloadIdentifier</key>
            <string>org.pasarguard.vpn.ca.{ca_uuid}</string>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadUUID</key>
            <string>{ca_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>"""

        password_xml = f"""
                <key>AuthPassword</key>
                <string>{password}</string>""" if password else ""

        return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadDisplayName</key>
    <string>{profile_name}</string>
    <key>PayloadIdentifier</key>
    <string>org.pasarguard.vpn.{payload_uuid}</string>
    <key>PayloadOrganization</key>
    <string>{self.organization}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{payload_uuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadContent</key>
    <array>{ca_payload_xml}
        <dict>
            <key>PayloadDisplayName</key>
            <string>{profile_name}</string>
            <key>PayloadIdentifier</key>
            <string>org.pasarguard.vpn.ikev2.{vpn_uuid}</string>
            <key>PayloadType</key>
            <string>com.apple.vpn.managed</string>
            <key>PayloadUUID</key>
            <string>{vpn_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>UserDefinedName</key>
            <string>{profile_name}</string>
            <key>VPNType</key>
            <string>IKEv2</string>
            <key>IKEv2</key>
            <dict>
                <key>RemoteAddress</key>
                <string>{self.server_address}</string>
                <key>RemoteIdentifier</key>
                <string>{self.remote_id}</string>
                <key>AuthenticationMethod</key>
                <string>None</string>
                <key>ExtendedAuthEnabled</key>
                <true/>
                <key>AuthName</key>
                <string>{username}</string>{password_xml}
                <key>DeadPeerDetectionRate</key>
                <string>Medium</string>
                <key>DisableMOBIKE</key>
                <integer>0</integer>
                <key>DisableRedirect</key>
                <integer>0</integer>
                <key>EnablePFS</key>
                <integer>1</integer>
            </dict>
        </dict>
    </array>
</dict>
</plist>
"""
