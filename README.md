# PasarGuard Unified VPN (OpenVPN, IKEv2, L2TP/IPsec)

افزونه ماژولار و یکپارچه پروتکل‌های VPN کلاسیک و سازگار با سیستم‌عامل‌ها برای پنل مدیریت **PasarGuard**.

## قابلیت‌ها:
- **OpenVPN:** پورت ۱۱۹۴ با هوک احراز هویت بلادرنگ (`--auth-user-pass-verify`) و اکانتینگ ترافیک در قطع اتصال.
- **IKEv2 (strongSwan):** پورت ۵۰۰ و ۴۵۰۰ برای اتصال بومی آیفون و ویندوز با تولید پروفایل خودکار `.mobileconfig`.
- **L2TP/IPsec:** پورت ۱۷۰۱ با محاسبه حجم بومی در `/etc/ppp/ip-down`.
- **سایدکار نود سبک:** باینری/هوک با مصرف کمتر از ۱۵ مگابایت رم و ۰٪ پردازنده در زمان Idle.
- **نگاشت گروه‌ها و هاست‌ها:** اتصال منطقی با ساختار Groups و Core Configs بدون دستکاری سورس پنل.

## ساختار:
- `backend/vpn_engine.py`: موتور احراز هویت و اکانتینگ متمرکز
- `backend/vpn_router.py`: روتر REST API (`/api/vpn/*`)
- `node_worker/pg_vpn_hook.py`: هوک سرورهای نود
- `plugin/vpn-panel.js`: رابط کاربری داشبورد
- `install.sh`: اسکریپت نصب خودکار حالت Master و Worker Node
- `tests/`: تست‌های جامع با pytest و Node.js (۳۱ تست کامل پاس شده)

## تست و تایید صحت:
```bash
python -m pytest
node tests/test_vpn_ui.js
```
