# PasarGuard Unified VPN (OpenVPN, IKEv2, L2TP/IPsec)

افزونه ماژولار و یکپارچه پروتکل‌های VPN کلاسیک و سازگار با سیستم‌عامل‌ها برای پنل مدیریت **PasarGuard**.

## قابلیت‌ها:
- **OpenVPN:** پورت ۱۱۹۴ با هوک احراز هویت بلادرنگ (`--auth-user-pass-verify`) و اکانتینگ ترافیک در قطع اتصال.
- **IKEv2 (strongSwan):** پورت ۵۰۰ و ۴۵۰۰ برای اتصال بومی آیفون و ویندوز با تولید پروفایل خودکار `.mobileconfig`.
- **L2TP/IPsec:** پورت ۱۷۰۱ با محاسبه حجم بومی در `/etc/ppp/ip-down`.
- **سایدکار نود سبک:** باینری/هوک با مصرف کمتر از ۱۵ مگابایت رم و ۰٪ پردازنده در زمان Idle.
- **نگاشت گروه‌ها و هاست‌ها:** اتصال منطقی با ساختار Groups و Core Configs بدون دستکاری سورس پنل.

## نحوه نصب سریع (One-Line Installers):

### ۱. روی سرور پنل مستر (Master Panel):
```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/RaMiNZer0/pasarguard-vpn/main/install.sh)
```

### ۲. روی سرورهای نود (Worker Node):
```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/RaMiNZer0/pasarguard-vpn/main/install.sh) --node
```

---

## ساختار ماژول‌ها:
- `backend/vpn_engine.py`: موتور احراز هویت، اکانتینگ و کش RAM
- `backend/pg_db_reader.py`: خواندن کاربران به صورت Read-Only از دیتابیس پاسارگارد
- `backend/pg_user_sync.py`: همگام‌ساز خودکار وضعیت کاربران و سهمیه‌ها
- `backend/vpn_router.py`: روتر REST API (`/api/vpn/*`)
- `node_worker/pg_vpn_hook.py`: هوک سرورهای نود (OpenVPN & L2TP)
- `node_worker/vici_poller.py`: پایشگر بلادرنگ نشست‌های IKEv2 strongSwan
- `node_worker/local_cache.py` و `circuit_breaker.py`: مکانیزم پایداری و تاب‌آوری نود در قطعی شبکه
- `plugin/vpn-panel.js`: رابط کاربری و دکمه‌های شناور پنل
- `install.sh`: اسکریپت نصب و یکپارچه‌سازی خودکار

## تست و تایید صحت:
```bash
python -m pytest
node tests/test_vpn_ui.js
```
> تمام ۴۲ تست بک‌اند و تست‌های فرانت‌اند با موفقیت ۱۰۰٪ پاس شده‌اند.

