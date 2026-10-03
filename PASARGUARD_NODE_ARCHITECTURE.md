# دانشنامه فنی معماری نودهای پاسارگارد و پیاده‌سازی VPN چندسروری (PasarGuard Node & Multi-Node VPN Knowledge Base)

> **تاریخ ثبت:** 2026-10-03  
> **هدف سند:** ذخیره‌سازی دائمی تمام اصول فنی، ساختار نودها، پروتکل‌های ارتباطی و معماری توزیع‌شده برای ماژول‌های VPN (شامل OpenVPN و IKEv2) در کنار پنل پاسارگارد.

---

## ۱. معماری بومی نودهای پاسارگارد (PasarGuard Node Mechanics)

پاسارگارد از یک مدل **Master-Worker (کنترلر و کارگر)** پیروی می‌کند:

### الف) سرور پنل اصلی (Master Panel):
* **فناوری:** پایتون (FastAPI) + ری‌اکت (Vite) + دیتابیس (SQLite / PostgreSQL / TimescaleDB).
* **وظایف:** 
  - ثبت و مدیریت کاربران، تعیین محدودیت‌های حجم و زمان انقضا.
  - مدیریت هاست‌ها، اینباندها و توکن‌های سابسکریپشن.
  - تولید گواهینامه‌های SSL داخلی جهت ارتباط امن با نودها.
  - **نکته مهم:** هیچ ترافیک پروکسی سنگینی از این سرور عبور نمی‌کند؛ پنل صرفاً فرماندهی و حسابداری را بر عهده دارد.

### ب) سرورهای نود (Worker Nodes):
* **فناوری:** پردازش بهینه‌سازی‌شده به زبان Go درون کانتینر داکر (`pg-node`).
* **وظایف:**
  - اجرای هسته پروکسی (Xray-core).
  - پذیرش اتصالات کلاینت‌ها روی پورت‌های تعریف‌شده (مانند ۴۴۳).
  - مانیتورینگ لحظه‌ای بایت‌های ارسالی/دریافتی هر کاربر و گزارش آن به پنل مرکزی.
* **نحوه اتصال و پروتکل ارتباطی:**
  - نودها از طریق **gRPC** روی پورت امن (پیش‌فرض `62050`) با پنل مرکزی ارتباط برقرار می‌کنند.
  - احراز هویت با پروتکل **mTLS (Mutual TLS)** و گواهینامه CA صادرشده توسط پنل انجام می‌شود (`node_bridge_py` در پایتون).
  - دستورات CLI مدیریت نود: `pg-node status`، `pg-node restart`، `pg-node logs`.

---

## ۲. سناریوی پیاده‌سازی پروتکل‌های غیربومی (OpenVPN / IKEv2) در محیط چندنودی

هسته Xray پاسارگارد تنها پروتکل‌های پروکسی (VLESS, VMess, Trojan, Shadowsocks) را می‌شناسد. برای پشتیبانی از OpenVPN و IKEv2 در ساختار چندسروری، از **معماری سایدکار توزیع‌شده (Distributed Sidecar Pattern)** استفاده می‌شود:

### دیاگرام جریان داده و احراز هویت:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                      سرور پنل اصلی (Master Panel)                      │
│   • دیتابیس کاربران (User: ali, Pass: 123, Quota: 50GB)               │
│   • اندپوینت احراز هویت مرکزی: POST /api/vpn/verify                    │
│   • اندپوینت دریافت گزارش مصرف: POST /api/vpn/usage                    │
│   • تولید لینک و فایل‌های کانفیگ: .ovpn و .mobileconfig               │
└──────────────────▲──────────────────────────────────▲──────────────────┘
                   │                                  │
          استعلام لاگین و حجم                 استعلام لاگین و حجم
          (HTTPS REST / Token)               (HTTPS REST / Token)
                   │                                  │
┌──────────────────┴────────────────┐ ┌───────────────┴──────────────────┐
│        سرور نود ۱ (آلمان)         │ │         سرور نود ۲ (هلند)        │
│ • داکر پاسارگارد (Xray - Port 443)│ │ • داکر پاسارگارد (Xray - Port 443)│
│ • سرویس OpenVPN (Port 1194)       │ │ • سرویس OpenVPN (Port 1194)       │
│ • سرویس strongSwan (IKEv2)        │ │ • سرویس strongSwan (IKEv2)        │
│ • اسکریپت Auth Hook و گزارش مصرف  │ │ • اسکریپت Auth Hook و گزارش مصرف  │
└──────────────────▲────────────────┘ └───────────────▲──────────────────┘
                   │                                  │
            کاربر نود آلمان                     کاربر نود هلند
```

### اجزای اجرایی روی نودها:
1. **اسکریپت نصاب نود (`pg-vpn-node.sh`):** سرویس‌های `openvpn` و `strongswan` را در کنار داکر نود نصب و کانفیگ می‌کند.
2. **هوک احراز هویت بلادرنگ (Real-time Auth):**
   - در OpenVPN: استفاده از آپشن `--auth-user-pass-verify hook.py via-file`.
   - در strongSwan: استفاده از پلاگین `ext-auth`.
   - اسکریپت با ارسال وب‌هوک به پنل اصلی، وضعیت کاربر را در کمتر از ۱۰۰ میلی‌ثانیه می‌سنجد.
3. **اکانتینگ و بستن سشن (Accounting & Kill-Switch):**
   - هر ۱ دقیقه حجم مصرفی خوانده شده و به پنل فرستاده می‌شود.
   - به محض رسیدن سهمیه کاربر به صفر، با دستور `kill` روی Management Interface سرویس OpenVPN، اتصال قطع می‌شود.

---

## ۳. فهرست منابع و آموزش‌های مرجع بررسی‌شده

### ویدیوهای مرجع یوتیوب:
1. **[آموزش تانل زدن و افزودن نود در پنل پاسارگارد](https://youtu.be/R_37V6lOaGo):** اتصال چندین سرور به پنل واحد و تانل ایران-خارج.
2. **[نود پاسارگارد چیه و چطور کار می‌کنه؟](https://www.youtube.com/watch?v=AUZIYQHpzAhHDpw6EsMk2QsD0pPeEAZxaLslbsyma5PZkVcNGu-A1zTup7Q5QMLiF63aE4ln3UP17IZV3LGAgzz6Dt_uVyyI1H-SAfIjkcTULxml4tdkEsYIFhKW1XElYirDwuzq):** مفاهیم تفکیک ترافیک نود و نصب داکر روی Ubuntu 22.
3. **[نصب کامل پنل پاسارگارد از صفر تا ۱۰۰](https://www.youtube.com/watch?v=AUZIYQE2FzN7WgXI69f8yJfXKDcdXskl3DNJLBHtHOWrB5lD5bI0-INphiI7XH2iLWqZobFZX0Viv3AERma9xDe8GWZZyqrExQFtxUZMd1TVndakVGjlRLKblPw1f9_SNmqJH8Ee):** راه‌اندازی مستر، دریافت Certificate و تبادل کلیدها.
4. **[نصب کامل پنل با دیتابیس TimescaleDB و نود لوکال](https://www.youtube.com/watch?v=AUZIYQED35SaRuMvG5BV1E8PPmoUYgswfiIIuehwNVso2yfgzrjSCw8rLB0F5qd3Mst5kJeeda_FnCjkpo78-vg_9_hG7PT7zS0Og8SGlFGm0C39RLIwalsP-bMdUQ9zn3VESvV_):** معماری ذخیره‌سازی آمار و لاگ‌های ترافیک.
5. **[سریع‌ترین روش نصب پنل و اتصال نودها](https://www.youtube.com/watch?v=AUZIYQHDvuvkuQ1Fz1dF8ZB0nb6-nwzSMFbhEF9BBX_gF5391DEgZvHL-7KxebbLzp55CmsYc8DJOqM5OCohfquyw8ypC2rW_QlD6M88gMNZOj1tuLkql_T0Y7qqfW1Ouk9JK8tO):** ساختار بهینه‌سازی روتینگ.
6. **[نصب پاسارگارد بدون دامنه (اتصال نود با IP مستقیم)](https://www.youtube.com/watch?v=AUZIYQEEdKVKp3LfhZ3tDwBBy1frlU-yYkN1OUFBd3TOU6anCIYShFiNVVeiBwnCEctI9KYU26Sf7yMUZnhouCafOSvI1e7UUYx2PXI6dW4f-7jJRMvJ_UhuZh12spT7tSkmHuJG):** بای‌پس محدودیت‌های DNS.
7. **[معماری پاسارگارد و تفاوت نود با مرزبان](https://www.youtube.com/watch?v=AUZIYQHkH6PhZS0fH6wzGbNr5hGOkMHm5XTw9RLxEH9aSNqdz-BeyTP3wCqzlIKVE57ewLyVekfpyw-FqnJHUpTCU8aPAr4lcu6e0w48eaaBXrch31UkzUMUqIN_r30kBrH_gr-l):** بررسی Worker Process و دیمن‌های پس‌زمینه.

### منابع سورس و مستندات رسمی:
8. **[PasarGuard Node Official Repository](https://github.com/PasarGuard/node):** اسکریپت نصب و تنظیمات محیطی نود.
9. **[PasarGuard Node Bridge Python](https://github.com/PasarGuard/node_bridge_py):** درایور ارتباط ناهمگام gRPC نود با پنل.
10. **[PasarGuard Core Panel Repository](https://github.com/PasarGuard/panel):** ساختار پایگاه‌داده و مدیریت گواهینامه‌های نود.

---

## ۴. جمع‌بندی ماندگار
تمامی داده‌ها و پیش‌نیازهای فنی این معماری ذخیره شده‌اند و در هر زمان آماده پیاده‌سازی یا پاسخ به سوالات عمیق شما در زمینه نودها و پروتکل‌های وی‌پی‌ان است.
