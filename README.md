# Tor Location Manager for 3x-ui

وب‌پنل مستقل برای اجرای چند خروجی Tor روی یک سرور و اتصال خودکار آن‌ها به 3x-ui.

هر Location یک Tor instance مستقل با `ExitNodes {CC}` و `StrictNodes 1` دارد. SOCKS مربوط به Tor فقط روی `127.0.0.1` باز می‌شود. برای ارتباط سرور 3x-ui با این سرور، پروژه برای هر Location یک Shadowsocks 2022 رمزنگاری‌شده روی پورت مستقل ایجاد می‌کند و سپس از API رسمی 3x-ui، Outbound و Routing Rule متناظر را به Xray اضافه می‌کند.

## معماری

```text
Client
  |
  v
3x-ui / Xray inbound (مثلاً port 443)
  |
  | routing by inboundTag
  v
SS2022 outbound: torloc-de-xxxx
  |
  | encrypted TCP
  v
Tor Location Server : 31001
  |
  v
Xray gateway -> 127.0.0.1:19050 (SOCKS)
  |
  v
Tor instance ExitNodes {de}
  |
  v
Germany Tor exit
```

بنابراین می‌توان روی **یک سرور Tor** چند کشور داشت:

| Gateway port | Tor country | 3x-ui inbound |
|---:|---|---|
| 31001 | DE | VLESS-DE |
| 31002 | NL | VLESS-NL |
| 31003 | FR | VLESS-FR |

پورت SOCKS داخلی هر Location عمومی نیست و فقط روی localhost گوش می‌دهد.

## قابلیت‌ها

- Web Panel فارسی و RTL
- اتصال به 3x-ui با API Token رسمی
- دریافت خودکار لیست Inboundهای 3x-ui
- ساخت/ویرایش/حذف Location
- Tor process مستقل برای هر کشور
- پورت مستقل برای هر Location
- Shadowsocks 2022 با کلید تصادفی 32-byte
- Sync خودکار Xray Outbounds و Routing Rules در 3x-ui
- نگهداری تنظیمات موجود Xray؛ فقط tagهای با پیشوند `torloc-` مدیریت می‌شوند
- جلوگیری از اختصاص هم‌زمان یک inbound به دو Location
- Block کردن UDP روی مسیر Tor برای جلوگیری از مسیر خروجی غیرمنتظره
- تست IP و کشور واقعی خروجی Tor از داخل Web Panel
- systemd service و auto-start
- رمزگذاری API Token و کلیدهای SS در دیتابیس با Fernet
- CSRF protection و session login
- تست config Xray قبل از جایگزینی Gateway config

## نیازمندی

- Ubuntu / Debian
- دسترسی root
- پورت Web Panel پیش‌فرض: `8787/tcp`
- برای هر Location یک Gateway TCP port که باید بین سرور 3x-ui و سرور Tor قابل دسترس باشد
- 3x-ui جدید با API Token و endpointهای `/panel/api/xray/*`

مستندات رسمی 3x-ui: https://docs.sanaei.dev/

OpenAPI خود پنل: `<PANEL_URL>/panel/api/openapi.json`

## نصب سریع

```bash
git clone https://github.com/hazhanhasani/tor.git
cd tor
sudo bash install.sh
```

بعد از نصب، URL و اطلاعات ورود در ترمینال چاپ می‌شود و یک نسخه root-only نیز در مسیر زیر ذخیره می‌شود:

```text
/root/tor-location-manager-credentials.txt
```

پنل پیش‌فرض:

```text
http://SERVER_IP:8787
```

### فایروال

برای Web Panel ترجیحاً پورت `8787` را فقط برای IP مدیریت خود باز کنید یا آن را پشت HTTPS reverse proxy قرار دهید.

برای هر Location فقط Gateway port همان Location باید از **IP سرور 3x-ui** قابل دسترسی باشد. نمونه UFW:

```bash
ufw allow from 3XUI_SERVER_IP to any port 31001 proto tcp
ufw allow from 3XUI_SERVER_IP to any port 31002 proto tcp
```

SOCKSهای `19050+` به localhost bind می‌شوند و نباید در فایروال باز شوند.

## اتصال Web Panel به 3x-ui

1. در 3x-ui یک API Token از Settings/Security بسازید.
2. در Tor Location Manager وارد **اتصال 3x-ui** شوید.
3. URL کامل پنل را ثبت کنید؛ اگر base path دارید، آن را نیز وارد کنید.
4. API Token را وارد کنید.
5. IP عمومی یا دامنه سرور Tor را در `Gateway host` قرار دهید.
6. **تست اتصال** را بزنید.
7. یک Location ایجاد کنید و Inboundهای موردنظر را انتخاب کنید.

بعد از Save، پروژه Tor instance و Xray Gateway را می‌سازد، config فعلی Xray را از 3x-ui می‌خواند، Outbound اختصاصی `torloc-<slug>` و Rule مبتنی بر `inboundTag` را اضافه می‌کند و آن را از endpoint رسمی `/panel/api/xray/update` اعمال می‌کند.

## نکات Tor

`ExitNodes {de}` به معنی تضمین وجود Exit در هر لحظه نیست. اگر برای یک کشور Exit مناسب در شبکه Tor موجود نباشد، آن Location ممکن است تا زمان پیدا شدن مسیر قابل استفاده نباشد. گزینه `StrictNodes 1` عمداً فعال است تا Tor در چنین شرایطی به کشور دیگری fallback نکند.

Tor برای TCP طراحی شده است. این پروژه UDP را در Gateway block می‌کند تا ترافیک UDP مستقیماً از مسیر دیگری خارج نشود.

## سرویس‌ها

```bash
systemctl status tor-location-panel
systemctl status tor-location-gateway
systemctl status tor-location@de-xxxx
journalctl -u tor-location-panel -f
journalctl -u tor-location-gateway -f
journalctl -u tor-location@de-xxxx -f
```

## تست توسعه

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

## حذف

```bash
sudo bash uninstall.sh
```

اسکریپت حذف، سرویس‌ها را پاک می‌کند ولی دیتابیس و تنظیمات را برای جلوگیری از حذف ناخواسته نگه می‌دارد.
