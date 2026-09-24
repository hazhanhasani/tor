# Tor Location Manager for 3x-ui

وب‌پنل مستقل برای اجرای چند خروجی Tor روی یک سرور و اتصال خودکار آن‌ها به 3x-ui.

هر Location یک Tor instance مستقل با `ExitNodes {CC}` و `StrictNodes 1` دارد. SOCKS مربوط به Tor فقط روی `127.0.0.1` باز می‌شود. برای ارتباط 3x-ui یا PasarGuard با سرور Tor، پروژه برای هر Location یک Gateway مستقل **VLESS + REALITY** می‌سازد و Outbound و Routing Rule متناظر را به Core اضافه می‌کند.

## معماری

```text
Client
  |
  v
3x-ui / Xray inbound (مثلاً port 443)
  |
  | routing by inboundTag
  v
VLESS + REALITY outbound: torloc-de-xxxx
  |
  | encrypted REALITY transport
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
- HTTPS مستقیم برای خود پنل با استفاده از همان Certificate/Key محلی 3x-ui
- ورود با دامنه 3x-ui به‌جای IP، Secure Cookie، HSTS و محدودسازی Host
- Sync خودکار تمدید Certificate 3x-ui با systemd timer
- WARP Assist اختیاری برای Route کردن دامنه‌های انتخابی از Cloudflare WARP و نگه‌داشتن بقیه ترافیک روی Tor
- دریافت خودکار لیست Inboundهای 3x-ui
- ساخت/ویرایش/حذف Location
- انتخاب کشور خروجی از فهرست کامل 249 کشور/قلمرو ISO به‌جای واردکردن دستی کد دوحرفی
- Tor process مستقل برای هر کشور
- پورت مستقل برای هر Location
- VLESS + REALITY برای Gateway هر Location با UUID، X25519 و shortId اختصاصی
- Sync خودکار Xray Outbounds و Routing Rules در 3x-ui
- نگهداری تنظیمات موجود Xray؛ فقط tagهای با پیشوند `torloc-` مدیریت می‌شوند
- جلوگیری از اختصاص هم‌زمان یک inbound به دو Location
- Block کردن UDP روی مسیر Tor برای جلوگیری از مسیر خروجی غیرمنتظره
- تست IP و کشور واقعی خروجی Tor از داخل Web Panel
- systemd service و auto-start
- رمزگذاری API Token و seed اختصاصی VLESS/REALITY در دیتابیس با Fernet
- CSRF protection و session login
- تست config Xray قبل از جایگزینی Gateway config
- Update Center داخل پنل
- تشخیص GitHub Release رسمی
- بررسی SHA-256 قبل از نصب نسخه جدید
- Backup خودکار قبل از Update
- Health Check بعد از نصب
- Rollback خودکار در صورت خراب بودن نسخه جدید
- نگهداری ۵ Backup آخر
- Installer idempotent؛ نصب مجدد credentialها، DB و تنظیمات 3x-ui را پاک نمی‌کند

## نیازمندی

- Ubuntu / Debian
- معماری amd64 یا arm64
- دسترسی root
- systemd
- پورت Web Panel پیش‌فرض قبل از فعال‌سازی SSL: `8787/tcp`
- بعد از فعال‌سازی SSL 3x-ui، یک پورت HTTPS جدا و سازگار با Cloudflare مثل `2096/tcp` برای پنل Tor
- برای هر Location یک Gateway TCP port که باید بین سرور 3x-ui و سرور Tor قابل دسترس باشد
- 3x-ui جدید با API Token و endpointهای `/panel/api/xray/*`

مستندات رسمی 3x-ui: https://docs.sanaei.dev/

OpenAPI خود پنل: `<PANEL_URL>/panel/api/openapi.json`

## نصب حرفه‌ای از Release

بعد از انتشار اولین GitHub Release می‌توانید آخرین نسخه رسمی و checksumدار را با Bootstrap نصب کنید:

```bash
curl -fsSL https://raw.githubusercontent.com/hazhanhasani/tor/main/bootstrap.sh | sudo bash
```

Bootstrap آخرین Release را پیدا می‌کند، Asset رسمی و فایل SHA-256 را دانلود می‌کند، checksum را بررسی می‌کند و سپس Installer را اجرا می‌کند.

## نصب از سورس

```bash
git clone https://github.com/hazhanhasani/tor.git
cd tor
sudo bash install.sh
```

اگر نصب قبلی وجود داشته باشد، Installer آن را Upgrade درجا در نظر می‌گیرد و فایل‌های پایدار زیر را حفظ می‌کند:

```text
/etc/tor-location-manager/panel.env
/var/lib/tor-location-manager/panel.db
/var/lib/tor-location-manager/tor/
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

از نسخه `1.12.0`، مسیر بین Core و Tor Gateway از Shadowsocks 2022 به **VLESS + REALITY (TCP, XTLS Vision)** مهاجرت کرده است. نصب‌های قبلی نیازی به ساخت دوباره Location ندارند؛ seed رمزنگاری‌شده قبلی حفظ می‌شود و از آن UUID، کلید X25519 و shortId پایدار مشتق می‌شود. در حالت Legacy نیز Inbound مدیریت‌شده 3x-ui به VLESS + REALITY تبدیل می‌شود؛ حالت Cloudflare همچنان VLESS + WebSocket + TLS است.

## WARP داخل خود 3x-ui برای سایت‌های حساس به Tor

WARP دیگر با `warp-cli` و Local Proxy جداگانه روی Tor Gateway پیاده‌سازی نمی‌شود. Tor Location Manager از API رسمی خود 3x-ui استفاده می‌کند:

1. اگر WARP هنوز Register نشده باشد، از `/panel/api/xray/warp/reg` آن را ثبت می‌کند.
2. یک Outbound واقعی با `tag=warp` و `protocol=wireguard` داخل Xray Config می‌سازد.
3. در تنظیمات، Inboundهای تحت کنترل WARP از یک لیست کشویی چندانتخابی انتخاب می‌شوند.
4. می‌توان WARP را برای **همه ترافیک Inboundهای انتخابی** یا فقط **دامنه‌های انتخابی** فعال کرد.
5. در حالت CDN، `torloc-cdn` به‌صورت پیش‌فرض انتخاب می‌شود.
6. Inbound CDN از route-only HTTP/TLS sniffing استفاده می‌کند تا اگر Client مقصد را به IP resolve کرده باشد، SNI/Host برای Routing دامنه‌ای قابل استفاده باشد.
7. اگر 3x-ui برای Inbound مدیریت‌شده Tag خودکار مثل `in-2087-tcp` ساخته باشد، پروژه همان Inbound را از روی Remark اختصاصی شناسایی و همان Tag واقعی را در Routing/WARP استفاده می‌کند.
8. اگر پورت CDN انتخابی واقعاً توسط Inbound دیگری اشغال باشد، پروژه به‌جای شکست، یک پورت آزاد از پورت‌های HTTPS قابل Proxy کلادفلر انتخاب و ذخیره می‌کند.


لیست آماده شامل سایت‌هایی مثل Check-Host، Google، YouTube، ChatGPT/OpenAI، GitHub و Discord است و دامنه سفارشی نیز قابل اضافه‌کردن است. برای مسیر دامنه‌ای، `challenges.cloudflare.com` خودکار کنار لیست WARP قرار می‌گیرد تا صفحه Challenge و سایت انتخاب‌شده تا حد ممکن از یک egress استفاده کنند.

> CDN ورودی به‌تنهایی Reputation خروجی Tor را تغییر نمی‌دهد. WARP می‌تواند برای دامنه‌های انتخابی خروجی را از Tor به شبکه Cloudflare تغییر دهد، اما موفقیت CAPTCHA تضمینی نیست؛ Cookie، JavaScript، Browser Fingerprint و سیاست خود سایت هم مؤثرند.

اسکریپت قدیمی `tor-location-manager-install-warp` فقط برای سازگاری با نصب‌های قبلی باقی مانده و در مسیر جدید لازم نیست.

## استفاده از SSL خود 3x-ui برای پنل Tor

اگر 3x-ui و Tor Location Manager روی **همان سرور** نصب باشند، می‌توانید Web Panel این پروژه را بدون IP و با همان SSL خود 3x-ui باز کنید.

از منوی **اتصال و شبکه → HTTPS خود پنل Tor با SSL 3x-ui** گزینه استفاده از SSL 3x-ui را فعال کنید و یک پورت HTTPS آزاد انتخاب کنید. دامنه از URL ذخیره‌شده 3x-ui خوانده می‌شود. پروژه از API رسمی 3x-ui مسیرهای `webCertFile` و `webKeyFile` را می‌گیرد، سپس سرویس privileged فقط روی همان سرور فایل‌های Certificate/Key را اعتبارسنجی و به مسیر محدود زیر Sync می‌کند:

```text
/etc/tor-location-manager/tls/panel.crt
/etc/tor-location-manager/tls/panel.key
```

Private Key در دیتابیس یا UI ذخیره و نمایش داده نمی‌شود. Key کپی‌شده فقط برای گروه سرویس پنل خواندنی است.

نمونه:

```text
3x-ui:               https://panel.example.com:2053
Tor Location Manager: https://panel.example.com:2096
```

پورت‌های انتخابی HTTPS به پورت‌های قابل Proxy در Cloudflare محدود شده‌اند: `443, 2053, 2083, 2087, 2096, 8443`. سیستم قبل از فعال‌سازی تداخل پورت با 3x-ui، CDN Inbound، Gatewayهای Tor و Hybrid Tunnel را بررسی می‌کند.

پس از فعال‌شدن SSL:

- Session Cookie فقط روی HTTPS ارسال می‌شود.
- HSTS، `X-Frame-Options` و `X-Content-Type-Options` فعال می‌شوند.
- صفحات مدیریتی با Host/IP دیگر پاسخ مدیریتی نمی‌دهند.
- Timer هر ۶ ساعت Certificate منبع 3x-ui را بررسی می‌کند و در صورت تمدید، نسخه جدید را Sync و سرویس پنل را Restart می‌کند.
- Health Check و Updater هر دو حالت HTTP/HTTPS را تشخیص می‌دهند.

اگر دامنه/SSL اشتباه تنظیم شد و پنل باز نشد، از SSH این Rollback اضطراری را اجرا کنید:

```bash
sudo /opt/tor-location-manager/venv/bin/python -m torpanel.helper panel-tls-disable
```

پنل دوباره روی `http://SERVER_IP:8787` بالا می‌آید.

اگر Private Key گواهی 3x-ui روی Host، Docker/Podman mount یا namespace پردازش x-ui/Xray/Reverse Proxy پیدا شود، همان Certificate به‌صورت امن Sync می‌شود.

اگر Certificate واقعی قابل خواندن نباشد دو حالت وجود دارد:

- **Cloudflare Origin CA**: حالت پیشنهادی برای Production. یک API Token با مجوز `SSL and Certificates: Edit` را فقط هنگام صدور وارد می‌کنید. پروژه کلید ECC را روی خود سرور تولید می‌کند، CSR را به API رسمی Cloudflare Origin CA می‌فرستد، Certificate را نصب می‌کند و پس از صدور موفق Token را از دیتابیس پاک می‌کند. این Certificate با **Full (strict)** سازگار است.
- **Self-signed fallback**: فقط حالت اضطراری. پروژه یک Origin TLS محلی می‌سازد و Cloudflare باید روی **Full** باشد؛ **Full (strict)** در این حالت Error 526 می‌دهد.

در Syncهای بعدی، اگر Certificate واقعی x-ui قابل خواندن شود، آن دوباره اولویت می‌گیرد. Origin CA صادرشده نیز تا نزدیک انقضا دوباره درخواست نمی‌شود.

> Certificate مربوط به Cloudflare Edge و Private Key آن روی Origin قرار ندارد و پروژه تلاشی برای استخراج آن نمی‌کند. Origin CA روش درست Cloudflare برای نگه‌داشتن Full (strict) در این سناریو است.

## بروزرسانی از داخل پنل

در منوی **بروزرسانی** نسخه نصب‌شده و آخرین GitHub Release نمایش داده می‌شود. نصب از پنل فقط زمانی فعال می‌شود که Release دارای هر دو Asset زیر باشد:

```text
tor-location-manager-vX.Y.Z.tar.gz
tor-location-manager-vX.Y.Z.tar.gz.sha256
```

روند Update:

1. پنل آخرین Release رسمی را از GitHub بررسی می‌کند.
2. updater مستقل systemd شروع می‌شود؛ Web Panel دسترسی مستقیم root به فایل‌های سیستم ندارد.
3. Asset و SHA-256 از همان Release دانلود می‌شوند.
4. checksum بررسی می‌شود.
5. از کد فعلی، دیتابیس، `panel.env`، sudoers و unitهای systemd Backup گرفته می‌شود.
6. نسخه جدید نصب می‌شود و credentialها و دیتابیس حفظ می‌شوند.
7. `/healthz` بررسی می‌شود.
8. اگر Health Check شکست بخورد، برنامه، DB و سرویس‌ها به نسخه قبلی Rollback می‌شوند.
9. ۵ Backup آخر در `/var/backups/tor-location-manager/` نگهداری می‌شود.

لاگ Update:

```text
/var/lib/tor-location-manager/update.log
```

## انتشار نسخه جدید

شماره نسخه را در هر دو فایل زیر یکسان کنید:

```text
VERSION
pyproject.toml
```

مثلاً برای نسخه `1.2.0`، Tag زیر را منتشر کنید:

```bash
git tag v1.2.0
git push origin v1.2.0
```

Workflow `Release` به‌صورت خودکار نسخه را اعتبارسنجی می‌کند، تست‌ها را اجرا می‌کند، بسته Release و checksum را می‌سازد و GitHub Release را منتشر می‌کند. بعد از آن سرورهای نصب‌شده می‌توانند همان نسخه را از Update Center نصب کنند.

## نکات Tor

`ExitNodes {de}` به معنی تضمین وجود Exit در هر لحظه نیست. اگر برای یک کشور Exit مناسب در شبکه Tor موجود نباشد، آن Location ممکن است تا زمان پیدا شدن مسیر قابل استفاده نباشد. گزینه `StrictNodes 1` عمداً فعال است تا Tor در چنین شرایطی به کشور دیگری fallback نکند.

Tor برای TCP طراحی شده است. این پروژه UDP را در Gateway block می‌کند تا ترافیک UDP مستقیماً از مسیر دیگری خارج نشود.

در فرم Location فهرست کامل کدهای ISO 3166-1 نمایش داده می‌شود و کد مناسب `ExitNodes` خودکار ذخیره می‌شود. نمایش یک کشور در فهرست به معنی وجود Exit زنده در همان لحظه نیست؛ موجودی Exitهای Tor دائماً تغییر می‌کند.

## سرویس‌ها

```bash
systemctl status tor-location-panel
systemctl status tor-location-gateway
systemctl status tor-location@de-xxxx
systemctl status tor-location-manager-update
journalctl -u tor-location-panel -f
journalctl -u tor-location-gateway -f
journalctl -u tor-location-manager-update -f
```

Health endpoint قبل از SSL:

```text
http://127.0.0.1:8787/healthz
```

بعد از فعال‌سازی SSL، همان endpoint روی پورت HTTPS انتخاب‌شده سرو می‌شود و Health Check داخلی آن را با HTTPS بررسی می‌کند.

## تست توسعه

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .
python -m compileall -q torpanel
bash -n install.sh bootstrap.sh scripts/tor-location-manager-update
pytest -q
```

## حذف

```bash
sudo bash uninstall.sh
```

اسکریپت حذف، سرویس‌ها را پاک می‌کند ولی دیتابیس و تنظیمات را برای جلوگیری از حذف ناخواسته نگه می‌دارد.

## سازگاری با Sanaei 3x-ui v3.8.5

این نسخه با API رسمی 3x-ui نسخه `v3.8.5` (منتشرشده ۲۰۲۶-۰۹-۱۶) بررسی شده است.
در بخش «تست اتصال 3x-ui»، نسخه واقعی پنل و Xray از
`GET /panel/api/server/status` نمایش داده می‌شود. در نسخه‌های قدیمی که این
Endpoint در دسترس نباشد، تست اتصال با API فهرست Inboundها همچنان قابل انجام است.

نسخه جدید 3x-ui پورت‌های رزرو شده AmneziaWG و Forwarded Peer را نیز هنگام
ایجاد/ویرایش Inbound بررسی می‌کند. در حالت CDN، اگر سرور یک پورت را به‌علت
این تداخل‌های پنهان رد کند، پروژه پورت‌های HTTPS سازگار دیگر Cloudflare را
به‌ترتیب امتحان می‌کند و فقط پس از ایجاد/ویرایش موفق، پورت جدید را ثبت
می‌کند. Inboundهای قدیمی قبل از ایجاد موفق CDN حذف نمی‌شوند.

**نکات ارتقای خود 3x-ui:** در v3.8.5 صفحه Profile اشتراک به‌طور پیش‌فرض
غیرفعال است؛ در صورت نیاز از Settings → Subscription فعال کنید. همچنین
تنظیم Restart Xray After Client Disable برای غیرفعال‌سازی دستی هم اعمال
می‌شود. الزامات رسمی این انتشار شامل Xray-core v26.9.9 است.
ارتقای خود نرم‌افزار 3x-ui باید جداگانه، پس از Backup، از مسیر رسمی آن
انجام شود؛ نصب Tor Location Manager نسخه 3x-ui سرور شما را تغییر نمی‌دهد.

منابع:
- [3x-ui v3.8.5](https://github.com/MHSanaei/3x-ui/releases/tag/v3.8.5)
- [API رسمی Inbounds](https://docs.sanaei.dev/reference/api/inbounds)
- [API رسمی Server](https://docs.sanaei.dev/reference/api/server)


### REALITY share-link hotfix (v1.12.2)

نسخه‌های 1.12.0 و 1.12.1 در Inbound مدیریت‌شده 3x-ui کلید عمومی REALITY را در محل مورد انتظار پنل ذخیره نمی‌کردند. در نتیجه لینک ساخته‌شده می‌توانست `pbk`، `fp` و `flow` لازم را نداشته باشد و اتصال Locationهای Legacy شکست بخورد. از v1.12.2 ساختار Inbound با wire schema رسمی 3x-ui v3.8.5 هماهنگ است و Sync بعدی Inboundهای قبلی را نیز تعمیر می‌کند.
