# Automatic Tor Location → Hybrid Tunnel Integration

این قابلیت دو حالت نصب رایج را بدون انتخاب دستی Location پوشش می‌دهد. هدف این است که وقتی Tor Location Manager روی یکی از Nodeهای Tunnel نصب است، همه Locationهای فعال فعلی و آینده به‌صورت خودکار با Hybrid Tunnel هماهنگ شوند.

## حالت A — Tor Manager روی سرور ایران

در این حالت خود Processهای Tor روی Iran Edge اجرا می‌شوند. Helper محلی `/etc/tor-location-node/agent.json` را می‌خواند و اگر Node محلی سمت `iran` یک Tunnel آماده باشد، `iran_overlay_ip` همان Link را برای تمام Tor instanceهای فعال به‌عنوان Source قرار می‌دهد.

```text
Client
  ↓
3x-ui / PasarGuard / Tor Gateway روی ایران
  ↓
Tor instance همان Location
  ↓  ExitNodes {country}
OutboundBindAddress = iran_overlay_ip
  ↓
Source-based policy routing + blackhole fallback
  ↓
WireGuard Direct یا Reverse FRP
  ↓
Foreign Node NAT
  ↓
Tor network
  ↓
Exit کشور انتخاب‌شده
```

برای هر Location فعال، `torrc` به شکل زیر تکمیل می‌شود:

```text
SocksPort 127.0.0.1:<socks_port>
OutboundBindAddress <iran_overlay_ip>
ExitNodes {de}
StrictNodes 1
```

در نتیجه ساخت Location جدید نیاز به تنظیم Tunnel جداگانه ندارد. Reconcile بعدی آن را خودکار وارد همان مسیر می‌کند.

## حالت B — Tor Manager روی سرور خارج

اگر Tor Location Manager روی Foreign Node نصب شده باشد، Node یک Inventory از همه Locationهای فعال می‌سازد و فقط Portهای عمومی متعلق به آن‌ها را به Controller اعلام می‌کند:

- `gateway_port` هر Location
- Inbound مدیریت‌شده 3x-ui (`xui_inbound_port`)
- Inboundهای دستی 3x-ui که به همان Location وصل شده‌اند
- Inboundهای PasarGuard که به همان Location وصل شده‌اند

`SOCKS` داخلی Tor عمداً در Inventory قرار نمی‌گیرد، چون روی `127.0.0.1` است و نباید عمومی شود.

Iran Edge هر 15 ثانیه Desired State را Poll می‌کند و با nftables برای همه Portهای Inventory یک Port Fabric می‌سازد:

```text
User → Iran_Public_IP:SAME_PORT
             ↓ DNAT
       foreign_overlay_ip:SAME_PORT
             ↓
       Hybrid Tunnel
             ↓
       Foreign service / Tor Location
             ↓
SNAT source = iran_overlay_ip
             ↓
Reply returns through the same Tunnel
```

برای هر Port، TCP و UDP همان شماره به‌صورت خودکار Mirror می‌شوند. اگر سرویس مقصد فقط TCP باشد، طبیعتاً UDP پاسخی نخواهد داشت؛ Port Fabric خودش Protocol سرویس را تغییر نمی‌دهد.

## چرا SNAT لازم است؟

DNAT به تنهایی کافی نیست. بدون SNAT، سرویس Foreign ممکن است پاسخ را از Default Route عمومی خود برگرداند و مسیر نامتقارن یا IP leak ایجاد شود. Port Fabric هنگام ورود به Interface Tunnel، Source را به `iran_overlay_ip` تبدیل می‌کند تا پاسخ به‌صورت قطعی از Overlay برگردد.

## Fail-closed و Leak Protection

در حالت A، Iran Node Agent برای `iran_overlay_ip` یک `ip rule` و جدول Route اختصاصی می‌سازد. جدول دارای Route Tunnel و `blackhole default` است؛ بنابراین ترافیک Bindشده به Overlay در صورت قطع Tunnel نباید روی Default Route عمومی ایران fallback کند.

در حالت B، Client فقط IP ایران را می‌بیند و Port Fabric مقصد را به `foreign_overlay_ip` می‌برد. IP عمومی Foreign Node در کانفیگ End-user قرار نمی‌گیرد.

این طراحی IP endpoint واقعی را از ISP، دیتاسنتر یا Peer شبکه «نامرئی» نمی‌کند؛ هدف آن حذف IP خارج از کانفیگ کاربران، جلوگیری از listenerهای غیرضروری و جلوگیری از fallback ناخواسته است.

## تشخیص و Reconcile خودکار

- Foreign Port Fabric تقریباً هر 60 ثانیه Inventory Tor را دوباره می‌خواند.
- Iran Port Fabric تقریباً هر 15 ثانیه Desired State را اعمال می‌کند.
- Location جدید یا تغییر Port در Sync بعدی بدون ساخت Link جدید وارد Fabric می‌شود.
- حذف Location باعث حذف Port آن در Reconcile بعدی می‌شود.
- حذف Tunnel باعث Cleanup Interface، FRP، Policy Route و Port Fabric مربوط به Link می‌شود.

## چند Tunnel و تداخل Port

یک Public Port روی یک Iran Edge نمی‌تواند همزمان به دو Foreign Node متفاوت تعلق داشته باشد. اگر دو Foreign Link همان Port را Advertise کنند، سیستم آن را Conflict اعلام می‌کند و به‌صورت مخفی مقصد را عوض نمی‌کند.

هنگام ساخت Tunnel جدید، allocator پورت‌های عمومی Locationهای موجود را رزرو می‌داند تا WireGuard/FRP با Gateway یا managed inboundهای Tor روی همان Host برخورد نکنند.

## ارتقای Nodeهای قدیمی

Port Fabric از Agent نسل `1.3.0` به بعد جزو Bootstrap است. Nodeهای قدیمی در صفحه Tunnel با پیام Upgrade مشخص می‌شوند. اجرای دستور Upgrade همان Enrollment قبلی را حفظ می‌کند و علاوه بر Agent اصلی، سرویس زیر را نصب می‌کند:

```bash
systemctl status tor-location-port-fabric --no-pager -l
journalctl -u tor-location-port-fabric -f
```

## Routing دستی 3x-ui / PasarGuard

Routing دستی Tunnel همچنان برای Inboundهایی باقی می‌ماند که عضو Locationهای Tor نیستند. برای Locationهای Tor نیازی نیست Portها یکی‌یکی انتخاب شوند؛ Integration خودکار بر اساس محل نصب Tor Manager یکی از دو روش بالا را اعمال می‌کند.
