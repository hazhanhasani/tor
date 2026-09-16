# Automatic Tor Location → Hybrid Tunnel Integration

وقتی Tor Location Manager و Iran Node Agent روی همان سرور ایران نصب باشند، تمام Locationهای فعال Tor به‌صورت خودکار از Hybrid Tunnel عبور می‌کنند.

## مسیر داده

```text
Client
  ↓
هر پورت مدیریت‌شده Location (3x-ui managed inbound / SS2022 gateway)
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

## نحوه تشخیص خودکار

Helper ریشه‌ای پروژه فایل `/etc/tor-location-node/agent.json` را می‌خواند. اگر `node_uuid` محلی دقیقاً با `iran_node_uuid` یک Tunnel فعال و دارای Foreign Node برابر باشد، `iran_overlay_ip` همان Link به عنوان Source تمام Tor instanceهای مدیریت‌شده انتخاب می‌شود.

اگر Controller روی سرور دیگری باشد یا Agent محلی نقش Foreign داشته باشد، این رفتار فعال نمی‌شود و Tor به Route معمول Host دست نمی‌زند.

برای هر Location فعال، torrc به شکل زیر تکمیل می‌شود:

```text
SocksPort 127.0.0.1:<socks_port>
OutboundBindAddress <iran_overlay_ip>
ExitNodes {de}
StrictNodes 1
```

بنابراین انتخاب کشور Tor حفظ می‌شود؛ Tunnel فقط مسیر شبکه بین Iran Edge و Foreign Egress را عوض می‌کند.

## همه Locationها و همه پورت‌های مدیریت‌شده

این اتصال در سطح خروجی خود Tor انجام می‌شود، نه فقط یک Inbound خاص. در نتیجه تمام Locationهای فعلی و Locationهایی که بعداً ساخته می‌شوند به‌صورت خودکار مشمول Tunnel می‌شوند. تمام ورودی‌های TCP مدیریت‌شده‌ای که نهایتاً به Tor instance همان Location می‌رسند از همین مسیر عبور می‌کنند و نیازی به انتخاب دستی `torloc-in-*` در بخش Routing Tunnel نیست.

Gateway لوکیشن‌های Tor عمداً TCP-only است و UDP را Block می‌کند. بنابراین «تمام پورت‌ها» در این بخش به معنی تمام پورت‌ها و جریان‌های TCP مدیریت‌شده توسط Locationهای Tor است؛ Tor برای arbitrary UDP proxy طراحی نشده است.

## Fail-closed

Iran Node Agent برای `iran_overlay_ip` یک `ip rule` و جدول Route اختصاصی می‌سازد. جدول دارای مسیر Tunnel با metric پایین و `blackhole default` به عنوان fallback است. چون Tor خروجی خود را به همان Overlay IP Bind می‌کند، در صورت قطع Tunnel آن ترافیک نباید به Default Route عمومی ایران سقوط کند.

## Reconcile خودکار

Iran Agent تقریباً هر 15 ثانیه heartbeat می‌فرستد. Controller پس از heartbeat ایران، Helper را idempotent اجرا می‌کند. Helper فقط زمانی Tor instance را Restart می‌کند که torrc آن تغییر کرده باشد یا سرویس خاموش باشد؛ در نتیجه Poll عادی باعث Restart مداوم Locationها نمی‌شود.

حذف Tunnel نیز Helper را اجرا می‌کند تا `OutboundBindAddress` مدیریت‌شده از Locationها حذف شود و Route عادی Host بازگردد.

## چند Tunnel

اگر چند Tunnel به همان Iran Node وصل باشند، سیستم ابتدا Link سالم (`direct` یا `reverse`) را به‌صورت deterministic انتخاب می‌کند. برای انتخاب صریح یک Link می‌توان مقدار تنظیم داخلی `tor_tunnel_link_uuid` را روی UUID موردنظر قرار داد. قابلیت خودکار با `tor_auto_tunnel_all_locations=1` فعال است.

## Routing دستی 3x-ui / PasarGuard

Routing دستی Tunnel همچنان برای Inboundهای غیر-Tor باقی می‌ماند. Inboundهای مدیریت‌شده Tor نباید با Freedom Outbound مستقیم به Tunnel فرستاده شوند، چون آن کار مرحله Tor/ExitNodes را دور می‌زند. برای Locationهای Tor، مسیر درست همان `OutboundBindAddress` روی process Tor است.
