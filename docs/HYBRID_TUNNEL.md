# Hybrid Iran ↔ Foreign Tunnel

این قابلیت یک Control Plane داخل Tor Location Manager و یک Agent سبک روی Nodeهای ایران و خارج ایجاد می‌کند.

## هدف

- افزودن تعداد زیادی سرور ایران و خارج بدون ساخت دستی config برای هر Node
- نصب هر Node با یک دستور Enrollment
- Overlay خصوصی برای آدرس‌دهی بین دو سرور
- مسیر اصلی سریع با WireGuard UDP
- مسیر پشتیبان Reverse با FRP که اتصال Control آن از سرور خارج به ایران برقرار می‌شود
- Failover خودکار در حالت `auto`
- جلوگیری از قرار گرفتن IP عمومی سرور خارج در کانفیگ End-user
- محدود کردن پورت Tunnel با nftables در حالت Kill-switch

## معماری

```text
                         Control Plane
                    Tor Location Manager
                         /api/tunnels
                         /      \
                        /        \
                 outbound       outbound
                    poll           poll
                     |              |
                Iran Node <------> Foreign Node
                     |              |
                     | WireGuard    |
                     +==============+
                     |
                     | fallback when direct path fails
                     |
             127.0.0.1:FRP-UDP
                     ^
                     |
                  frps (Iran)
                     ^
                     | TLS + token + encrypted proxy stream
                     |
                  frpc (Foreign)
```

در مسیر Reverse، `frpc` روی سرور خارج به `frps` روی ایران وصل می‌شود و UDP مربوط به WireGuard را به یک Port که فقط روی `127.0.0.1` ایران Bind شده منتقل می‌کند. Agent ایران Endpoint همتای WireGuard را از IP عمومی خارج به همان Loopback Port تغییر می‌دهد.

## حالت‌ها

### Auto

1. Direct WireGuard را فعال می‌کند.
2. Overlay peer را Health Check می‌کند.
3. در خرابی Direct، Endpoint WireGuard را به Reverse FRP تغییر می‌دهد.
4. وقتی Reverse سالم است، به‌صورت دوره‌ای Direct را Probe می‌کند.
5. اگر Direct دوباره سالم شد، مسیر به WireGuard مستقیم برمی‌گردد.

### Direct

فقط WireGuard مستقیم استفاده می‌شود.

### Reverse

WireGuard packetها فقط از Reverse FRP عبور می‌کنند. این حالت برای شبکه‌ای مناسب است که اتصال مستقیم ایران به Endpoint خارج قابل اتکا نیست ولی سرور خارج می‌تواند به ایران اتصال خروجی برقرار کند.

## Enrollment

در پنل:

1. وارد «تانل ترکیبی» شوید.
2. یک Link بسازید.
3. دستور ایران را روی Node ایران اجرا کنید.
4. دستور خارج را روی Node خارج اجرا کنید.

هر دستور One-time token دارد. Node هنگام نصب:

- WireGuard key را **روی خود Node** تولید می‌کند؛ Private Key به Controller ارسال نمی‌شود.
- FRP رسمی را از GitHub Release دریافت و SHA-256 رسمی آن را بررسی می‌کند.
- Agent token مستقل دریافت می‌کند.
- systemd Agent را نصب می‌کند.
- Desired State را از Controller Poll می‌کند.

## IP Leak Protection

این سیستم «IP عمومی خارج را از ساختار End-user جدا می‌کند»؛ این با «نامرئی کردن IP در خود اینترنت» متفاوت است.

- سرویس‌های ایران باید به `foreign_overlay_ip` متصل شوند، نه IP عمومی خارج.
- اگر Overlay قطع شود، مسیر Overlay Unreachable می‌شود و نرم‌افزار به IP عمومی خارج fallback نمی‌کند.
- پورت WireGuard خارج در حالت Kill-switch فقط از Loopback و IP مشاهده‌شده Node ایران مجاز می‌شود.
- پورت FRP ایران فقط از IP مشاهده‌شده Node خارج مجاز می‌شود.
- Reverse UDP Port روی ایران با `proxyBindAddr = 127.0.0.1` عمومی نیست.
- Enrollment token یک‌بارمصرف و زمان‌دار است.
- Agent token فقط به شکل SHA-256 در Controller ذخیره می‌شود.
- WireGuard PSK و FRP token در دیتابیس Controller با Fernet رمزگذاری می‌شوند.

Peer مستقیم، دیتاسنتر و ISP مسیر طبیعتاً می‌توانند Endpoint شبکه‌ای را که واقعاً با آن ارتباط دارند مشاهده کنند. هدف این قابلیت جلوگیری از افشای IP در config کاربران، listenerهای غیرضروری و fallback اشتباه است؛ نه ادعای پنهان‌سازی فیزیکی مسیر اینترنت.

## پورت‌های خودکار

به‌صورت پیش‌فرض برای هر Link منابع جدا رزرو می‌شود:

- Overlay: از `10.203.0.0/16` به صورت `/30`
- WireGuard خارج: `52000-59999/udp`
- FRP Control ایران: `22000-29999/tcp`
- Reverse UDP روی ایران: `40000-47999/udp` ولی فقط روی Loopback توسط FRP Proxy Bind

محدودیت مصنوعی در UI برای تعداد Node وجود ندارد. ظرفیت نهایی تابع CPU/RAM، محدوده Port و Overlay CIDR است. محدوده پیش‌فرض برای هزاران Link طراحی شده و در معماری می‌توان آن را گسترش داد.

## سرویس Node

```bash
systemctl status tor-location-node-agent
journalctl -u tor-location-node-agent -f
```

برای هر Link، Agent Interface با نام `tlmXXXXXXX` و در صورت نیاز یک سرویس FRP مدیریت‌شده ایجاد می‌کند.

## سرور ایران و شبکه محدود

Bootstrap فقط به Controller، APT و در صورت نیاز GitHub Release برای FRP نیاز دارد. متغیرهای زیر برای شبکه محدود پشتیبانی می‌شوند:

```bash
export TLM_APT_PROXY=http://127.0.0.1:8080
export TLM_DOWNLOAD_PROXY=http://127.0.0.1:8080
export TLM_FRP_RELEASE_API=https://api.github.com/repos/fatedier/frp/releases/latest
```

برای Production بهتر است Controller با HTTPS معتبر در دسترس باشد. استفاده از HTTP فقط با `--allow-http` صریح انجام می‌شود.

## مسیر داده پیشنهادی با 3x-ui

```text
Client
  ↓
3x-ui روی ایران
  ↓
foreign_overlay_ip
  ↓
Hybrid Tunnel
  ↓
Foreign Node
  ↓
Egress / upstream service
```

در این مدل هیچ نیازی نیست IP عمومی Foreign Node در subscription یا client config قرار گیرد.
