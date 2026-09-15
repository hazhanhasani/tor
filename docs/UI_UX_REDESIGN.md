# Tor Location Manager — UI/UX System

این سند مرجع طراحی رابط کاربری پروژه است تا توسعه‌های بعدی ظاهر و تجربه یکپارچه داشته باشند.

## هدف محصول

پنل باید در چند ثانیه پاسخ این سؤال‌ها را بدهد:

1. آیا خود پنل سالم است؟
2. آیا 3x-ui متصل است؟
3. چند Tor Location فعال است؟
4. مسیر هر Location از کدام Inbound، Gateway و Tor Exit عبور می‌کند؟
5. اگر خطایی وجود دارد، از کجا باید آن را دید و برطرف کرد؟
6. آیا نسخه جدیدی وجود دارد و Update امن است؟

## اصول طراحی

- RTL واقعی و Mobile-first
- Light theme پیش‌فرض؛ Dark theme اختیاری و local-only
- بدون وابستگی UI به CDN یا فونت خارجی تا روی سرور ایران هم قابل استفاده باشد
- عدم نیاز به اسکرول افقی
- Actionهای خطرناک دارای confirmation
- اطلاعات شبکه‌ای با متن monospace و direction=ltr
- وضعیت‌ها با متن + رنگ؛ هیچ وضعیت مهمی فقط با رنگ نمایش داده نشود
- Empty state، Loading state، Error state و Disabled state برای صفحات اصلی
- حفظ سرعت: Vanilla JS و CSS، بدون framework فرانت‌اند سنگین

## Information Architecture

### Dashboard

- تعداد کل Locationها
- Locationهای فعال
- وضعیت 3x-ui
- وضعیت Xray Gateway
- Transport mode: Direct / obfs4
- آخرین Locationها
- Quick actions
- لینک مستقیم به Logs و Updates

### Locations

- Search
- Status filter
- Country filter
- کارت هر Location با مسیر تصویری:

```text
3x-ui Inbound -> SS2022 Gateway -> Tor Exit
```

- Portها و Tagهای مهم
- Edit / Test Exit / Delete
- Sync کامل

### Location Wizard

چهار مرحله:

1. نام و کشور
2. Inbound/Gateway ports
3. Inboundهای دستی اضافی و Enabled state
4. Review + Save

Validation باید قبل از رفتن به مرحله بعد انجام شود.

### Connection & Network

- 3x-ui URL
- API Token
- Gateway host
- Outbound health URL
- TLS verification
- Direct / obfs4 segmented control
- Bridge editor فقط زمانی نمایش داده شود که obfs4 فعال است
- خطاهای 401/403/404/timeout به زبان ساده

### Update Center

- Installed version
- Latest release
- Package verification state
- Restricted-network readiness
- Backup/Health/Rollback policy
- Update state
- Log tail

### Logs & Health

- Web panel
- Xray Gateway
- Updater
- یک log source برای هر Tor instance
- ActiveState/SubState
- Copy log
- Optional 10-second refresh

## Design Tokens

تمام رنگ‌ها، Radiusها، Shadowها و spacingهای اصلی باید در `:root` فایل `torpanel/static/app.css` تعریف شوند. از مقدارهای پراکنده و hard-coded تا حد ممکن پرهیز شود.

Semantic colors:

- Primary: action/navigation
- Success: healthy/running
- Warning: degraded/missing configuration
- Danger: failed/destructive
- Info: neutral operational info

## Responsive Rules

Desktop:

- Sidebar ثابت
- Content max-width کنترل‌شده
- Location grid دو ستونه در عرض کافی

Tablet:

- Sidebar به drawer تبدیل شود
- Layoutهای دو ستونه تک‌ستونه شوند

Mobile:

- بدون horizontal scroll
- Cards تک‌ستونه
- Buttons مهم touch-friendly
- Filterها wrap/grid شوند
- Route visualization خلاصه شود
- Wizard rail افقی شود

## Accessibility

- icon buttonها باید `aria-label` داشته باشند
- form fieldها label واقعی داشته باشند
- keyboard focus قابل مشاهده باشد
- statusها متن داشته باشند
- modal/confirm برای actionهای خطرناک
- contrast متن و background در هر دو theme حفظ شود

## Development Prompt

برای توسعه‌های بعدی می‌توان این Prompt را به ابزار coding داد:

> قبل از هر تغییر، ساختار فعلی Tor Location Manager را بررسی کن و Design System موجود در `torpanel/static/app.css`، componentهای `torpanel/templates/components/` و JavaScript موجود در `torpanel/static/app.js` را reuse کن. هیچ UI موازی یا framework جدیدی بدون ضرورت اضافه نکن. تمام صفحات جدید باید RTL، responsive، بدون horizontal scroll، قابل استفاده روی موبایل و مستقل از CDN باشند. Light theme پیش‌فرض باقی بماند. برای وضعیت‌های operational از componentهای status/banner/card موجود استفاده کن. اطلاعات IP/port/tag باید LTR و ترجیحاً monospace باشند. Actionهای destructive confirmation داشته باشند. برای فرم چندمرحله‌ای، validation قبل از رفتن به مرحله بعد الزامی است. UI نباید قابلیت‌های backend موجود را خراب کند. در پایان Jinja templateها، Python compile، shell syntax و pytest را اجرا کن و VERSION/pyproject را فقط زمانی bump کن که تغییر Release-worthy است.

## Definition of Done

یک تغییر UI زمانی کامل است که:

- Desktop و Mobile layout سالم باشد
- horizontal overflow نداشته باشد
- Jinja parse test پاس شود
- بدون JavaScript نیز فرم‌های حیاتی قابل submit باشند یا graceful fallback داشته باشند
- وضعیت Error/Empty/Success مشخص باشد
- API Token یا secret در UI log نشود
- هیچ CDN خارجی برای عملکرد اصلی لازم نباشد
- CI سبز باشد
