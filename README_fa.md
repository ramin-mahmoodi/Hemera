# هِمِرا (Hemera)

<p align="center">
  <img src="icon.png" alt="Hemera Logo" width="120" height="120">
</p>

<h3 align="center">پیاده‌سازی کاملاً بومی (Native) با C++26 از هسته ضدسانسور و کلاینت ویندوز Aether</h3>

<p align="center">
  پورت بومی و مستقل هسته تونل‌های ضدسانسور <a href="https://github.com/CluvexStudio/Aether"><b>Aether</b></a> برای سیستم‌عامل ویندوز.<br>
  توسعه‌یافته به صورت یکپارچه از پایه با <b>ISO C++26</b> به همراه استک شبکه داخلی، <b>رندرینگ سخت‌افزاری Direct2D</b> و بدون وابستگی به رانتایم‌های خارجی.
</p>

<p align="center">
  <a href="https://github.com/ramin-mahmoodi/Hemera/releases"><img src="https://img.shields.io/github/v/release/ramin-mahmoodi/Hemera?sort=semver&style=flat-square&color=0078D6" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/ramin-mahmoodi/Hemera?style=flat-square&color=2ea44f" alt="License: AGPL v3"></a>
  <img src="https://img.shields.io/badge/platform-Windows%2010%20%2F%2011-0078D6?style=flat-square&logo=windows&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/C%2B%2B-26-00599C?style=flat-square&logo=c%2B%2B&logoColor=white" alt="C++26">
  <img src="https://img.shields.io/badge/Direct2D-Hardware%20Accelerated-orange?style=flat-square" alt="Direct2D">
  <img src="https://img.shields.io/badge/arch-x64%20%7C%20ARM64-lightgrey?style=flat-square" alt="Arch">
  <a href="https://github.com/ramin-mahmoodi/Hemera/actions"><img src="https://img.shields.io/github/actions/workflow/status/ramin-mahmoodi/Hemera/build-and-release.yml?style=flat-square&logo=githubactions&logoColor=white" alt="Build Status"></a>
</p>

<p align="center">
  <a href="README.md"><b>English</b></a> · <b>فارسی</b>
</p>

---

<p align="center">
  <img src="docs/1.png" alt="صفحه اصلی هِمِرا در تم روشن" width="370">&nbsp;&nbsp;&nbsp;&nbsp;
  <img src="docs/2.png" alt="صفحه اصلی هِمِرا در تم تاریک" width="370">
</p>

## معرفی پروژه

**هِمِرا (Hemera)** بازپیاده‌سازی کاملاً بومی و کلاینت مستقل ویندوز برای معماری ضدسانسور [**Aether**](https://github.com/CluvexStudio/Aether) است؛ پروتکلی پیشرفته برای دورزدن فیلترینگ در شبکه‌های متخاصم که تحت فیلترینگ عمیق بسته‌ها (DPI)، انگشت‌نگاری پروتکل‌ها و اختلالات شدید روی ترافیک شبکه قرار دارند.

هِمِرا **صرفاً یک پوسته یا رابط کاربری گرافیکی (GUI Wrapper) نیست**؛ بلکه کل هسته تونل، پشته شبکه (NetStack) و پروتکل‌ها همراه با رابط کاربری به صورت یکپارچه با **C++26** پورت و بازنویسی شده‌اند:
- **حذف کامل رانتایم‌های Go یا Rust:** بدون نیاز به پروسه‌های مجزای پس‌زمینه (Sidecar/Daemon)، سربار سنگین ارتباط بین‌پروسه‌ای (IPC) یا وقفه‌های زباله‌روب (Garbage Collection).
- **حذف کامل فریم‌ورک‌های وب و الکترون:** بدون استفاده از ابزارهای سنگینی مانند Electron، WebView2 یا کرومیوم؛ طراحی‌شده مستقیماً با Win32 API و رندر سخت‌افزاری **Direct2D و DirectWrite**.
- **مصرف منابع در سطح مینیمال:** مصرف **کمتر از ۱۵ مگابایت رم**، **۰٫۰٪ مصرف پردازنده در حالت بیکار**، باز شدن آنی در کمتر از ۳۰۰ میلی‌ثانیه و انتشار در قالب یک تک‌فایل اجرایی سبک.

---

## ⚡ مقایسه عملکرد و معماری

| شاخص | هِمِرا (Native C++26) | معماری رایج Go/Rust + Webview | کلاینت‌های مبتنی بر Electron |
| :--- | :---: | :---: | :---: |
| **معماری هسته** | **هسته C++26 بومی و کامپایل‌شده درون پروسه** | پروسه CLI خارجی + پل ارتباطی IPC | بک‌اند Node.js / سایدکار مجزا |
| **مصرف حافظه (RAM)** | **کمتر از ۱۵ مگابایت** | ۷۰ تا ۱۶۰ مگابایت | ۲۰۰ تا ۴۵۰ مگابایت |
| **مصرف پردازنده در حالت آماده (Idle CPU)** | **۰٫۰٪** | ۰٫۸ تا ۳٫۰٪ | ۲٫۰ تا ۶٫۰٪ |
| **موتور گرافیکی** | **Direct2D و DirectWrite (سخت‌افزاری GPU)** | WebView2 / WebKit DOM | موتور Blink و کرومیوم |
| **سرعت بالا آمدن (Startup Time)** | **کمتر از ۳۰۰ میلی‌ثانیه (آنی)** | ۱٫۵ تا ۳ ثانیه | ۲٫۵ تا ۶ ثانیه |
| **ساختار باینری** | **تک‌فایل مستقل `.exe` (حدود ۱۲ مگابایت)** | باندل چند فایلی با فایل‌های وب | بیش از ۱۰۰ مگابایت فایل فریم‌ورک |
| **وابستگی‌های اجرایی** | **هیچ (مستقیماً Win32 API ویندوز)** | رانتایم Microsoft WebView2 | رانتایم Node.js + مرورگر کرومیوم |

---

## قابلیت‌ها و ویژگی‌های کلیدی

### 🧠 پورت بومی هسته شبکه در C++ (Native NetStack)
- **موتور پروتکل درون‌پروسه‌ای:** پیاده‌سازی مستقیم پروتکل‌های تونل در استانداردهای مدرن C++26، بدون نیاز به پایپ‌ها و سوکت‌های میانی.
- **تخمین پویای RTT بر اساس RFC 6298 (Jacobson/Karn):** اندازه‌گیری مداوم زمان رفت‌وبرگشت بسته‌ها و واریانس آن با تنظیم مرزهای RTO (بین ۱۰۰ میلی‌ثانیه تا ۱۰ ثانیه) جهت حذف کامل سکته‌های شبکه در خطوط ناپایدار.
- **بازیابی سریع پکت‌های گمشده با NewReno (RFC 6582):** جبران بسته‌های مفقود بدون افت سرعت ارسال و بدون توقف خط لوله داده.
- **سیستم رویدادمحور با Condition Variable:** بدون اسپین‌لاک یا Sleepهای مصنوعی روی تریدها، با تضمین مصرف ۰٪ پردازنده در حالت سکون.
- **سازگاری با EcoQoS ویندوز ۱۱:** مدیریت هوشمند اولویت پروسه تا در صورت کوچک شدن به System Tray، افت سرعت یا تاخیر زمان‌سنج پیش نیاید.

### 🛡️ پشته پروتکل‌های مقاوم در برابر فیلترینگ
- **پروتکل MASQUE (نسخه‌های HTTP/3 و HTTP/2):** کپسوله‌سازی دیتاگرام‌های خام IP درون جریان‌های واقعی TLS و QUIC. مجهز به خردسازی بسته اول (ClientHello Fragmentation) برای عبور از فیلترهای هوشمند مبتنی بر SNI.
- **موتور WireGuard:** پیاده‌سازی سبک و پرسرعت تونل مدرن UDP.
- **حالت WARP-in-WARP (`gool`):** دو تونل تو در توی وایرگارد به صورت خودکار یا با اندپوینت‌های دلخواه جهت دستیابی به آی‌پی خروجی تمیز.
- **حالت MASQUE-in-MASQUE (`mim`):** دو لایه ماسک متوالی برای نهایت پایداری در برابر رفتارهای DPI و دستیابی به تنوع سرور خروجی.

### 🌐 هدایت سراسری ترافیک ویندوز و پروکسی سیستم
- **درایور کارت شبکه مجازی Wintun L3:** هدایت بدون نشت تمام ترافیک ویندوز از لایه ۳ شبکه با جلوگیری قطعی از نشت DNS و دورزدن UDP.
- **پروکسی هوشمند سیستم (WinINet SysProxy):** تنظیم خودکار پروکسی ویندوز با اعمال آنی از طریق `InternetSetOptionW` بدون نیاز به بستن مرورگرها.
- **بازیابی تضمینی تنظیمات اینترنت:** بازگردانی قطعی تنظیمات پیش‌فرض پروکسی شبکه پس از قطع اتصال، خروج کاربر یا ریستارت ناگهانی سیستم.

### 🔍 اسکن و اعتبارسنجی چندمرحله‌ای مسیرها
- **پروفایل‌های اسکن:** تنظیم عمق جستجو و بودجه کاندیداها در سه سطح Turbo، Balanced و Thorough.
- **اعتبارسنجی سطح داده (Verified / Ironclad):** سنجش سلامت واقعی سرورها با ارسال و دریافت یک درخواست واقعی رمزنگاری‌شده HTTP تا هیچ‌گاه ترافیک به سمت سرور مرده هدایت نشود.

### 🎛️ سازگاری کامل با ویندوز
- **سینی سیستم (System Tray):** اجرای پس‌زمینه با نشانگر زنده وضعیت اتصال و منوی کلیک‌راست سریع.
- **محیط امن Job Object ویندوز:** مهار کردن پروسه‌های کمکی جهت جلوگیری قطعی از باقی ماندن پردازش‌های یتیم در پس‌زمینه.
- **کنسول لاگ زنده:** ثبت گزارش‌های عیب‌یابی دقیق همراه با دکمه کپی سریع در کلیپ‌بورد.

---

## دریافت و دانلود

فایل‌های آماده از بخش [**Releases (انتشارها)**](https://github.com/ramin-mahmoodi/Hemera/releases) قابل دریافت است:

| معماری پردازنده | فایل دانلودی | کاربرد |
| :--- | :--- | :--- |
| **ویندوز x64** | [`Hemera-v1.0.7-windows-x64.zip`](https://github.com/ramin-mahmoodi/Hemera/releases/latest) | مناسب تمام پردازنده‌های معمول ۶۴ بیتی اینتل و AMD |
| **ویندوز ARM64** | [`Hemera-v1.0.7-windows-arm64.zip`](https://github.com/ramin-mahmoodi/Hemera/releases/latest) | مناسب سرفیس‌پرو و پردازنده‌های اسنپ‌دراگون و ARM |

> **بدون نیاز به نصب.** فایل فشرده را استخراج کرده و `Hemera.exe` را اجرا کنید.

---

## راهنمای کامپایل از سورس (Build)

### پیش‌نیازها
- **ویندوز ۱۰ یا ۱۱** (معماری x64 یا ARM64)
- **Visual Studio 2022** (نسخه ۱۷٫۱۰ به بالا) با ابزارهای *Desktop development with C++*
- **CMake نسخه ۳٫۲۵ به بالا**

### مراحل ساخت

۱. **دریافت سورس‌کد:**
   ```bash
   git clone https://github.com/ramin-mahmoodi/Hemera.git
   cd Hemera
   ```

۲. **پیکربندی CMake:**
   ```cmd
   cmake -B build -DCMAKE_BUILD_TYPE=Release
   ```

۳. **کامپایل پروژه در حالت Release:**
   ```cmd
   cmake --build build --config Release
   ```
   فایل اجرایی در مسیر `build/Release/Hemera.exe` ایجاد خواهد شد.

۴. **اجرای ۵۴ تست واحد:**
   ```cmd
   .\build\Release\test_runner.exe
   ```

---

## ساختار پوشه‌های پروژه

```
Hemera/
├── include/                 # هدرهای عمومی و ساختارهای داده
├── src/                     # کدهای رابط کاربری Direct2D و هماهنگ‌کننده موتور
│   ├── gui.cpp              # موتور رندرینگ سخت‌افزاری با Direct2D و DirectWrite
│   ├── engine.cpp           # مدیریت پروسه‌ها، لایف‌سایکل و وضعیت اتصال
│   ├── sysproxy.cpp         # تنظیم و بازیابی امن سیستم‌پروکسی ویندوز
│   └── main.cpp             # نقطه ورود WinMain، مدیریت DPI و EcoQoS
├── core/                    # هسته C++ شبکه و پیاده‌سازی پروتکل‌ها
│   ├── src/                 # کدهای NetStack، MASQUE، WireGuard، DNS، ECH
│   └── vendor/              # کتابخانه‌های داخلی (BoringSSL، nghttp2، ngtcp2، RE2)
├── tests/                   # ۵۴ سوئیت آزمون واحد جامع
├── docs/                    # تصاویر و اسکرین‌شات‌های مستندات
├── scripts/                 # اسکریپت‌های کمکی و بیلد ARM64
├── CMakeLists.txt           # پیکربندی مدرن ساخت پروژه با CMake
└── build.bat                # اسکریپت ساخت سریع
```

---

## قدردانی و منابع (Credits)

- [**CluvexStudio/Aether**](https://github.com/CluvexStudio/Aether) — طراحی پروتکل‌ها و معماری اولیه تونل‌های ضدسانسور.
- [**Wintun**](https://www.wintun.net/) — درایور فوق‌العاده پرسرعت کارت شبکه مجازی ویندوز.

---

## لایسنس (License)

این پروژه تحت پروانه [**GNU Affero General Public License v3.0 (AGPL-3.0)**](LICENSE) منتشر شده است.
